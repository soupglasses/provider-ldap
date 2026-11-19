#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
tests_image=provider-ldap-tests:development
docker buildx build --load --target tests --tag "$tests_image" "$repo_dir"
kind load docker-image --name "${KIND_CLUSTER_NAME:?}" "$tests_image"

# Restricted namespaces also exercise the runtime security configuration.
for namespace in crossplane-system ldap-test applications; do
    kubectl create namespace "$namespace" --dry-run=client --output yaml | kubectl apply --filename -
    kubectl label namespace "$namespace" --overwrite \
        pod-security.kubernetes.io/enforce=restricted \
        pod-security.kubernetes.io/enforce-version=v1.34 \
        pod-security.kubernetes.io/audit=restricted \
        pod-security.kubernetes.io/audit-version=v1.34 \
        pod-security.kubernetes.io/warn=restricted \
        pod-security.kubernetes.io/warn-version=v1.34
done
kubectl wait serviceaccount/default --namespace ldap-test --for=create --timeout=60s
if kubectl run psa-rejection --namespace ldap-test --restart=Never --dry-run=server \
    --image="$tests_image" --command -- /bin/true >"$work_dir/psa-rejection.log" 2>&1; then
    echo 'ERROR: restricted Pod Security did not reject an insecure test Pod' >&2
    exit 1
fi
if ! grep -q 'violates PodSecurity "restricted:v1.34"' "$work_dir/psa-rejection.log"; then
    cat "$work_dir/psa-rejection.log" >&2
    echo 'ERROR: insecure Pod failed for a reason other than restricted Pod Security' >&2
    exit 1
fi

# Only the disposable directory gets the private key; the provider trusts its public certificate.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=ldap.ldap-test.svc \
    -addext 'subjectAltName=DNS:ldap.ldap-test.svc' \
    -keyout "$work_dir/tls.key" -out "$work_dir/tls.crt"
kubectl create secret tls ldap-server-tls -n ldap-test --cert="$work_dir/tls.crt" --key="$work_dir/tls.key"
kubectl create configmap ldap-test-trust -n crossplane-system --from-file=fixture.pem="$work_dir/tls.crt"
kubectl apply --namespace ldap-test --filename "$repo_dir/tests/fixture.yaml"
kubectl rollout status --namespace ldap-test deployment/ldap --timeout=120s
for ldif in base:dc=example,dc=test:cn=admin,dc=example,dc=test:disposable-fixture-password \
    examples:dc=example,dc=org:cn=service-admin,dc=example,dc=org:disposable-examples-password; do
    IFS=: read -r name _ bind_dn password <<<"$ldif"
    kubectl exec --namespace ldap-test deployment/ldap -- \
        ldapadd -x -H ldap://127.0.0.1:1389 -D "$bind_dn" -w "$password" -f "/fixtures/$name.ldif"
done

kubectl apply -f "$repo_dir/examples/shared-config-rbac.yaml"
cp "$repo_dir/tests/provider.yaml" "$work_dir/provider.yaml"
yq -i '(select(.kind == "Provider") | .spec.package) = strenv(PROVIDER_PACKAGE_REF) | (select(.kind == "DeploymentRuntimeConfig" and .metadata.name == "provider-ldap") | .spec.deploymentTemplate.spec.template.spec.containers[0].args) = ["--poll-interval=2s"]' "$work_dir/provider.yaml"
yq -i '(select(.kind == "DeploymentRuntimeConfig") | .spec.deploymentTemplate.spec.template.spec) |=
    (.volumes += [{"name":"ldap-test-trust","configMap":{"name":"ldap-test-trust"}}] |
     (.containers[] | select(.name == "package-runtime") | .volumeMounts) +=
        [{"name":"ldap-test-trust","mountPath":"/etc/ssl/certs/fixture.pem","subPath":"fixture.pem","readOnly":true}])' "$work_dir/provider.yaml"
kubectl apply --filename "$work_dir/provider.yaml"
kubectl wait provider/ldap --for=condition=Healthy --timeout=180s
kubectl wait crd/entries.ldap.finnes.dev --for=condition=Established --timeout=90s

# The examples' ProviderConfig, with credentials for the disposable directory.
kubectl create secret generic directory-credentials --namespace applications \
    --from-literal=credentials.yaml="$(printf '%s\n' 'host: ldap.ldap-test.svc' 'port: 1389' \
        'bindDN: cn=service-admin,dc=example,dc=org' 'password: disposable-examples-password' 'tls: false')"
yq 'select(.kind != "Secret" and .kind != "Namespace")' "$repo_dir/examples/setup.yaml" | kubectl apply --filename -
