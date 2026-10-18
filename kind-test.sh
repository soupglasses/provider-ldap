#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
# SPDX-License-Identifier: MIT
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cluster="provider-ldap-test-$$"
work_dir=$(mktemp -d)
export KUBECONFIG="$work_dir/kubeconfig"
package_file=${PROVIDER_PACKAGE:-/tmp/provider-ldap.xpkg}
registry="${cluster}-registry"
registry_image=registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e
tests_image=${TESTS_IMAGE:-provider-ldap-tests:development}
test_pattern=${INTEGRATION_TEST_PATTERN:-Test}
cleanup() {
    result=$?
    trap - EXIT
    if ((result != 0)); then
        if [[ -f "$work_dir/psa-rejection.log" ]]; then
            cat "$work_dir/psa-rejection.log" >&2
        fi
        kubectl get provider,providerrevision -o yaml >&2 || true
        kubectl get pods --all-namespaces >&2 || true
        kubectl logs --namespace ldap-test ldap-tests >&2 || true
        kubectl logs --namespace crossplane-system -l app.kubernetes.io/name=ldap-provider --tail=80 >&2 || true
    fi
    kind delete cluster --name "$cluster" || true
    docker rm -f "$registry" >/dev/null 2>&1 || true
    rm -rf -- "$work_dir"
    exit "$result"
}
trap cleanup EXIT
[[ -s "$package_file" ]]
kind create cluster --name "$cluster" --kubeconfig "$KUBECONFIG" \
    --image kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d
kind load docker-image --name "$cluster" "$tests_image"
docker run -d --name "$registry" --network kind "$registry_image" >/dev/null
registry_ip=$(docker inspect "$registry" --format '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
registry_address="$registry_ip:5000"
# Only the disposable node trusts the test registry's HTTP endpoint.
docker exec "$cluster-control-plane" mkdir -p "/etc/containerd/certs.d/$registry_address"
cat <<CONFIG | docker exec -i "$cluster-control-plane" tee "/etc/containerd/certs.d/$registry_address/hosts.toml" >/dev/null
server = "http://$registry_address"
[host."http://$registry_address"]
    capabilities = ["pull", "resolve"]
CONFIG
crossplane xpkg push --insecure-skip-tls-verify --package-files "$package_file" \
    "$registry_address/provider-ldap:v0.1.0"
# Restricted namespaces also exercise the runtime security configuration.
for namespace in crossplane-system ldap-test; do
    kubectl create namespace "$namespace"
    kubectl label namespace "$namespace" \
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
    echo 'ERROR: insecure Pod failed for a reason other than restricted Pod Security' >&2
    kubectl version --client --output=yaml >&2
    exit 1
fi
helm upgrade --install crossplane crossplane --repo https://charts.crossplane.io/stable \
    --version 2.4.2 --namespace crossplane-system \
    --set-json 'securityContextCrossplane={"runAsNonRoot":true,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}' \
    --set-json 'securityContextRBACManager={"runAsNonRoot":true,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}' \
    --set 'args[0]=--poll-interval=2s' --wait --timeout 4m
cp "$repo_dir/tests/provider.yaml" "$work_dir/provider.yaml"
REGISTRY_ADDRESS="$registry_address" yq -i '(select(.kind == "Provider") | .spec.package) = strenv(REGISTRY_ADDRESS) + "/provider-ldap:v0.1.0" | (select(.kind == "DeploymentRuntimeConfig" and .metadata.name == "ldap") | .spec.deploymentTemplate.spec.template.spec.containers[0].args) = ["--poll-interval=2s"]' "$work_dir/provider.yaml"
kubectl apply --filename "$work_dir/provider.yaml"
kubectl wait provider/ldap --for=condition=Healthy --timeout=180s
kubectl wait crd/entries.ldap.ops.finnes.dev --for=condition=Established --timeout=90s
cp "$repo_dir/tests/kubernetes.yaml" "$work_dir/tests.yaml"
TESTS_IMAGE="$tests_image" TEST_PATTERN="$test_pattern" yq -i '(select(.kind == "Pod") | .spec.containers[0].image) = strenv(TESTS_IMAGE) | (select(.kind == "Pod") | .spec.containers[0].args[2]) = "-test.run=" + strenv(TEST_PATTERN)' "$work_dir/tests.yaml"
kubectl apply --filename "$work_dir/tests.yaml"
kubectl wait pod/ldap-tests --namespace ldap-test \
    --for=jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' --timeout=9m
kubectl logs --namespace ldap-test ldap-tests
[[ $(kubectl get pod ldap-tests --namespace ldap-test --output jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}') == 0 ]]
