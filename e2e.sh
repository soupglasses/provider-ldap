#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
provider=$(yq .metadata.name package/crossplane.yaml)
package_file=${PROVIDER_PACKAGE:-/tmp/$provider.xpkg}
manifests=examples/group.yaml,examples/service-account.yaml
[[ -s "$package_file" ]] || { echo "Build $package_file first: mise run build" >&2; exit 1; }
export KIND_CLUSTER_NAME="$provider-e2e-$$"
registry="$KIND_CLUSTER_NAME-registry"
registry_image=registry:3.1.2@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c
work_dir=$(mktemp -d)
export KUBECONFIG="$work_dir/kubeconfig"
KUBECTL=$(command -v kubectl)
CHAINSAW=$(command -v chainsaw)
CROSSPLANE_CLI=$(command -v crossplane)
export KUBECTL CHAINSAW CROSSPLANE_CLI
cleanup() {
    result=$?
    trap - EXIT
    if ((result != 0)); then
        kubectl get providers,providerrevisions,deploymentruntimeconfigs -o yaml >&2 || true
        kubectl get managed --all-namespaces -o yaml >&2 || true
        kubectl get pods --all-namespaces >&2 || true
        kubectl get events --all-namespaces --sort-by=.lastTimestamp >&2 || true
        kubectl get pods --all-namespaces --no-headers \
            --output custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name |
            grep -Ev '^(kube-system|local-path-storage) ' |
            while read -r namespace pod; do
                echo "--- logs $namespace/$pod" >&2
                kubectl logs --namespace "$namespace" "$pod" --all-containers --tail=100 >&2 || true
            done
    fi
    kind delete cluster --name "$KIND_CLUSTER_NAME" || true
    docker ps --all --quiet --filter "name=^$KIND_CLUSTER_NAME-" | xargs --no-run-if-empty docker rm --force >/dev/null || true
    rm -f /tmp/provider-ldap-generated-password.sha256
    rm -rf -- "$work_dir"
    exit "$result"
}
trap cleanup EXIT

kind create cluster --name "$KIND_CLUSTER_NAME" --kubeconfig "$KUBECONFIG" \
    --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
docker run --detach --name "$registry" --network kind "$registry_image" >/dev/null
registry_ip=$(docker inspect "$registry" --format '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
registry_address="$registry_ip:5000"
# Only the disposable node trusts the test registry's HTTP endpoint.
docker exec "$KIND_CLUSTER_NAME-control-plane" mkdir -p "/etc/containerd/certs.d/$registry_address"
cat <<CONFIG | docker exec -i "$KIND_CLUSTER_NAME-control-plane" tee "/etc/containerd/certs.d/$registry_address/hosts.toml" >/dev/null
server = "http://$registry_address"
[host."http://$registry_address"]
    capabilities = ["pull", "resolve"]
CONFIG
export PROVIDER_PACKAGE_REF="$registry_address/$provider:development"
crossplane xpkg push --insecure-skip-tls-verify --package-files "$package_file" "$PROVIDER_PACKAGE_REF"

kubectl create namespace crossplane-system
kubectl label namespace crossplane-system pod-security.kubernetes.io/enforce=restricted
helm upgrade --install crossplane crossplane --repo https://charts.crossplane.io/stable \
    --version 2.4.3 --namespace crossplane-system \
    --set-json 'securityContextCrossplane={"runAsNonRoot":true,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}' \
    --set-json 'securityContextRBACManager={"runAsNonRoot":true,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}' \
    --set 'args[0]=--poll-interval=2s' --wait --timeout 4m

CROSSPLANE_NAMESPACE=crossplane-system uptest e2e "$manifests" \
    --setup-script "$PWD/tests/setup.sh" --test-directory "$work_dir/uptest"
[[ -z ${TEST_ARTIFACTS_DIR:-} ]] || mkdir -p "$TEST_ARTIFACTS_DIR"
chainsaw test tests/e2e ${TEST_ARTIFACTS_DIR:+--report-format JUNIT-TEST --report-path "$TEST_ARTIFACTS_DIR"}
