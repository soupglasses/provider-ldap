#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")"
controller-gen object:headerFile=hack/boilerplate.go.txt paths=./apis/...
controller-gen crd paths=./apis/namespaced/... output:crd:dir=generated/crds
for manifest in generated/crds/*.yaml; do
    yamlfmt "$manifest"
    cat > "$manifest.license" <<'LICENSE'
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: Apache-2.0
LICENSE
done
