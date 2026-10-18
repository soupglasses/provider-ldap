#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
before=$(mktemp)
trap 'rm -f "$before"' EXIT
find apis internal -type f -name '*.go' | sort > "$before"
go run -buildvcs=false ./cmd/generate
controller-gen object:headerFile=hack/boilerplate.go.txt paths=./apis/...
angryjet generate-methodsets --header-file=hack/boilerplate.go.txt ./apis/...
controller-gen crd paths=./apis/namespaced/... output:crd:dir=generated/crds
# License metadata is generated alongside the CRDs; source manifests are never hand-edited.
for manifest in generated/crds/*.yaml; do
    yamlfmt "$manifest"
    cat > "$manifest.license" <<'LICENSE'
SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
SPDX-License-Identifier: Apache-2.0
LICENSE
done

# Export generated sources separately from maintained provider types and setup code.
mkdir -p generated/source/config
cp config/schema.json generated/source/config/schema.json
cp config/schema.json.license generated/source/config/schema.json.license
printf '%s\n' config/schema.json > generated/source/MANIFEST
while IFS= read -r source; do
    if ! grep -Fxq "$source" "$before" || grep -q '^// Code generated.*DO NOT EDIT' "$source"; then
        mkdir -p "generated/source/$(dirname "$source")"
        cp "$source" "generated/source/$source"
        printf '%s\n' "$source" >> generated/source/MANIFEST
    fi
done < <(find apis internal -type f -name '*.go' | sort)
