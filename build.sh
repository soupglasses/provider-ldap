#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
package_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
output=${1:?Pass the output .xpkg path}
platform=${2:-$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')}
case "$platform" in
    linux/amd64|linux/arm64) ;;
    *) echo "Supported runtime platforms: linux/amd64, linux/arm64" >&2; exit 1 ;;
esac
image="provider-ldap:development-${platform#linux/}"
docker build --platform "$platform" --target runtime --tag "$image" "$package_dir"
crossplane xpkg build --package-root "$package_dir/package" \
    --embed-runtime-image "$image" --package-file "$output"
