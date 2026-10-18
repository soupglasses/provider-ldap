<!--
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: Apache-2.0
-->

# Development

Use Docker and the pinned tools in `.mise.toml`.

```sh
mise exec -- go test ./cmd/... ./apis/...
mise exec -- bash build.sh /tmp/provider-ldap.xpkg
docker build --target tests --tag provider-ldap-tests:development .
mise exec -- env PROVIDER_PACKAGE=/tmp/provider-ldap.xpkg bash kind-test.sh
```

Unit tests exercise the native Crossplane connector and LDAP ownership logic.
[Chainsaw](https://kyverno.github.io/chainsaw/) drives real Kubernetes lifecycle
operations in disposable kind; ordinary Go tests verify the resulting LDAP state.
The fixture uses OpenLDAP, restricted Pod Security and synthetic credentials.

Run `generate.sh` after API changes with controller-gen and yamlfmt installed.
Commit generated deepcopy methods and CRDs. Docker's `generated` target exports
both, and CI verifies they reproduce the checked-in files. CI also exports Go
coverage and Chainsaw reports. Renovate updates dependencies through these checks.

Main builds publish commit-qualified packages. Push a new semantic `v*` tag for
a release: CI checks it, publishes the Provider package, and creates a GitHub
release with the xpkg and SHA-256 checksum. Do not move published release tags.
