<!--
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: Apache-2.0
-->

# Development

Use Docker and the pinned tools in `.mise.toml`.

```sh
docker build --target unit-tests .
mise run e2e
```

`mise run e2e` builds the package and tests it in a disposable kind cluster.
Unit tests exercise the native Crossplane connector and LDAP ownership logic.
[uptest](https://github.com/crossplane/uptest) applies the examples listed in `e2e.sh`
against the disposable directory that `tests/setup.sh` starts, and re-imports them after
a provider restart.
[Chainsaw](https://kyverno.github.io/chainsaw/) drives real Kubernetes lifecycle
operations in disposable kind; ordinary Go tests verify the resulting LDAP state.
The fixture uses OpenLDAP, restricted Pod Security and synthetic credentials.
Unit tests also verify TLS trust and hostname checks with an ephemeral local CA.

Run `generate.sh` after API changes with controller-gen and yamlfmt installed.
Commit generated deepcopy methods and CRDs. Docker's `generated` target exports
both, and CI verifies they reproduce the checked-in files. CI also exports Go
coverage and Chainsaw reports. Renovate updates dependencies through these checks.

`build.sh` accepts `linux/amd64` or `linux/arm64` as its second argument and
defaults to the Docker host platform. CI builds both runtime architectures and
publishes them as one Provider package through `crossplane xpkg push`.

Main builds publish commit-qualified packages. Push a new semantic `v*` tag for
a release: CI checks it, publishes the Provider package, and creates a GitHub
release with both architecture-specific xpkgs and SHA-256 checksums. Do not move published release tags.
