<!--
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: MIT
-->

# Development

Use Docker, the Crossplane CLI, kind and the tools in `.mise.toml`.

```sh
bash build.sh /tmp/provider-ldap.xpkg
docker build --target tests --tag provider-ldap-tests:development .
PROVIDER_PACKAGE=/tmp/provider-ldap.xpkg bash kind-test.sh
```

CI verifies generated schemas and real OpenLDAP reconciliation, drift, Secret
rotation, controller restart, observation, retention, adoption and deletion in
disposable kind. Renovate proposes dependency updates through the same checks.

Docker's `generated` target exports CRDs and the SDK schema. Copy those outputs
to `package/crds/` and `config/schema.json` when generation changes. The
`generated-source` target exports generated Go source with its path manifest.

Main builds publish commit-qualified packages. Push a new `v*` Git tag for a
release: CI runs the checks, publishes its native Provider package, and creates
a GitHub release containing the xpkg and SHA-256 checksum. Existing release tags
must not be moved.
