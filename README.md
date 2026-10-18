<!--
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: Apache-2.0
-->

# provider-ldap

A native Crossplane provider that reconciles LDAP entries through
[go-ldap](https://github.com/go-ldap/ldap). Declare exact attribute ownership or
manage selected values with Subset ownership while preserving other writers' values.

## Install

Requires Crossplane 2.4 or later. Pin the package digest in production.

```yaml
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: ldap
spec:
  package: ghcr.io/soupglasses/provider-ldap:v0.4.0
```

The [runtime example](tests/provider.yaml) includes resource limits, probes and
restricted Pod Security settings.

## Use

Edit the directory credentials, host and DN in
[examples/selfcontained.yaml](examples/selfcontained.yaml), then apply it:

```sh
kubectl apply -f examples/selfcontained.yaml
kubectl wait --namespace applications entry/service --for=condition=Ready --timeout=120s
```

An Entry declares its desired `forProvider.dn`, inline `attributes`, and
`attributeSecretRefs` for sensitive values. Use `attributeOwnership: {member: Subset}`
to manage selected values while preserving others. DN changes rename or move the
same LDAP identity.
Secret values stay out of Entry status. TLS defaults to enabled.

Omitting `managementPolicies` includes deletion. The example explicitly uses
`[Observe, Create, Update]` to retain LDAP data when the Entry is deleted.
See [usage](docs/usage.md) for ownership and shared credentials.

Optional [GroupOfNames and ServiceAccount compositions](examples/compositions/)
provide reusable APIs, including generated application credentials, without
adding application policy to the provider. See [contributing](CONTRIBUTING.md)
for development and release checks.
