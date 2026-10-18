<!--
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: MIT
-->

# provider-ldap

A native Crossplane Provider for LDAP entries. Upjet embeds the
[l-with Terraform LDAP provider](https://registry.terraform.io/providers/l-with/ldap/latest)
SDK in the controller process. It uses neither a Terraform executable nor a
Terraform state file. Crossplane manages the controller, permissions and CRDs.

## Install

Crossplane 2.4 or later is required. Install a released package and pin its digest
in production:

```yaml
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: ldap
spec:
  package: ghcr.io/soupglasses/provider-ldap:v0.1.0
```

Use `DeploymentRuntimeConfig` for runtime settings. The
[test installation](tests/provider.yaml) includes probes, resource limits and
restricted Pod Security settings.

## Configure

Edit the host, bind DN, passwords and base DN in
[examples/selfcontained.yaml](examples/selfcontained.yaml) to match your LDAP
server, then apply it:

```sh
kubectl apply -f examples/selfcontained.yaml
kubectl wait --namespace applications entry/service --for=condition=Ready --timeout=120s
```

The example creates its namespace, Secrets, ProviderConfig and Entry.
`crossplane.io/external-name` is the LDAP DN, including when adopting an existing
entry. `restrictAttributes` defines which attributes the controller owns; other
attributes remain externally managed. Secret changes take effect during
reconciliation. TLS defaults to enabled.

Omitting `managementPolicies` defaults to `["*"]`, which includes deletion.
The example's `managementPolicies: [Observe, Create, Update]` retains LDAP data
when the Kubernetes Entry is deleted. Add `Delete` to delete both. Use `[Observe]`
for read-only adoption. This API uses management policies rather than a
`deletionPolicy` field. See [usage](docs/usage.md) for shared credentials and
attribute ownership, and [contributing](CONTRIBUTING.md) for builds and releases.
