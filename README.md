<!--
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: Apache-2.0
-->

# provider-ldap

A native Crossplane provider for LDAP entries, using
[go-ldap](https://github.com/go-ldap/ldap). Manage service identities and groups
from Git while directory UIs and other writers manage their own attribute values.

- **Continuous reconciliation:** update declared attributes and repair drift.
- **Shared attributes:** add and remove your declared values while preserving
  other values. Ownership intent survives interrupted updates and restarts.
- **Renames and moves:** change the DN through ModifyDN while retaining the same
  entryUUID. UUID assertions protect writes against replacement entries.
- **Credentials and lifecycle:** reconcile local Secret inputs without copying
  their values to status; observe, create, update, delete, or orphan entries.

## Install

Requires Crossplane 2.4 or later. Pin the package digest in production.

```yaml
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: ldap
spec:
  package: ghcr.io/soupglasses/provider-ldap:v0.5.0
```

The [runtime example](tests/provider.yaml) includes probes and restricted Pod
Security settings. See [contributing](CONTRIBUTING.md) for tests and releases.

## Use

Configure the connection in [setup.yaml](examples/setup.yaml), then edit the
[group example](examples/group.yaml) for your directory and non-login sentinel:

```sh
kubectl wait provider/ldap --for=condition=Healthy --timeout=180s
kubectl apply -f examples/setup.yaml -f examples/group.yaml
kubectl wait -n applications entry/application-readers --for=condition=Ready --timeout=120s
```

The group's settings are plain LDAP attribute sets:

```yaml
forProvider:
  dn: cn=application.readers,ou=groups,dc=example,dc=org
  attributes:
    cn: [application.readers]
  sharedAttributes:
    objectClass: [groupOfNames]
    member:
      - uid=group-sentinel,ou=services,dc=example,dc=org
```

Change both `dn` and `attributes.cn` to rename this group. Changing its parent DN
moves it; other memberships survive. Attribute updates and ModifyDN are separate
operations, and Ready requires verified convergence. See [usage](docs/usage.md)
for directory prerequisites, ownership and deletion behavior.

The [service account example](examples/service-account.yaml) uses a password hash
from a Secret. Optional [GroupOfNames and ServiceAccount compositions](examples/compositions/)
provide shorter APIs and generated credentials. Their `cn` and `baseDN` fields
handle renames and moves; ServiceAccount renames preserve generated credentials.
