<!--
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: Apache-2.0
-->

# LDAP ownership and credentials

`Entry` (`ldap.finnes.dev/v1alpha1`) reconciles its desired `spec.forProvider.dn`.
When available, the controller records the LDAP entryUUID after adoption in
`crossplane.io/external-name` and follows that identity across renames and moves.
Changing the DN uses LDAP ModifyDN; it does not adopt an unrelated destination.
Observe-only policies never rename an entry. Delete follows the bound identity,
including when a requested destination is occupied by another entry. Directories
without readable entryUUID support fixed-DN CRUD only. UUID-protected writes and
rename/move require the RFC 4528 assertion control; unsupported servers fail closed.

Use plain maps of LDAP attribute names to value lists:

| Field | Behavior |
| --- | --- |
| `attributes` | Exact declared values; `[]` clears the attribute |
| `sharedAttributes` | Manage declared values while preserving other values |
| `attributeSecretRefs` | One exact value from each local Secret key |

LDAP multivalued attributes are [unordered sets](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.1.7).
List order does not affect reconciliation. LDAP schema aliases and matching rules
remain authoritative for attribute identity and value equality.

Omitted exact attributes remain unmanaged. Shared values are claimed even when
they already exist in LDAP. Removing a declared shared value removes its
LDAP-equivalent value while preserving other values. `[]` or omitting the shared
attribute removes all prior claims before relinquishing ownership. The provider
persists inline shared values in status before writes and verifies cleanup after
interrupted updates. First declare current values and wait for convergence when
adopting existing configuration: historical ownership cannot be inferred.

A key cannot overlap the maps, including aliases and case variants. Secret
references must resolve locally. Secret-backed attributes always use exact
ownership.
Attribute changes use one atomic LDAP Modify. A DN change and an attribute update
are separate operations; readiness requires both to be observed as converged.

Secret changes reconcile continuously; referenced values are never copied to
status. `status.atProvider.observedGeneration` and `observedSecretVersions`
acknowledge configuration and Secret versions confirmed against LDAP. Secret
version keys use the configured attribute description in lowercase, with sorted
options (for example, `userpassword`).
The LDAP server receives each supplied value as-is, including `userPassword`.
Use a prehashed Secret value when the directory hashes passwords: server-side
rewriting of a declared plaintext value prevents exact-value convergence. See
[OpenLDAP password storage](https://www.openldap.org/doc/admin25/security.html#Password%20Storage).

The bind identity needs read access to the entry's `subschemaSubentry` and its
`attributeTypes` schema, so aliases and numeric attribute OIDs resolve correctly.
Shared-value removals use the RFC 3876
matched-values control; unsupported directories fail closed. LDAP matching rules
remain authoritative. The bind identity also needs access to entryUUID and
rootDSE namingContexts for UUID discovery within its authorized search scope.

Omitting `managementPolicies` defaults to `["*"]`, including deletion.

| Management policies | Behavior |
| --- | --- |
| `Observe` | Adopt and observe without changing LDAP |
| `Observe, Create, Update` | Create and repair drift; retain LDAP data on deletion |
| `Observe, Create, Update, Delete` | Also delete the LDAP entry on deletion |

A namespaced `ProviderConfig` (`ldap.finnes.dev/v1beta1`) references a Secret:

```yaml
spec:
  credentials:
    source: Secret
    secretRef:
      name: directory-credentials
      key: credentials.yaml
      namespace: applications
```

That key contains YAML or JSON with `host`, `port` (default 636), `bindDN`,
`password`, `tls` (default true), and optional `tlsServerName`.
Namespaced configurations read local Secrets only.

`ClusterProviderConfig` additionally requires a nonempty `namespaceSelector`,
explicit credential Secret namespace, TLS, and `allowedBases`. Each entry must
be a direct child of an allowed base, with first RDN value starting
`<namespace>.`. Administrators must control authorization labels. LDAP ACLs
remain the directory permission boundary. In-use configurations are protected
by standard ProviderConfigUsage tracking. Namespaced configurations discover UUIDs
within advertised namingContexts; shared configurations search only allowedBases.
An external move outside that search scope cannot be recovered by a directory-wide
scan. A known unauthorized source fails closed; an undiscoverable entry may be
recreated at its desired DN when Create is enabled.

## Optional compositions

Install [function-go-templating](../examples/compositions/functions.yaml) and the
chosen `definition.yaml` under [examples/compositions](../examples/compositions/),
then configure its `example.yaml` with your namespace, backend and base DN.
These APIs are examples installed separately from the provider package.

`GroupOfNames` declares its CN and optional description in `attributes`, and its
groupOfNames class and sentinel membership in `sharedAttributes`. Other memberships
remain managed by the directory's UI or other writers. Supply a non-login
sentinel identity; the composition does not manage human memberships. Changing
`sentinelDN` replaces the provider-owned membership while preserving other
members. Changing `cn` or `baseDN` renames or moves the same LDAP group.

`ServiceAccount` creates a 32-character random password and a persisted bcrypt
hash in a Secret named by Crossplane. Applications use its `password` key; LDAP
uses its `ldap-password` hash. This OpenLDAP example requires `{CRYPT}` bcrypt
support and acceptance of prehashed passwords. It exposes the Secret name through
`status.secretRef.name`. Applications should use the returned reference rather
than an assumed Secret name. This API does not accept an existing Secret name;
the generated Secret belongs to the composite.
The observed password is reused across reconciles and controller restarts.

Change `rotationID` to request a new password. Ready is false until LDAP confirms
the current Secret version. Rotation updates the Secret before LDAP, so consumers
can briefly see a password that LDAP has not accepted yet; coordinate application
reloads accordingly. Deleting or losing the Secret also rotates credentials;
back it up if credentials must survive disaster recovery. Passwords never appear
in composite status. Changing `cn` or `baseDN` renames or moves the account without rotating its
password. Use `rotationID` to request credential rotation explicitly.

Both examples expose `deletionPolicy: Delete|Orphan`, translated to native
management policies. Orphan retains LDAP data, but deleting the composite still
garbage-collects its Kubernetes Secret. Recreating it generates new credentials.
