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

Declare inline values in `attributes`; `attributeOwnership` selects each key's
behavior. The default is `Exact`.

| Ownership | Behavior |
| --- | --- |
| `Exact` | Replace the declared key's values; `[]` clears it |
| `Subset` | Manage only the declared values while preserving other values |

Omitted Exact attributes remain unmanaged. Subset ownership claims preexisting
declared values too. Removing a declared value removes its LDAP-equivalent value,
preserving other values. `[]` removes
all previously claimed values. Omitting the attribute and its ownership setting
also removes prior claims before relinquishing ownership. The provider persists
inline Subset values in status before writes and verifies cleanup after interrupted
updates. LDAP schema aliases and matching rules determine identity and equality.

`attributeSecretRefs` supplies one exact value per local Secret key. Secret-backed
attributes cannot use Subset ownership. Legacy `additiveAttributes` and
`absentAttributes` remain supported but are deprecated; new declarations should
use the ownership modes above. When migrating additive configuration to Subset,
keep the current managed values and wait for convergence before changing or
removing them. Subset cannot infer ownership of historical values it never claimed.
Exact ownership cannot overlap another mode,
including aliases and case variants. Attribute changes use one atomic LDAP
Modify. A DN change and an attribute update are separate operations; readiness
requires both to be observed as converged.

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
Subset removals and legacy additive/absent combinations use the RFC 3876
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

`GroupOfNames` owns its CN and optional description, and uses Subset ownership
for its groupOfNames class and configured sentinel membership. Other memberships
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
