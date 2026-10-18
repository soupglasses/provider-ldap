<!--
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: Apache-2.0
-->

# LDAP ownership and credentials

`Entry` (`ldap.finnes.dev/v1alpha1`) declares an immutable `spec.forProvider.dn`.
Recreate an Entry with the same DN to adopt retained data. Its first RDN
attributes are included automatically when creating the LDAP entry.

| Field | Ownership |
| --- | --- |
| `attributes` | Exact values for declared keys; `[]` clears a key |
| `attributeSecretRefs` | One exact attribute value from each referenced Secret key |
| `additiveAttributes` | Ensure these values exist without removing extra values |
| `absentAttributes` | Remove only these values; preserve all other values |

Omitted keys remain unmanaged. Exact ownership cannot overlap with additive or
absent ownership, including aliases and case variants. Additive and absent
values may share an attribute but must not contradict one another under the
directory's matching rules. Changes are submitted in one atomic LDAP Modify,
so adding a required object class and its attributes succeeds together. Secret
references must resolve in the Entry namespace.
Secret changes reconcile continuously; desired sensitive values are not copied
to status. `status.atProvider.observedGeneration` and `observedSecretVersions`
acknowledge configuration and Secret versions confirmed against LDAP. Secret
version keys use the configured attribute description in lowercase, with sorted
options (for example, `userpassword`).
The LDAP server receives each supplied value as-is, including `userPassword`.
Use a prehashed Secret value when the directory hashes passwords: server-side
rewriting of a declared plaintext value prevents exact-value convergence. See
[OpenLDAP password storage](https://www.openldap.org/doc/admin25/security.html#Password%20Storage).

The bind identity needs read access to the entry's `subschemaSubentry` and its
`attributeTypes` schema, so aliases and numeric attribute OIDs resolve correctly.
Combining additive and absent values for one attribute additionally requires
the RFC 3876 matched-values control; unsupported directories fail closed.
LDAP matching rules remain authoritative for value equality. Contradictory
present/absent declarations fail before removal; if neither equivalent value
exists yet, the contradiction is detected after the required value is created.

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
by standard ProviderConfigUsage tracking.

## Optional compositions

Install [function-go-templating](../examples/compositions/functions.yaml) and the
chosen `definition.yaml` under [examples/compositions](../examples/compositions/),
then configure its `example.yaml` with your namespace, backend and base DN.
These APIs are examples installed separately from the provider package.

`GroupOfNames` owns its CN and optional description, while additively ensuring
`objectClass: groupOfNames` and one configured sentinel DN. Other memberships
remain managed by the directory's UI or other writers. Supply a non-login
sentinel identity; the composition does not create or manage human memberships.
Changing `sentinelDN` adds the new sentinel and removes prior sentinels in one
atomic update. The composition records pending sentinel transitions in status
before applying them, so interrupted migrations preserve their intent. Keep DN
spelling consistent; equivalent DNs cannot be declared both present and absent.

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
in composite status. Configure immutable `cn` and `baseDN` before creation.

Both examples expose `deletionPolicy: Delete|Orphan`, translated to native
management policies. Orphan retains LDAP data, but deleting the composite still
garbage-collects its Kubernetes Secret. Recreating it generates new credentials.
