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

Omitted keys remain unmanaged. Attribute names cannot overlap between maps,
including case variants. Secret references must resolve in the Entry namespace.
Secret changes reconcile continuously; desired sensitive values are not copied
to status. The LDAP server receives each supplied value as-is, including
`userPassword`; configure server password policy or supply an appropriate hash
if the server requires one.

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

`ServiceAccount` creates a 32-character random password in the named local
Secret, then reconciles an inetOrgPerson Entry referencing that Secret. The
observed Secret password is reused across reconciles and controller restarts.
Change `rotationID` explicitly to rotate it. Deleting or losing the Secret also
rotates credentials; preserve it if the password must survive disaster recovery.
The password is not placed in composite status. Configure immutable `cn` and
`baseDN` before creation; use a stable `secretName` for applications.

Both examples expose `deletionPolicy: Delete|Orphan`, translated to native
management policies. Orphan retains LDAP data, but deleting the composite still
garbage-collects its Kubernetes Secret. Recreating it generates new credentials.
