<!--
SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
SPDX-License-Identifier: MIT
-->

# LDAP ownership and credentials

`Entry` uses `crossplane.io/external-name` as its LDAP DN. Keep it stable after
creation. Recreate an Entry with the same DN to adopt retained data.

Omitting `managementPolicies` defaults to `["*"]`, enabling all operations,
including deletion. Set policies explicitly for retained entries.

| Management policies | Behavior |
| --- | --- |
| `Observe` | Read an existing entry without changing it |
| `Observe, Create, Update` | Create and repair drift; retain LDAP data when the Entry is deleted |
| `Observe, Create, Update, Delete` | Also delete the LDAP entry when the Entry is deleted |

`dataJsonSecretRef` references a Secret document mapping attribute names to arrays
of strings. `restrictAttributes` defines ownership. Include an attribute when
its absence from the document should remove the external value. Attributes
outside that list remain externally managed. The underlying SDK also exposes
creation defaults; ordinary desired attributes belong in `dataJsonSecretRef`
and reconcile continuously. Attribute documents stay out of resource status.

A namespaced `ProviderConfig` reads credentials from its own namespace. TLS
defaults to enabled; `tlsServerName` overrides the certificate name when the
connection host differs from it.

For shared credentials, `ClusterProviderConfig` requires a nonempty
`namespaceSelector`, a credential Secret namespace, TLS, and `allowedBases`.
Each DN must be a direct child of an allowed base and its first RDN value must
start with `<namespace>.`. Administrators must control authorization labels;
LDAP ACLs remain the external permission boundary. Prefer namespaced credentials
when they can be scoped to one namespace.

The existing `ldap.ops.finnes.dev` API group is retained for compatibility.
