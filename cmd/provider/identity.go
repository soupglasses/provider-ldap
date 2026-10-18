// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/crossplane/crossplane-runtime/v2/pkg/meta"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	configapi "github.com/soupglasses/provider-ldap/apis/namespaced/v1beta1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const assertionControlOID = "1.3.6.1.1.12"

type entryIdentity struct {
	kube              client.Client
	scope             identityScope
	uuid              string
	currentDN         string
	previousBinding   string
	atDesiredDN       bool
	resolvedDesiredDN string
}

type identityScope struct {
	namespace string
	bases     []string
	shared    bool
}

func identityScopeFor(ctx context.Context, k client.Client, entry *entryapi.Entry) (identityScope, error) {
	scope := identityScope{namespace: entry.Namespace}
	ref := entry.GetProviderConfigReference()
	if ref == nil {
		return scope, fmt.Errorf("a provider configuration reference is required")
	}
	if ref.Kind == "ClusterProviderConfig" {
		pc := &configapi.ClusterProviderConfig{}
		if err := k.Get(ctx, types.NamespacedName{Name: ref.Name}, pc); err != nil {
			return scope, err
		}
		scope.shared = true
		scope.bases = append([]string{}, pc.Spec.AllowedBases...)
	}
	return scope, nil
}
func (s identityScope) authorize(dn string) error {
	if s.shared {
		return validateEntryDN(dn, s.namespace, s.bases)
	}
	_, err := parseDN(dn)
	return err
}
func equalDN(a, b string) bool {
	left, err := parseDN(a)
	if err != nil {
		return false
	}
	right, err := parseDN(b)
	return err == nil && left.EqualFold(right)
}
func identityUUID(value string) (string, error) {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return "", fmt.Errorf("LDAP identity requires an RFC4530 entryUUID")
	}
	return parsed.String(), nil
}
func entryUUID(entry *ldap.Entry) (string, error) {
	values := entry.GetEqualFoldAttributeValues("entryUUID")
	if len(values) == 0 {
		values = entry.GetEqualFoldAttributeValues("1.3.6.1.1.16.4")
	}
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("directory returned more than one entryUUID")
	}
	return identityUUID(values[0])
}
func (e *ldapExternal) actualDN(entry *entryapi.Entry) string {
	if e.identity != nil && e.identity.currentDN != "" {
		return e.identity.currentDN
	}
	return entry.Spec.ForProvider.DN
}
func (e *ldapExternal) needsRename(entry *entryapi.Entry) bool {
	if e.identity == nil {
		return false
	}
	return !e.identity.atDesiredDN || e.identity.resolvedDesiredDN != entry.Spec.ForProvider.DN
}
func (e *ldapExternal) identityRead(ctx context.Context, dn string) (*ldap.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := e.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"entryUUID"}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, nil
	}
	if err != nil {
		return nil, e.operationError(ctx, "resolve entry identity", err)
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("identity base search did not return exactly one entry")
	}
	return result.Entries[0], nil
}
func (e *ldapExternal) persistBinding(ctx context.Context, entry *entryapi.Entry, binding string) error {
	if meta.GetExternalName(entry) == binding {
		return nil
	}
	if e.identity == nil || e.identity.kube == nil {
		return fmt.Errorf("cannot persist LDAP identity without a Kubernetes client")
	}
	before := entry.DeepCopy()
	meta.SetExternalName(entry, binding)
	if err := e.identity.kube.Patch(ctx, entry, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		meta.SetExternalName(entry, meta.GetExternalName(before))
		return fmt.Errorf("persist LDAP external identity: %w", err)
	}
	return nil
}
func (e *ldapExternal) bindIdentity(ctx context.Context, entry *entryapi.Entry, observed *ldap.Entry) error {
	if err := e.identity.scope.authorize(observed.DN); err != nil {
		return err
	}
	value, err := entryUUID(observed)
	if err != nil {
		return err
	}
	if value != "" {
		if err := e.persistBinding(ctx, entry, value); err != nil {
			return err
		}
	}
	e.identity.uuid = value
	e.identity.currentDN = observed.DN
	return nil
}
func (e *ldapExternal) identitySearchBases(ctx context.Context) ([]string, error) {
	if e.identity.scope.shared {
		return e.identity.scope.bases, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := e.conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"namingContexts"}, nil))
	if err != nil {
		return nil, e.operationError(ctx, "discover identity search bases", err)
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("directory did not publish readable namingContexts")
	}
	var bases []string
	for _, base := range result.Entries[0].GetEqualFoldAttributeValues("namingContexts") {
		if _, err := parseDN(base); err != nil {
			return nil, fmt.Errorf("directory published an invalid naming context")
		}
		duplicate := false
		for _, existing := range bases {
			if equalDN(base, existing) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			bases = append(bases, base)
		}
	}
	if len(bases) == 0 {
		return nil, fmt.Errorf("UUID discovery requires readable root DSE namingContexts")
	}
	return bases, nil
}
func (e *ldapExternal) findUUID(ctx context.Context, entry *entryapi.Entry, binding string) (*ldap.Entry, error) {
	e.identity.atDesiredDN = false
	e.identity.resolvedDesiredDN = entry.Spec.ForProvider.DN
	candidates := []string{entry.Spec.ForProvider.DN, entry.Status.AtProvider.DN}
	checked := map[string]bool{}
	for _, dn := range candidates {
		if dn == "" || checked[dn] {
			continue
		}
		checked[dn] = true
		if err := e.identity.scope.authorize(dn); err != nil {
			return nil, err
		}
		observed, err := e.identityRead(ctx, dn)
		if err != nil {
			return nil, err
		}
		if observed == nil {
			continue
		}
		value, err := entryUUID(observed)
		if err != nil {
			return nil, err
		}
		if value == "" {
			return nil, fmt.Errorf("cannot verify a bound identity without readable entryUUID")
		}
		if value == binding {
			e.identity.atDesiredDN = dn == entry.Spec.ForProvider.DN
			if err := e.identity.scope.authorize(observed.DN); err != nil {
				return nil, err
			}
			return observed, nil
		}
	}
	bases, err := e.identitySearchBases(ctx)
	if err != nil {
		return nil, err
	}
	var found *ldap.Entry
	for _, base := range bases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := e.conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, "(entryUUID="+ldap.EscapeFilter(binding)+")", []string{"entryUUID"}, nil))
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			continue
		}
		if err != nil {
			return nil, e.operationError(ctx, "find bound LDAP identity", err)
		}
		for _, observed := range result.Entries {
			value, err := entryUUID(observed)
			if err != nil {
				return nil, err
			}
			if value != binding {
				return nil, fmt.Errorf("directory UUID search returned a different identity")
			}
			if err := e.identity.scope.authorize(observed.DN); err != nil {
				return nil, err
			}
			if found != nil && !equalDN(found.DN, observed.DN) {
				return nil, fmt.Errorf("directory returned an ambiguous entryUUID")
			}
			found = observed
		}
	}
	return found, nil
}

// Resolve by the bound UUID before trusting any DN, which may have been reused.
// Legacy DN annotations are an explicit adoption anchor until the first UUID is persisted.
func (e *ldapExternal) refreshIdentity(ctx context.Context, entry *entryapi.Entry) (bool, error) {
	if e.identity == nil {
		return true, nil
	}
	binding := meta.GetExternalName(entry)
	if binding == "" {
		return false, fmt.Errorf("LDAP external identity has not been initialized")
	}
	if value, err := identityUUID(binding); err == nil {
		e.identity.uuid = value
		observed, err := e.findUUID(ctx, entry, value)
		if err != nil {
			return false, err
		}
		e.identity.currentDN = ""
		if observed == nil {
			return false, nil
		}
		e.identity.currentDN = observed.DN
		return true, nil
	}
	anchor, err := parseDN(binding)
	if err != nil || len(anchor.RDNs) == 0 {
		return false, fmt.Errorf("external name must be a bound entryUUID or an adoption DN")
	}
	if err := e.identity.scope.authorize(binding); err != nil {
		return false, err
	}
	observed, err := e.identityRead(ctx, binding)
	if err != nil {
		return false, err
	}
	e.identity.currentDN = ""
	if observed == nil {
		return false, nil
	}
	if err := e.bindIdentity(ctx, entry, observed); err != nil {
		return false, err
	}
	e.identity.resolvedDesiredDN = entry.Spec.ForProvider.DN
	e.identity.atDesiredDN = binding == entry.Spec.ForProvider.DN
	if e.identity.uuid == "" {
		if !e.identity.atDesiredDN {
			return false, fmt.Errorf("renaming requires a readable entryUUID; this entry supports fixed-DN management only")
		}
	} else if !e.identity.atDesiredDN {
		target, err := e.identityRead(ctx, entry.Spec.ForProvider.DN)
		if err != nil {
			return false, err
		}
		if target != nil {
			value, err := entryUUID(target)
			if err != nil {
				return false, err
			}
			e.identity.atDesiredDN = value == e.identity.uuid
		}
	}
	return true, nil
}
func (e *ldapExternal) assertionControls() ([]ldap.Control, error) {
	if e.identity == nil || e.identity.uuid == "" {
		return nil, nil
	}
	filter, err := ldap.CompileFilter("(entryUUID=" + ldap.EscapeFilter(e.identity.uuid) + ")")
	if err != nil {
		return nil, fmt.Errorf("cannot encode UUID assertion")
	}
	return []ldap.Control{ldap.NewControlString(assertionControlOID, true, string(filter.Bytes()))}, nil
}
func (e *ldapExternal) rename(ctx context.Context, entry *entryapi.Entry) error {
	if !e.needsRename(entry) {
		return nil
	}
	if e.identity == nil || e.identity.uuid == "" {
		return fmt.Errorf("renaming requires a readable, durably bound entryUUID")
	}
	source := e.identity.currentDN
	if err := e.identity.scope.authorize(source); err != nil {
		return err
	}
	target := entry.Spec.ForProvider.DN
	if err := e.identity.scope.authorize(target); err != nil {
		return err
	}
	occupied, err := e.identityRead(ctx, target)
	if err != nil {
		return err
	}
	if occupied != nil {
		value, err := entryUUID(occupied)
		if err != nil {
			return err
		}
		if value != e.identity.uuid {
			return fmt.Errorf("rename target DN is occupied by a different LDAP identity")
		}
		e.identity.currentDN = occupied.DN
		e.identity.atDesiredDN = true
		e.identity.resolvedDesiredDN = target
		return nil
	}
	oldDN, err := parseDN(source)
	if err != nil {
		return err
	}
	nextDN, err := parseDN(target)
	if err != nil {
		return err
	}
	superior := ""
	oldParent := &ldap.DN{RDNs: oldDN.RDNs[1:]}
	nextParent := &ldap.DN{RDNs: nextDN.RDNs[1:]}
	if oldParent.String() != nextParent.String() {
		if len(nextParent.RDNs) == 0 {
			return fmt.Errorf("moving an LDAP entry to the empty root DN is not supported")
		}
		superior = nextParent.String()
	}
	controls, err := e.assertionControls()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	request := ldap.NewModifyDNWithControlsRequest(source, nextDN.RDNs[0].String(), true, superior, controls)
	if err := e.conn.ModifyDN(request); err != nil {
		return e.operationError(ctx, "rename bound LDAP entry", err)
	}
	e.identity.currentDN = target
	e.identity.atDesiredDN = true
	e.identity.resolvedDesiredDN = target
	return nil
}

func (e *ldapExternal) prepareCreate(ctx context.Context, entry *entryapi.Entry) error {
	if e.identity == nil {
		return nil
	}
	exists, err := e.refreshIdentity(ctx, entry)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("bound LDAP entry appeared before creation; observe it again")
	}
	if err := e.identity.scope.authorize(entry.Spec.ForProvider.DN); err != nil {
		return err
	}
	occupied, err := e.identityRead(ctx, entry.Spec.ForProvider.DN)
	if err != nil {
		return err
	}
	if occupied != nil {
		return fmt.Errorf("create target DN is occupied by another LDAP identity")
	}
	e.identity.previousBinding = meta.GetExternalName(entry)
	// LDAP assigns entryUUID on Add. Persist the deterministic adoption DN first,
	// so a successful Add with a lost reply is discoverable after restart.
	if err := e.persistBinding(ctx, entry, entry.Spec.ForProvider.DN); err != nil {
		return err
	}
	e.identity.uuid = ""
	e.identity.currentDN = ""
	return nil
}
func (e *ldapExternal) abortCreate(ctx context.Context, entry *entryapi.Entry) error {
	if e.identity == nil || e.identity.previousBinding == "" {
		return nil
	}
	return e.persistBinding(ctx, entry, e.identity.previousBinding)
}
func (e *ldapExternal) bindCreated(ctx context.Context, entry *entryapi.Entry) error {
	if e.identity == nil {
		return nil
	}
	observed, err := e.identityRead(ctx, entry.Spec.ForProvider.DN)
	if err != nil {
		return err
	}
	if observed == nil {
		return fmt.Errorf("created LDAP identity could not be observed")
	}
	return e.bindIdentity(ctx, entry, observed)
}

func (e *ldapExternal) verifyIdentity(observed *ldap.Entry) error {
	if e.identity == nil {
		return nil
	}
	if err := e.identity.scope.authorize(observed.DN); err != nil {
		return err
	}
	if e.identity.uuid == "" {
		return nil
	}
	value, err := entryUUID(observed)
	if err != nil {
		return err
	}
	if value != e.identity.uuid {
		return fmt.Errorf("LDAP DN no longer refers to the bound entryUUID")
	}
	return nil
}
