// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	"github.com/go-ldap/ldap/v3"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var attributeName = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*|[0-9]+(\.[0-9]+)+)(;[A-Za-z0-9-]+)*$`)

func parseDN(raw string) (*ldap.DN, error) {
	dn, err := ldap.ParseDN(raw)
	if err != nil || len(dn.RDNs) == 0 {
		return nil, fmt.Errorf("dn must be a valid nonempty LDAP distinguished name")
	}
	return dn, nil
}
func validateParameters(p entryapi.EntryParameters) error {
	dn, err := parseDN(p.DN)
	if err != nil {
		return err
	}
	modes := map[string]string{}
	validateMap := func(mode string, attrs map[string][]string) error {
		local := map[string]bool{}
		for key, values := range attrs {
			canonical := canonicalAttributeName(key)
			if len(key) > 128 || !attributeName.MatchString(key) {
				return fmt.Errorf("invalid LDAP attribute name")
			}
			if local[canonical] {
				return fmt.Errorf("attribute %s occurs more than once in %s", key, mode)
			}
			local[canonical] = true
			if previous, ok := modes[canonical]; ok && (previous == "exact" || mode == "exact") {
				return fmt.Errorf("attribute %s overlaps exact ownership", key)
			}
			modes[canonical] = mode
			seen := map[string]bool{}
			for _, value := range values {
				if seen[value] {
					return fmt.Errorf("attribute %s contains duplicate values", key)
				}
				seen[value] = true
			}
		}
		return nil
	}
	if err := validateMap("exact", p.Attributes); err != nil {
		return err
	}
	secretNames := map[string][]string{}
	for key, ref := range p.AttributeSecretRefs {
		if ref.Name == "" || ref.Key == "" {
			return fmt.Errorf("attribute %s requires a complete local Secret reference", key)
		}
		secretNames[key] = nil
	}
	if err := validateMap("exact", secretNames); err != nil {
		return err
	}
	if err := validateMap("additive", p.AdditiveAttributes); err != nil {
		return err
	}
	if err := validateMap("absent", p.AbsentAttributes); err != nil {
		return err
	}
	for key, present := range p.AdditiveAttributes {
		for absentKey, absent := range p.AbsentAttributes {
			if canonicalAttributeName(key) == canonicalAttributeName(absentKey) {
				for _, value := range present {
					if contains(absent, value) {
						return fmt.Errorf("attribute %s declares the same value present and absent", key)
					}
				}
			}
		}
	}
	for key, mode := range p.AttributeOwnership {
		if len(key) > 128 || !attributeName.MatchString(key) {
			return fmt.Errorf("invalid LDAP ownership attribute name")
		}
		if mode != entryapi.AttributeOwnershipExact && mode != entryapi.AttributeOwnershipSubset {
			return fmt.Errorf("unknown attribute ownership policy")
		}
		if mode == entryapi.AttributeOwnershipSubset {
			for secretKey := range p.AttributeSecretRefs {
				if canonicalAttributeName(secretKey) == canonicalAttributeName(key) {
					return fmt.Errorf("Secret references cannot use Subset ownership")
				}
			}
		}
	}
	// A replace-owned RDN attribute must include its naming value to avoid illegal renames.
	for _, rdn := range dn.RDNs[0].Attributes {
		for key, values := range p.Attributes {
			if strings.EqualFold(key, rdn.Type) && len(p.AttributeOwnership) == 0 && !contains(values, rdn.Value) {
				return fmt.Errorf("attribute %s must include the DN naming value", key)
			}
		}
		for key, values := range p.AbsentAttributes {
			if canonicalAttributeName(key) == canonicalAttributeName(rdn.Type) && contains(values, rdn.Value) {
				return fmt.Errorf("DN naming values cannot be declared absent")
			}
		}
		for key := range p.AttributeSecretRefs {
			if strings.EqualFold(key, rdn.Type) {
				return fmt.Errorf("DN naming attributes cannot use Secret references")
			}
		}
	}
	return nil
}
func resolveAttributes(ctx context.Context, k client.Client, entry *entryapi.Entry) (map[string][]string, map[string]string, error) {
	versions := map[string]string{}
	out := make(map[string][]string, len(entry.Spec.ForProvider.Attributes)+len(entry.Spec.ForProvider.AttributeSecretRefs))
	for key, values := range entry.Spec.ForProvider.Attributes {
		out[key] = append([]string{}, values...)
	}
	secrets := map[string]*corev1.Secret{}
	for key, ref := range entry.Spec.ForProvider.AttributeSecretRefs {
		secret := secrets[ref.Name]
		if secret == nil {
			secret = &corev1.Secret{}
			if err := k.Get(ctx, types.NamespacedName{Namespace: entry.Namespace, Name: ref.Name}, secret); err != nil {
				return nil, nil, fmt.Errorf("read local attribute Secret: %w", err)
			}
			secrets[ref.Name] = secret
		}
		value, ok := secret.Data[ref.Key]
		if !ok || len(value) == 0 {
			return nil, nil, fmt.Errorf("attribute %s Secret key is missing or empty", key)
		}
		out[key] = []string{string(value)}
		versions[canonicalAttributeName(key)] = secret.ResourceVersion
	}
	return out, versions, nil
}

// LDAP operations are narrow so ownership can be tested against a directory contract.
type ldapConnection interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Compare(string, string, string) (bool, error)
	Add(*ldap.AddRequest) error
	Modify(*ldap.ModifyRequest) error
	ModifyDN(*ldap.ModifyDNRequest) error
	Del(*ldap.DelRequest) error
	Close() error
}
type ldapExternal struct {
	kube      client.Client
	ownership map[string]entryapi.AttributeOwnershipPolicy
	identity  *entryIdentity
	ledger    map[string][]string

	conn           ldapConnection
	desired        map[string][]string
	additive       map[string][]string
	absent         map[string][]string
	secretVersions map[string]string
	schema         attributeSchema
	stopCancel     func() bool
}

func (e *ldapExternal) cancelOnContext(ctx context.Context) {
	e.stopCancel = context.AfterFunc(ctx, func() { _ = e.conn.Close() })
}
func (e *ldapExternal) Disconnect(context.Context) error {
	if e.stopCancel != nil {
		e.stopCancel()
	}
	return e.conn.Close()
}
func (e *ldapExternal) operationError(ctx context.Context, operation string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return directoryError(operation, err)
}
func (e *ldapExternal) read(ctx context.Context, dn string) (*ldap.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	selected := map[string][]string{"entryUUID": nil}
	for key := range e.desired {
		selected[key] = nil
	}
	for key := range e.additive {
		selected[key] = nil
	}
	for key := range e.absent {
		selected[key] = nil
	}
	for key := range e.ledger {
		selected[key] = nil
	}
	result, err := e.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", keys(selected), nil))
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, nil
	}
	if err != nil {
		return nil, e.operationError(ctx, "observe", err)
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("LDAP base search did not return exactly one entry")
	}
	entry := result.Entries[0]
	if err := e.verifyIdentity(entry); err != nil {
		return nil, err
	}
	for _, attribute := range entry.Attributes {
		if canonical, err := e.schema.key(attribute.Name); err == nil {
			attribute.Name = canonical
		}
	}
	return entry, nil
}
func canonicalAttributeName(key string) string {
	parts := strings.Split(strings.ToLower(key), ";")
	sort.Strings(parts[1:])
	return strings.Join(parts, ";")
}
func attributeValues(entry *ldap.Entry, key string) []string {
	for _, attr := range entry.Attributes {
		if canonicalAttributeName(attr.Name) == canonicalAttributeName(key) {
			return attr.Values
		}
	}
	return nil
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func keys(attrs map[string][]string) []string {
	out := make([]string, 0, len(attrs))
	for key := range attrs {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// Compare delegates schema-specific equality (DNs, case, normalization) to the LDAP server.
func (e *ldapExternal) hasValue(ctx context.Context, observed *ldap.Entry, key, value string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if contains(attributeValues(observed, key), value) {
		return true, nil
	}
	same, err := e.conn.Compare(observed.DN, key, value)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
		return false, nil
	}
	if err != nil {
		return false, e.operationError(ctx, "compare", err)
	}
	return same, nil
}
func (e *ldapExternal) upToDate(ctx context.Context, observed *ldap.Entry, entry *entryapi.Entry) (bool, error) {
	if err := e.validateValuePolicies(ctx, observed.DN); err != nil {
		return false, err
	}
	for key, want := range e.desired {
		if !e.isSubset(key) && len(attributeValues(observed, key)) != len(want) {
			return false, nil
		}
		for _, value := range want {
			same, err := e.hasValue(ctx, observed, key, value)
			if err != nil {
				return false, err
			}
			if !same {
				return false, nil
			}
		}
	}
	for key, want := range e.additive {
		for _, value := range want {
			same, err := e.hasValue(ctx, observed, key, value)
			if err != nil {
				return false, err
			}
			if !same {
				return false, nil
			}
		}
	}
	for key, values := range e.absent {
		for _, value := range values {
			present, err := e.hasValue(ctx, observed, key, value)
			if err != nil {
				return false, err
			}
			if present {
				return false, nil
			}
		}
	}
	retired, err := e.retiredValues(ctx, observed.DN, entry)
	if err != nil {
		return false, err
	}
	for _, values := range retired {
		if len(values) > 0 {
			return false, nil
		}
	}
	return true, nil
}
func (e *ldapExternal) Observe(ctx context.Context, mg resource.Managed) (result managed.ExternalObservation, observeErr error) {
	entry := mg.(*entryapi.Entry)
	defer func() {
		if entry.GetDeletionTimestamp().IsZero() && (observeErr != nil || !result.ResourceExists || !result.ResourceUpToDate) {
			entry.SetConditions(xpv2.Unavailable())
		}
	}()
	exists, err := e.refreshIdentity(ctx, entry)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	if !exists {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	if err := e.prepareOwnership(ctx, entry, false); err != nil {
		return managed.ExternalObservation{}, err
	}
	e.ledger = entry.Status.OwnedAttributeValues
	observed, err := e.read(ctx, e.actualDN(entry))
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	if observed == nil {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	entry.Status.AtProvider.DN = observed.DN
	uuidKey, _ := e.schema.key("entryUUID")
	if uuidKey == "" {
		uuidKey = "entryUUID"
	}
	entry.Status.AtProvider.UUID = ""
	if values := attributeValues(observed, uuidKey); len(values) > 0 {
		entry.Status.AtProvider.UUID = values[0]
	}
	if !entry.GetDeletionTimestamp().IsZero() {
		return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
	}
	current, err := e.upToDate(ctx, observed, entry)
	if err == nil && e.needsRename(entry) {
		current = false
	}
	if err == nil && current {
		entry.SetConditions(xpv2.Available())
		e.compactOwnership(entry)
		entry.Status.AtProvider.ObservedGeneration = entry.Generation
		entry.Status.AtProvider.ObservedSecretVersions = e.secretVersions
	}
	return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: current}, err
}
func (e *ldapExternal) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	if err := ctx.Err(); err != nil {
		return managed.ExternalCreation{}, err
	}
	entry := mg.(*entryapi.Entry)
	if err := e.prepareOwnership(ctx, entry, true); err != nil {
		return managed.ExternalCreation{}, err
	}
	if err := e.prepareCreate(ctx, entry); err != nil {
		return managed.ExternalCreation{}, err
	}
	attrs := map[string][]string{}
	for _, source := range []map[string][]string{e.desired, e.additive} {
		for key, values := range source {
			if len(values) > 0 {
				attrs[key] = append([]string{}, values...)
			}
		}
	}
	dn, err := parseDN(entry.Spec.ForProvider.DN)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	for _, rdn := range dn.RDNs[0].Attributes {
		key, err := e.schema.key(rdn.Type)
		if err != nil {
			return managed.ExternalCreation{}, err
		}
		for existing := range attrs {
			if strings.EqualFold(existing, key) {
				key = existing
				break
			}
		}
		if !contains(attrs[key], rdn.Value) {
			attrs[key] = append(attrs[key], rdn.Value)
		}
	}
	request := ldap.NewAddRequest(entry.Spec.ForProvider.DN, nil)
	for _, key := range keys(attrs) {
		request.Attribute(key, attrs[key])
	}
	if err := ctx.Err(); err != nil {
		return managed.ExternalCreation{}, err
	}
	if err := e.conn.Add(request); err != nil {
		var rejected *ldap.Error
		if errors.As(err, &rejected) && rejected.ResultCode < 200 {
			if restoreErr := e.abortCreate(ctx, entry); restoreErr != nil {
				return managed.ExternalCreation{}, restoreErr
			}
		}
		return managed.ExternalCreation{}, e.operationError(ctx, "create", err)
	}
	if err := e.bindCreated(ctx, entry); err != nil {
		return managed.ExternalCreation{}, err
	}
	return managed.ExternalCreation{}, nil
}
func (e *ldapExternal) planModify(ctx context.Context, dn string, observed *ldap.Entry, entry *entryapi.Entry) (*ldap.ModifyRequest, error) {
	if err := e.validateValuePolicies(ctx, dn); err != nil {
		return nil, err
	}
	controls, err := e.assertionControls()
	if err != nil {
		return nil, err
	}
	request := ldap.NewModifyRequest(dn, controls)
	// Every operation is one atomic LDAP Modify, so auxiliary classes and their
	// required attributes become valid together. Add never replaces foreign values.
	for _, key := range keys(e.additive) {
		for _, value := range e.additive[key] {
			present, err := e.hasValue(ctx, observed, key, value)
			if err != nil {
				return nil, err
			}
			if !present {
				request.Add(key, []string{value})
			}
		}
	}
	for _, key := range keys(e.desired) {
		want := e.desired[key]
		if e.isSubset(key) {
			for _, value := range want {
				present, err := e.hasValue(ctx, observed, key, value)
				if err != nil {
					return nil, err
				}
				if !present {
					request.Add(key, []string{value})
				}
			}
			continue
		}
		same := len(attributeValues(observed, key)) == len(want)
		if same {
			for _, value := range want {
				equal, err := e.hasValue(ctx, observed, key, value)
				if err != nil {
					return nil, err
				}
				if !equal {
					same = false
					break
				}
			}
		}
		if !same {
			request.Replace(key, want)
		}
	}
	for _, key := range keys(e.absent) {
		for _, value := range e.absent[key] {
			present, err := e.hasValue(ctx, observed, key, value)
			if err != nil {
				return nil, err
			}
			if present {
				request.Delete(key, []string{value})
			}
		}
	}
	retired, err := e.retiredValues(ctx, dn, entry)
	if err != nil {
		return nil, err
	}
	for _, key := range keys(retired) {
		for _, value := range retired[key] {
			request.Delete(key, []string{value})
		}
	}
	return request, nil
}
func (e *ldapExternal) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	entry := mg.(*entryapi.Entry)
	if err := e.prepareOwnership(ctx, entry, false); err != nil {
		return managed.ExternalUpdate{}, err
	}
	if err := e.rename(ctx, entry); err != nil {
		return managed.ExternalUpdate{}, err
	}
	e.ledger = entry.Status.OwnedAttributeValues
	for attempt := 0; attempt < 3; attempt++ {
		observed, err := e.read(ctx, e.actualDN(entry))
		if err != nil {
			return managed.ExternalUpdate{}, err
		}
		if observed == nil {
			return managed.ExternalUpdate{}, fmt.Errorf("LDAP entry disappeared before update")
		}
		request, err := e.planModify(ctx, e.actualDN(entry), observed, entry)
		if err != nil {
			return managed.ExternalUpdate{}, err
		}
		if len(request.Changes) == 0 {
			return managed.ExternalUpdate{}, nil
		}
		if err := ctx.Err(); err != nil {
			return managed.ExternalUpdate{}, err
		}
		err = e.conn.Modify(request)
		if err == nil {
			return managed.ExternalUpdate{}, nil
		}
		// The server rejected the entire atomic request. Re-read instead of dropping
		// other pending changes when another writer added or removed a target first.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultAttributeOrValueExists) || ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
			continue
		}
		return managed.ExternalUpdate{}, e.operationError(ctx, "atomic attribute update", err)
	}
	return managed.ExternalUpdate{}, fmt.Errorf("LDAP attribute update conflicted repeatedly with concurrent writers")
}
func (e *ldapExternal) Delete(ctx context.Context, mg resource.Managed) (managed.ExternalDelete, error) {
	if err := ctx.Err(); err != nil {
		return managed.ExternalDelete{}, err
	}
	entry := mg.(*entryapi.Entry)
	controls, err := e.assertionControls()
	if err != nil {
		return managed.ExternalDelete{}, err
	}
	if err := e.conn.Del(ldap.NewDelRequest(e.actualDN(entry), controls)); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return managed.ExternalDelete{}, e.operationError(ctx, "delete", err)
	}
	return managed.ExternalDelete{}, nil
}
