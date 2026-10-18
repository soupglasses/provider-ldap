// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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
	keys := map[string]bool{}
	addKey := func(key string) error {
		canonical := canonicalAttributeName(key)
		if len(key) > 128 || !attributeName.MatchString(key) {
			return fmt.Errorf("invalid LDAP attribute name")
		}
		if keys[canonical] {
			return fmt.Errorf("attribute %s occurs more than once across ownership modes", key)
		}
		keys[canonical] = true
		return nil
	}
	for _, attrs := range []map[string][]string{p.Attributes, p.AdditiveAttributes} {
		for key, values := range attrs {
			if err := addKey(key); err != nil {
				return err
			}
			seen := map[string]bool{}
			for _, value := range values {
				if seen[value] {
					return fmt.Errorf("attribute %s contains duplicate values", key)
				}
				seen[value] = true
			}
		}
	}
	for key, ref := range p.AttributeSecretRefs {
		if err := addKey(key); err != nil {
			return err
		}
		if ref.Name == "" || ref.Key == "" {
			return fmt.Errorf("attribute %s requires a complete local Secret reference", key)
		}
	}
	// A replace-owned RDN attribute must include its naming value to avoid illegal renames.
	for _, rdn := range dn.RDNs[0].Attributes {
		for key, values := range p.Attributes {
			if strings.EqualFold(key, rdn.Type) && !contains(values, rdn.Value) {
				return fmt.Errorf("attribute %s must include the DN naming value", key)
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
func resolveAttributes(ctx context.Context, k client.Client, entry *entryapi.Entry) (map[string][]string, error) {
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
				return nil, fmt.Errorf("read local attribute Secret: %w", err)
			}
			secrets[ref.Name] = secret
		}
		value, ok := secret.Data[ref.Key]
		if !ok || len(value) == 0 {
			return nil, fmt.Errorf("attribute %s Secret key is missing or empty", key)
		}
		out[key] = []string{string(value)}
	}
	return out, nil
}

// LDAP operations are narrow so ownership can be tested against a directory contract.
type ldapConnection interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Compare(string, string, string) (bool, error)
	Add(*ldap.AddRequest) error
	Modify(*ldap.ModifyRequest) error
	Del(*ldap.DelRequest) error
	Close() error
}
type ldapExternal struct {
	conn     ldapConnection
	desired  map[string][]string
	additive map[string][]string
}

func (e *ldapExternal) Disconnect(context.Context) error { return e.conn.Close() }
func (e *ldapExternal) read(dn string) (*ldap.Entry, error) {
	selected := map[string][]string{"entryUUID": nil}
	for key := range e.desired {
		selected[key] = nil
	}
	for key := range e.additive {
		selected[key] = nil
	}
	result, err := e.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", keys(selected), nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, nil
	}
	if err != nil {
		return nil, directoryError("observe", err)
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("LDAP base search did not return exactly one entry")
	}
	return result.Entries[0], nil
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
func (e *ldapExternal) hasValue(observed *ldap.Entry, key, value string) (bool, error) {
	if contains(attributeValues(observed, key), value) {
		return true, nil
	}
	same, err := e.conn.Compare(observed.DN, key, value)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
		return false, nil
	}
	if err != nil {
		return false, directoryError("compare", err)
	}
	return same, nil
}
func (e *ldapExternal) upToDate(observed *ldap.Entry) (bool, error) {
	for key, want := range e.desired {
		if len(attributeValues(observed, key)) != len(want) {
			return false, nil
		}
		for _, value := range want {
			same, err := e.hasValue(observed, key, value)
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
			same, err := e.hasValue(observed, key, value)
			if err != nil {
				return false, err
			}
			if !same {
				return false, nil
			}
		}
	}
	return true, nil
}
func (e *ldapExternal) Observe(_ context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	entry := mg.(*entryapi.Entry)
	observed, err := e.read(entry.Spec.ForProvider.DN)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	if observed == nil {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	entry.Status.AtProvider = entryapi.EntryObservation{DN: observed.DN, UUID: observed.GetAttributeValue("entryUUID")}
	if !entry.GetDeletionTimestamp().IsZero() {
		return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
	}
	entry.SetConditions(xpv2.Available())
	current, err := e.upToDate(observed)
	return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: current}, err
}
func (e *ldapExternal) Create(_ context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	entry := mg.(*entryapi.Entry)
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
		key := rdn.Type
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
	if err := e.conn.Add(request); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return managed.ExternalCreation{}, directoryError("create", err)
	}
	return managed.ExternalCreation{}, nil
}
func (e *ldapExternal) Update(_ context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	entry := mg.(*entryapi.Entry)
	observed, err := e.read(entry.Spec.ForProvider.DN)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	if observed == nil {
		return managed.ExternalUpdate{}, fmt.Errorf("LDAP entry disappeared before update")
	}
	replace := ldap.NewModifyRequest(entry.Spec.ForProvider.DN, nil)
	for _, key := range keys(e.desired) {
		want := e.desired[key]
		current := attributeValues(observed, key)
		same := len(current) == len(want)
		if same {
			for _, value := range want {
				equal, err := e.hasValue(observed, key, value)
				if err != nil {
					return managed.ExternalUpdate{}, err
				}
				if !equal {
					same = false
					break
				}
			}
		}
		if !same {
			replace.Replace(key, want)
		}
	}
	if len(replace.Changes) > 0 {
		if err := e.conn.Modify(replace); err != nil {
			return managed.ExternalUpdate{}, directoryError("update owned attributes", err)
		}
	}
	// Add one value per atomic request. A concurrent writer adding it first is success,
	// and unrelated values are never replaced from a potentially stale read snapshot.
	for _, key := range keys(e.additive) {
		for _, value := range e.additive[key] {
			present, err := e.hasValue(observed, key, value)
			if err != nil {
				return managed.ExternalUpdate{}, err
			}
			if present {
				continue
			}
			request := ldap.NewModifyRequest(entry.Spec.ForProvider.DN, nil)
			request.Add(key, []string{value})
			if err := e.conn.Modify(request); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultAttributeOrValueExists) {
				return managed.ExternalUpdate{}, directoryError("ensure additive attribute", err)
			}
		}
	}
	return managed.ExternalUpdate{}, nil
}
func (e *ldapExternal) Delete(_ context.Context, mg resource.Managed) (managed.ExternalDelete, error) {
	entry := mg.(*entryapi.Entry)
	if err := e.conn.Del(ldap.NewDelRequest(entry.Spec.ForProvider.DN, nil)); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return managed.ExternalDelete{}, directoryError("delete", err)
	}
	return managed.ExternalDelete{}, nil
}
