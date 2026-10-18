// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	"github.com/go-ldap/ldap/v3"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type fixtureLDAP struct {
	entry        *ldap.Entry
	changes      []*ldap.ModifyRequest
	created      *ldap.AddRequest
	beforeModify func()
	compareErr   error
	compareFn    func(string, string, string) (bool, error)
	searchFn     func(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

func (f *fixtureLDAP) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.searchFn != nil {
		return f.searchFn(request)
	}
	if f.entry == nil {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("absent"))
	}
	copy := ldap.NewEntry(f.entry.DN, map[string][]string{})
	for _, a := range f.entry.Attributes {
		copy.Attributes = append(copy.Attributes, &ldap.EntryAttribute{Name: a.Name, Values: append([]string{}, a.Values...)})
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{copy}}, nil
}
func (f *fixtureLDAP) Compare(dn string, key, value string) (bool, error) {
	if f.compareFn != nil {
		return f.compareFn(dn, key, value)
	}
	if f.compareErr != nil {
		return false, f.compareErr
	}
	return contains(attributeValues(f.entry, key), value), nil
}
func (f *fixtureLDAP) Add(request *ldap.AddRequest) error { f.created = request; return nil }
func (f *fixtureLDAP) Modify(request *ldap.ModifyRequest) error {
	if f.beforeModify != nil {
		f.beforeModify()
		f.beforeModify = nil
	}
	f.changes = append(f.changes, request)
	next := ldap.NewEntry(f.entry.DN, map[string][]string{})
	for _, a := range f.entry.Attributes {
		next.Attributes = append(next.Attributes, &ldap.EntryAttribute{Name: a.Name, Values: append([]string{}, a.Values...)})
	}
	for _, change := range request.Changes {
		var attr *ldap.EntryAttribute
		for _, a := range next.Attributes {
			if canonicalAttributeName(a.Name) == canonicalAttributeName(change.Modification.Type) {
				attr = a
				break
			}
		}
		if attr == nil {
			attr = &ldap.EntryAttribute{Name: change.Modification.Type}
			next.Attributes = append(next.Attributes, attr)
		}
		switch change.Operation {
		case ldap.AddAttribute:
			for _, value := range change.Modification.Vals {
				if contains(attr.Values, value) {
					return ldap.NewError(ldap.LDAPResultAttributeOrValueExists, fmt.Errorf("racing writer"))
				}
				attr.Values = append(attr.Values, value)
			}
		case ldap.ReplaceAttribute:
			attr.Values = change.Modification.Vals
		case ldap.DeleteAttribute:
			for _, value := range change.Modification.Vals {
				if !contains(attr.Values, value) {
					return ldap.NewError(ldap.LDAPResultNoSuchAttribute, fmt.Errorf("racing removal"))
				}
				remaining := []string{}
				for _, current := range attr.Values {
					if current != value {
						remaining = append(remaining, current)
					}
				}
				attr.Values = remaining
			}
		default:
			return fmt.Errorf("unexpected LDAP operation")
		}
	}
	f.entry = next
	return nil
}
func (f *fixtureLDAP) ModifyDN(*ldap.ModifyDNRequest) error { return nil }
func (f *fixtureLDAP) Del(*ldap.DelRequest) error           { f.entry = nil; return nil }
func (f *fixtureLDAP) Close() error                         { return nil }
func TestAtomicAddPreservesConcurrentMembership(t *testing.T) {
	dn := "cn=group,dc=example"
	conn := &fixtureLDAP{entry: ldap.NewEntry(dn, map[string][]string{"member": {"uid=existing,dc=example"}, "description": {"old"}, "owner": {"uid=owner,dc=example"}})}
	conn.beforeModify = func() {
		for _, a := range conn.entry.Attributes {
			if a.Name == "member" {
				a.Values = append(a.Values, "uid=concurrent,dc=example")
			}
		}
	}
	external := &ldapExternal{conn: conn, desired: map[string][]string{"description": {"new"}}, shared: map[string][]string{"member": {"uid=sentinel,dc=example"}}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = dn
	persistExternalFixture(t, external, entry)
	if _, err := external.Update(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"uid=existing,dc=example", "uid=concurrent,dc=example", "uid=sentinel,dc=example"} {
		if !contains(attributeValues(conn.entry, "member"), want) {
			t.Fatalf("lost membership %s", want)
		}
	}
	if !contains(attributeValues(conn.entry, "owner"), "uid=owner,dc=example") {
		t.Fatal("undeclared owner overwritten")
	}
	if len(conn.changes) != 1 || conn.changes[0].Changes[0].Operation != ldap.AddAttribute {
		t.Fatal("membership update was not atomic Add")
	}
}
func TestConcurrentSentinelAddIsIdempotent(t *testing.T) {
	dn := "cn=group,dc=example"
	conn := &fixtureLDAP{entry: ldap.NewEntry(dn, map[string][]string{"member": {"uid=human,dc=example"}})}
	conn.beforeModify = func() {
		conn.entry.Attributes[0].Values = append(conn.entry.Attributes[0].Values, "uid=sentinel,dc=example")
	}
	external := &ldapExternal{conn: conn, shared: map[string][]string{"member": {"uid=sentinel,dc=example"}}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = dn
	persistExternalFixture(t, external, entry)
	if _, err := external.Update(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
}
func TestOwnedClearAndOmittedPreserve(t *testing.T) {
	conn := &fixtureLDAP{entry: ldap.NewEntry("cn=group,dc=example", map[string][]string{"description": {"old"}, "owner": {"someone"}})}
	external := &ldapExternal{conn: conn, desired: map[string][]string{"description": {}}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = conn.entry.DN
	persistExternalFixture(t, external, entry)
	if _, err := external.Update(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if len(attributeValues(conn.entry, "description")) != 0 || !contains(attributeValues(conn.entry, "owner"), "someone") {
		t.Fatal("clear/preserve contract failed")
	}
}
func TestCreateMaterializesEscapedAndMultivaluedRDN(t *testing.T) {
	conn := &fixtureLDAP{}
	external := &ldapExternal{conn: conn, shared: map[string][]string{"objectClass": {"inetOrgPerson"}}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = `uid=service+cn=Media\, Server,dc=example`
	persistExternalFixture(t, external, entry)
	if _, err := external.Create(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	attrs := map[string][]string{}
	for _, a := range conn.created.Attributes {
		attrs[a.Type] = a.Vals
	}
	if !contains(attrs["uid"], "service") || !contains(attrs["cn"], "Media, Server") {
		t.Fatal("DN naming attributes not materialized")
	}
}
func TestOwnershipValidation(t *testing.T) {
	for _, p := range []entryapi.EntryParameters{
		{DN: "cn=group,dc=example", Attributes: map[string][]string{"member": {"a"}, "Member": {"b"}}},
		{DN: "cn=group,dc=example", Attributes: map[string][]string{"member": {"a"}}, SharedAttributes: map[string][]string{"MEMBER": {"b"}}},
		{DN: "cn=group,dc=example", Attributes: map[string][]string{"cn": {"different"}}},
		{DN: "cn=group,dc=example", Attributes: map[string][]string{"bad key": {"a"}}},
		{DN: "cn=group,dc=example", Attributes: map[string][]string{"description": {"a", "a"}}},
	} {
		if err := validateParameters(p); err == nil {
			t.Fatalf("invalid ownership accepted: %#v", p)
		}
	}
}
func TestSecretAttributeResolutionStaysLocal(t *testing.T) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credential", Namespace: "media"}, Data: map[string][]byte{"value": []byte("sensitive-fixture")}}
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(secret).Build()
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.AttributeSecretRefs = map[string]xpv2.LocalSecretKeySelector{"userPassword": {LocalSecretReference: xpv2.LocalSecretReference{Name: "credential"}, Key: "value"}}
	desired, _, err := resolveAttributes(context.Background(), kube, entry)
	if err != nil {
		t.Fatal(err)
	}
	if desired["userPassword"][0] != "sensitive-fixture" {
		t.Fatal("local Secret not resolved")
	}
	if entry.Status.AtProvider.UUID != "" || entry.Status.AtProvider.DN != "" {
		t.Fatal("credential resolution populated status")
	}
}

func TestDeletionObservationIgnoresAttributeDrift(t *testing.T) {
	conn := &fixtureLDAP{entry: ldap.NewEntry("cn=group,dc=example", map[string][]string{}), compareErr: fmt.Errorf("attribute comparison is unavailable")}
	external := &ldapExternal{conn: conn, desired: map[string][]string{"description": {"desired"}}, shared: map[string][]string{"member": {"uid=sentinel,dc=example"}}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = conn.entry.DN
	now := metav1.Now()
	entry.SetDeletionTimestamp(&now)
	observation, err := external.Observe(context.Background(), entry)
	if err != nil || !observation.ResourceExists {
		t.Fatalf("deletion observation depends on unrelated attribute state: %v", err)
	}
}

func TestLDAPAttributeDescriptions(t *testing.T) {
	for _, name := range []string{"cn", "objectClass", "2.5.4.3", "2.5.4.3;binary", "cn;lang-en"} {
		p := entryapi.EntryParameters{DN: "uid=service,dc=example", Attributes: map[string][]string{name: {"value"}}}
		if err := validateParameters(p); err != nil {
			t.Fatalf("valid LDAP attribute %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{`1\x2`, `2\.5\.4\.3`, "2x5x4x3", "2.5.", "2..5"} {
		p := entryapi.EntryParameters{DN: "uid=service,dc=example", Attributes: map[string][]string{name: {"value"}}}
		if err := validateParameters(p); err == nil {
			t.Fatalf("invalid LDAP attribute %q accepted", name)
		}
	}
}

func TestHealthyObservePreservesReadyTransitionTime(t *testing.T) {
	entry := testEntry("ProviderConfig", "fixture")
	ready := xpv2.Available()
	ready.LastTransitionTime = metav1.NewTime(time.Unix(100, 0))
	entry.SetConditions(ready)
	conn := &fixtureLDAP{entry: ldap.NewEntry(entry.Spec.ForProvider.DN, map[string][]string{"cn": {"service"}})}
	external := &ldapExternal{conn: conn, desired: map[string][]string{"cn": {"service"}}}
	for i := 0; i < 2; i++ {
		observed, err := external.Observe(context.Background(), entry)
		if err != nil || !observed.ResourceUpToDate {
			t.Fatalf("healthy observation failed: %v", err)
		}
		if got := entry.GetCondition(ready.Type); !got.LastTransitionTime.Equal(&ready.LastTransitionTime) {
			t.Fatalf("healthy poll changed Ready transition time: %v", got.LastTransitionTime)
		}
	}
	conn.entry = ldap.NewEntry(entry.Spec.ForProvider.DN, map[string][]string{"cn": {"drift"}})
	observed, err := external.Observe(context.Background(), entry)
	if err != nil || observed.ResourceUpToDate || entry.GetCondition(ready.Type).Status != corev1.ConditionFalse {
		t.Fatalf("known drift retained Ready=True: %v", err)
	}
}

func persistExternalFixture(t *testing.T, external *ldapExternal, entry *entryapi.Entry) {
	t.Helper()
	if len(external.shared) == 0 || external.kube != nil {
		return
	}
	entry.Name = "fixture"
	external.kube = fake.NewClientBuilder().WithScheme(testScheme(t)).WithStatusSubresource(&entryapi.Entry{}).WithObjects(entry).Build()
	if err := external.kube.Get(context.Background(), client.ObjectKeyFromObject(entry), entry); err != nil {
		t.Fatal(err)
	}
}
