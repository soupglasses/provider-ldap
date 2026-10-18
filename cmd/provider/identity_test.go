// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crossplane/crossplane-runtime/v2/pkg/meta"
	"github.com/go-ldap/ldap/v3"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	identityA     = "11111111-1111-4111-8111-111111111111"
	identityB     = "22222222-2222-4222-8222-222222222222"
	identityOldDN = "uid=media.old,ou=users,dc=example,dc=test"
	identityNewDN = "uid=media.new,ou=users,dc=example,dc=test"
)

type identityPatchFailure struct{ client.Client }

func (identityPatchFailure) Patch(context.Context, client.Object, client.Patch, ...client.PatchOption) error {
	return errors.New("metadata unavailable")
}

func identityResponse(entry *ldap.Entry) *ldap.Entry {
	attrs := map[string][]string{}
	for _, attr := range entry.Attributes {
		attrs[attr.Name] = append([]string{}, attr.Values...)
	}
	return ldap.NewEntry(entry.DN, attrs)
}

type identityDirectory struct {
	fixtureLDAP
	records         map[string]*ldap.Entry
	renames         []*ldap.ModifyDNRequest
	searches        []*ldap.SearchRequest
	lostRenameReply bool
	caseExact       bool
}

func (d *identityDirectory) at(dn string) *ldap.Entry {
	for name, entry := range d.records {
		if name == dn || (!d.caseExact && equalDN(name, dn)) {
			return entry
		}
	}
	return nil
}
func (d *identityDirectory) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	d.searches = append(d.searches, r)
	if r.BaseDN == "" {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{"namingContexts": {"dc=example,dc=test"}})}}, nil
	}
	if r.Scope == ldap.ScopeWholeSubtree {
		id := strings.TrimSuffix(strings.TrimPrefix(r.Filter, "(entryUUID="), ")")
		result := &ldap.SearchResult{}
		base, _ := ldap.ParseDN(r.BaseDN)
		for _, entry := range d.records {
			dn, _ := ldap.ParseDN(entry.DN)
			if (base.EqualFold(dn) || base.AncestorOfFold(dn)) && entry.GetEqualFoldAttributeValue("entryUUID") == id {
				result.Entries = append(result.Entries, identityResponse(entry))
			}
		}
		return result, nil
	}
	entry := d.at(r.BaseDN)
	if entry == nil {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("absent"))
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{identityResponse(entry)}}, nil
}
func (d *identityDirectory) ModifyDN(r *ldap.ModifyDNRequest) error {
	d.renames = append(d.renames, r)
	entry := d.at(r.DN)
	if entry == nil {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("absent"))
	}
	if len(r.Controls) != 1 {
		return errors.New("missing UUID assertion")
	}
	expected, _ := ldap.CompileFilter("(entryUUID=" + entry.GetEqualFoldAttributeValue("entryUUID") + ")")
	assertion, ok := r.Controls[0].(*ldap.ControlString)
	if !ok || assertion.ControlType != assertionControlOID || !assertion.Criticality || assertion.ControlValue != string(expected.Bytes()) {
		return ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("wrong identity"))
	}
	parsed, _ := ldap.ParseDN(r.DN)
	parent := (&ldap.DN{RDNs: parsed.RDNs[1:]}).String()
	if r.NewSuperior != "" {
		parent = r.NewSuperior
	}
	target := r.NewRDN + "," + parent
	if d.at(target) != nil {
		return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("occupied"))
	}
	delete(d.records, entry.DN)
	entry.DN = target
	d.records[target] = entry
	if d.lostRenameReply {
		d.lostRenameReply = false
		return ldap.NewError(ldap.ErrorNetwork, errors.New("reply lost"))
	}
	return nil
}
func (d *identityDirectory) Del(r *ldap.DelRequest) error {
	entry := d.at(r.DN)
	if entry == nil {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("absent"))
	}
	expected, _ := ldap.CompileFilter("(entryUUID=" + entry.GetEqualFoldAttributeValue("entryUUID") + ")")
	if len(r.Controls) != 1 {
		return errors.New("missing UUID assertion")
	}
	assertion, ok := r.Controls[0].(*ldap.ControlString)
	if !ok || assertion.ControlValue != string(expected.Bytes()) {
		return ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("wrong identity"))
	}
	delete(d.records, entry.DN)
	return nil
}
func identityRecord(dn, id string) *ldap.Entry {
	attrs := map[string][]string{"objectClass": {"inetOrgPerson"}}
	if id != "" {
		attrs["entryUUID"] = []string{id}
	}
	return ldap.NewEntry(dn, attrs)
}
func identityFixture(t *testing.T, binding, target string, records ...*ldap.Entry) (*ldapExternal, *entryapi.Entry, *identityDirectory) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := entryapi.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	entry := &entryapi.Entry{TypeMeta: metav1.TypeMeta{APIVersion: entryapi.CRDGroupVersion.String(), Kind: "Entry"}, ObjectMeta: metav1.ObjectMeta{Namespace: "media", Name: "identity", UID: types.UID("managed-resource")}, Spec: entryapi.EntrySpec{ForProvider: entryapi.EntryParameters{DN: target}}}
	meta.SetExternalName(entry, binding)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&entryapi.Entry{}).WithObjects(entry).Build()
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: entry.Namespace, Name: entry.Name}, entry); err != nil {
		t.Fatal(err)
	}
	directory := &identityDirectory{records: map[string]*ldap.Entry{}}
	for _, record := range records {
		directory.records[record.DN] = record
	}
	external := &ldapExternal{conn: directory, identity: &entryIdentity{kube: kube, scope: identityScope{namespace: "media"}}}
	return external, entry, directory
}
func TestIdentityAdoptionPersistsUUIDBeforeRename(t *testing.T) {
	external, entry, directory := identityFixture(t, identityOldDN, identityNewDN, identityRecord(identityOldDN, identityA))
	exists, err := external.refreshIdentity(context.Background(), entry)
	if err != nil || !exists {
		t.Fatalf("adoption: %v", err)
	}
	stored := &entryapi.Entry{}
	if err := external.identity.kube.Get(context.Background(), client.ObjectKeyFromObject(entry), stored); err != nil {
		t.Fatal(err)
	}
	if meta.GetExternalName(stored) != identityA || len(directory.renames) != 0 {
		t.Fatal("UUID was not durable before mutation")
	}
	if err := external.rename(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if len(directory.renames) != 1 || !directory.renames[0].DeleteOldRDN || directory.at(identityNewDN).GetAttributeValue("entryUUID") != identityA {
		t.Fatal("rename did not preserve LDAP identity")
	}
}
func TestIdentityRenameRecoversLostReplyAndReusedDN(t *testing.T) {
	external, entry, directory := identityFixture(t, identityA, identityNewDN, identityRecord(identityOldDN, identityA))
	entry.Status.AtProvider.DN = identityOldDN
	if _, err := external.refreshIdentity(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	directory.lostRenameReply = true
	if err := external.rename(context.Background(), entry); err == nil {
		t.Fatal("lost reply was not surfaced")
	}
	directory.records[identityOldDN] = identityRecord(identityOldDN, identityB)
	entry.Spec.ForProvider.DN = "uid=media.latest,ou=users,dc=example,dc=test"
	restarted := &ldapExternal{conn: directory, identity: &entryIdentity{kube: external.identity.kube, scope: external.identity.scope}}
	if exists, err := restarted.refreshIdentity(context.Background(), entry); err != nil || !exists {
		t.Fatalf("UUID recovery: %v", err)
	}
	if restarted.actualDN(entry) != identityNewDN {
		t.Fatal("reused old DN was adopted instead of the bound UUID")
	}
	if err := restarted.rename(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if directory.at(identityOldDN).GetAttributeValue("entryUUID") != identityB || directory.at(entry.Spec.ForProvider.DN).GetAttributeValue("entryUUID") != identityA {
		t.Fatal("rename touched a foreign replacement")
	}
}
func TestIdentityParentMoveAndTargetCollision(t *testing.T) {
	external, entry, directory := identityFixture(t, identityA, "uid=media.new,ou=services,dc=example,dc=test", identityRecord(identityOldDN, identityA))
	entry.Status.AtProvider.DN = identityOldDN
	if _, err := external.refreshIdentity(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	directory.records[entry.Spec.ForProvider.DN] = identityRecord(entry.Spec.ForProvider.DN, identityB)
	if err := external.rename(context.Background(), entry); err == nil || len(directory.renames) != 0 {
		t.Fatal("foreign destination was not rejected before ModifyDN")
	}
	delete(directory.records, entry.Spec.ForProvider.DN)
	if err := external.rename(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if directory.renames[0].NewSuperior != "ou=services,dc=example,dc=test" {
		t.Fatal("parent move did not specify newSuperior")
	}
}
func TestIdentityMissingUUIDIsFixedDNOnly(t *testing.T) {
	external, entry, _ := identityFixture(t, identityOldDN, identityOldDN, identityRecord(identityOldDN, ""))
	if exists, err := external.refreshIdentity(context.Background(), entry); err != nil || !exists {
		t.Fatalf("fixed-DN fallback: %v", err)
	}
	entry.Spec.ForProvider.DN = identityNewDN
	if _, err := external.refreshIdentity(context.Background(), entry); err == nil {
		t.Fatal("rename without entryUUID was accepted")
	}
}
func TestIdentityCreateIntentSurvivesRestartAndRejectsForeignReplacement(t *testing.T) {
	external, entry, directory := identityFixture(t, identityA, identityNewDN)
	entry.Status.AtProvider.DN = identityOldDN
	if err := external.prepareCreate(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if meta.GetExternalName(entry) != identityNewDN {
		t.Fatal("creation target not durable before Add")
	}
	// A definite Add rejection restores the old UUID, so an unrelated winner is never adopted.
	if err := external.abortCreate(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	directory.records[identityNewDN] = identityRecord(identityNewDN, identityB)
	if err := external.prepareCreate(context.Background(), entry); err == nil || meta.GetExternalName(entry) != identityA {
		t.Fatal("foreign replacement was adopted")
	}
	delete(directory.records, identityNewDN)
	if err := external.prepareCreate(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	// Model a successful Add whose reply was lost before the UUID metadata update.
	directory.records[identityNewDN] = identityRecord(identityNewDN, identityB)
	restarted := &ldapExternal{conn: directory, identity: &entryIdentity{kube: external.identity.kube, scope: external.identity.scope}}
	if exists, err := restarted.refreshIdentity(context.Background(), entry); err != nil || !exists || meta.GetExternalName(entry) != identityB {
		t.Fatalf("pending Add recovery failed: %v", err)
	}
}
func TestIdentityDeletionWithPendingRenamePreservesForeignTarget(t *testing.T) {
	external, entry, directory := identityFixture(t, identityA, identityNewDN, identityRecord(identityOldDN, identityA), identityRecord(identityNewDN, identityB))
	entry.Status.AtProvider.DN = identityOldDN
	if _, err := external.refreshIdentity(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if _, err := external.Delete(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if directory.at(identityOldDN) != nil || directory.at(identityNewDN).GetAttributeValue("entryUUID") != identityB {
		t.Fatal("pending rename deletion touched the foreign target")
	}
}
func TestIdentityMetadataFailureAndSourceAuthorizationBlockWrites(t *testing.T) {
	external, entry, directory := identityFixture(t, identityOldDN, identityNewDN, identityRecord(identityOldDN, identityA))
	base := external.identity.kube
	external.identity.kube = identityPatchFailure{Client: base}
	if _, err := external.refreshIdentity(context.Background(), entry); err == nil || len(directory.renames) != 0 {
		t.Fatal("metadata failure did not block mutation")
	}
	external.identity.kube = base
	external.identity.scope = identityScope{shared: true, namespace: "media", bases: []string{"ou=services,dc=example,dc=test"}}
	entry.Status.AtProvider.DN = identityOldDN
	meta.SetExternalName(entry, identityA)
	if _, err := external.refreshIdentity(context.Background(), entry); err == nil {
		t.Fatal("out-of-scope source was accepted")
	}
}
func TestIdentityRejectsReplacementBetweenResolveAndDelete(t *testing.T) {
	external, entry, directory := identityFixture(t, identityA, identityOldDN, identityRecord(identityOldDN, identityA))
	if _, err := external.refreshIdentity(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	directory.records[identityOldDN] = identityRecord(identityOldDN, identityB)
	if _, err := external.Delete(context.Background(), entry); err == nil {
		t.Fatal("UUID assertion did not reject a replacement")
	}
	if directory.at(identityOldDN).GetAttributeValue("entryUUID") != identityB {
		t.Fatal("foreign replacement was deleted")
	}
}

func TestIdentityRenameUsesServerDNMatching(t *testing.T) {
	for _, exact := range []bool{true, false} {
		t.Run(map[bool]string{true: "case exact", false: "case ignore"}[exact], func(t *testing.T) {
			old := "uid=media.Case,ou=users,dc=example,dc=test"
			target := "uid=media.case,ou=users,dc=example,dc=test"
			external, entry, directory := identityFixture(t, identityA, target, identityRecord(old, identityA))
			directory.caseExact = exact
			entry.Status.AtProvider.DN = old
			if exists, err := external.refreshIdentity(context.Background(), entry); err != nil || !exists {
				t.Fatalf("resolve: %v", err)
			}
			if external.needsRename(entry) != exact {
				t.Fatal("rename decision ignored LDAP DN lookup")
			}
			if err := external.rename(context.Background(), entry); err != nil {
				t.Fatal(err)
			}
			want := 0
			if exact {
				want = 1
			}
			if len(directory.renames) != want {
				t.Fatal("incorrect ModifyDN count")
			}
			if _, err := external.refreshIdentity(context.Background(), entry); err != nil {
				t.Fatal(err)
			}
			if external.needsRename(entry) {
				t.Fatal("converged identity requests another rename")
			}
		})
	}
}
func TestIdentityCaseExactParentMove(t *testing.T) {
	old := "uid=media.person,ou=Case,dc=example,dc=test"
	target := "uid=media.person,ou=case,dc=example,dc=test"
	external, entry, directory := identityFixture(t, identityA, target, identityRecord(old, identityA))
	directory.caseExact = true
	entry.Status.AtProvider.DN = old
	if _, err := external.refreshIdentity(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if err := external.rename(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if len(directory.renames) != 1 || directory.renames[0].NewSuperior != "ou=case,dc=example,dc=test" {
		t.Fatal("case-exact parent move was suppressed")
	}
}
