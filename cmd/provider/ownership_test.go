// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"strings"
	"testing"

	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	"github.com/go-ldap/ldap/v3"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func subsetFixture(t *testing.T, claimed []string) (*ldapExternal, *entryapi.Entry, *fixtureLDAP) {
	t.Helper()
	entry := testEntry("ProviderConfig", "fixture")
	entry.Name = "owned"
	entry.UID = types.UID("ownership-fixture")
	entry.Generation = 1
	entry.Spec.ManagementPolicies = xpv2.ManagementPolicies{xpv2.ManagementActionAll}
	entry.Spec.ForProvider.DN = "cn=group,dc=example"
	entry.Spec.ForProvider.SharedAttributes = map[string][]string{"member": claimed}
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithStatusSubresource(&entryapi.Entry{}).WithObjects(entry).Build()
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(entry), entry); err != nil {
		t.Fatal(err)
	}
	values := append([]string{"human"}, claimed...)
	conn := &fixtureLDAP{entry: ldap.NewEntry(entry.Spec.ForProvider.DN, map[string][]string{"member": values})}
	matchedValueFixture(t, conn)
	external := &ldapExternal{kube: kube, conn: conn, shared: map[string][]string{"member": claimed}}
	return external, entry, conn
}
func updateSubsetSpec(t *testing.T, external *ldapExternal, entry *entryapi.Entry, values []string, omit bool) {
	t.Helper()
	entry.Generation++
	if omit {
		entry.Spec.ForProvider.SharedAttributes = nil
		external.shared = nil
	} else {
		entry.Spec.ForProvider.SharedAttributes = map[string][]string{"member": values}
		external.shared = entry.Spec.ForProvider.SharedAttributes
	}
	if err := external.kube.Update(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
}
func TestSubsetAdoptsCurrentValuesAndRetiresAcrossRestart(t *testing.T) {
	ctx := context.Background()
	external, entry, conn := subsetFixture(t, []string{"first"})
	observed, err := external.Observe(ctx, entry)
	if err != nil || !observed.ResourceUpToDate {
		t.Fatalf("initial subset adoption failed: %v", err)
	}
	persisted := &entryapi.Entry{}
	if err := external.kube.Get(ctx, client.ObjectKeyFromObject(entry), persisted); err != nil {
		t.Fatal(err)
	}
	if !contains(persisted.Status.OwnedAttributeValues["member"], "first") {
		t.Fatal("already-current declared value was not durably claimed")
	}
	updateSubsetSpec(t, external, entry, []string{"second"}, false)
	conn.beforeModify = func() {
		current := &entryapi.Entry{}
		if err := external.kube.Get(ctx, client.ObjectKeyFromObject(entry), current); err != nil {
			t.Fatal(err)
		}
		if !contains(current.Status.OwnedAttributeValues["member"], "first") || !contains(current.Status.OwnedAttributeValues["member"], "second") {
			t.Fatal("LDAP write preceded durable ownership intent")
		}
	}
	if _, err := external.Update(ctx, entry); err != nil {
		t.Fatal(err)
	}
	// Simulate process loss after directory write but before verified status compaction.
	recovered := &entryapi.Entry{}
	if err := external.kube.Get(ctx, client.ObjectKeyFromObject(entry), recovered); err != nil {
		t.Fatal(err)
	}
	restarted := &ldapExternal{kube: external.kube, conn: conn, shared: recovered.Spec.ForProvider.SharedAttributes}
	updateSubsetSpec(t, restarted, recovered, []string{"third"}, false)
	if _, err := restarted.Update(ctx, recovered); err != nil {
		t.Fatal(err)
	}
	observed, err = restarted.Observe(ctx, recovered)
	if err != nil || !observed.ResourceUpToDate {
		t.Fatalf("restarted subset did not converge: %v", err)
	}
	values := attributeValues(conn.entry, "member")
	if contains(values, "first") || contains(values, "second") || !contains(values, "third") || !contains(values, "human") {
		t.Fatalf("owned retirement lost or leaked values: %v", values)
	}
	if len(recovered.Status.OwnedAttributeValues["member"]) != 1 || recovered.Status.OwnedAttributeValues["member"][0] != "third" {
		t.Fatal("verified ledger did not compact to current declared intent")
	}
}
func TestSubsetEmptyAndOmittedAttributesRetireClaims(t *testing.T) {
	for _, omit := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "omitted"}[omit], func(t *testing.T) {
			ctx := context.Background()
			external, entry, conn := subsetFixture(t, []string{"owned"})
			if _, err := external.Observe(ctx, entry); err != nil {
				t.Fatal(err)
			}
			updateSubsetSpec(t, external, entry, []string{}, omit)
			if _, err := external.Update(ctx, entry); err != nil {
				t.Fatal(err)
			}
			observed, err := external.Observe(ctx, entry)
			if err != nil || !observed.ResourceUpToDate {
				t.Fatalf("retirement did not converge: %v", err)
			}
			if contains(attributeValues(conn.entry, "member"), "owned") || !contains(attributeValues(conn.entry, "member"), "human") {
				t.Fatal("cleanup deleted unmanaged data or leaked owned value")
			}
			if len(entry.Status.OwnedAttributeValues) != 0 {
				t.Fatal("retired ledger persisted after verification")
			}
		})
	}
}
func TestSubsetClaimsRespectManagementPolicies(t *testing.T) {
	for _, policies := range []xpv2.ManagementPolicies{
		{xpv2.ManagementActionObserve},
		{xpv2.ManagementActionObserve, xpv2.ManagementActionCreate},
		{xpv2.ManagementActionObserve, xpv2.ManagementActionUpdate},
	} {
		ctx := context.Background()
		external, entry, _ := subsetFixture(t, []string{"preexisting"})
		entry.Spec.ManagementPolicies = policies
		if err := external.kube.Update(ctx, entry); err != nil {
			t.Fatal(err)
		}
		if _, err := external.Observe(ctx, entry); err != nil {
			t.Fatal(err)
		}
		expect := false
		for _, policy := range policies {
			expect = expect || policy == xpv2.ManagementActionUpdate
		}
		if contains(entry.Status.OwnedAttributeValues["member"], "preexisting") != expect {
			t.Fatalf("existing-value claim did not respect policy %v", policies)
		}
	}
	external, entry, _ := subsetFixture(t, []string{"created"})
	entry.Spec.ManagementPolicies = xpv2.ManagementPolicies{xpv2.ManagementActionObserve, xpv2.ManagementActionCreate}
	if err := external.kube.Update(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if err := external.prepareOwnership(context.Background(), entry, true); err != nil {
		t.Fatal(err)
	}
	if !contains(entry.Status.OwnedAttributeValues["member"], "created") {
		t.Fatal("Create policy could not claim before creation")
	}
}
func TestSubsetDoesNotRetireDirectoryEquivalentDesiredValue(t *testing.T) {
	ctx := context.Background()
	external, entry, conn := subsetFixture(t, []string{"uid=Sentinel,dc=example"})
	if _, err := external.Observe(ctx, entry); err != nil {
		t.Fatal(err)
	}
	updateSubsetSpec(t, external, entry, []string{"UID=sentinel,DC=example"}, false)
	// This fixture models the directory's distinguishedNameMatch rule, not a client-side rule.
	conn.compareFn = func(_ string, key, value string) (bool, error) {
		for _, current := range attributeValues(conn.entry, key) {
			if strings.EqualFold(current, value) {
				return true, nil
			}
		}
		return false, nil
	}
	if _, err := external.Update(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if len(conn.changes) != 0 {
		t.Fatal("equivalent desired value was needlessly added or deleted")
	}
	observed, err := external.Observe(ctx, entry)
	if err != nil || !observed.ResourceUpToDate {
		t.Fatalf("equivalent subset did not verify: %v", err)
	}
	if !contains(attributeValues(conn.entry, "member"), "uid=Sentinel,dc=example") {
		t.Fatal("retirement deleted desired-equivalent stored value")
	}
}
func TestSubsetLedgerQuotaReleasesConfirmedAbsentHistory(t *testing.T) {
	ctx := context.Background()
	external, entry, _ := subsetFixture(t, []string{"new"})
	retired := strings.Repeat("x", maxOwnedBytes-len("member"))
	entry.Status.OwnedAttributeValues = map[string][]string{"member": {retired}}
	if err := external.kube.Status().Update(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if err := external.prepareOwnership(ctx, entry, false); err != nil {
		t.Fatalf("confirmed-absent history permanently blocked ledger capacity: %v", err)
	}
	if len(entry.Status.OwnedAttributeValues["member"]) != 1 || entry.Status.OwnedAttributeValues["member"][0] != "new" {
		t.Fatal("quota cleanup retained absent history or lost new intent")
	}
}
func TestSubsetStaleIntentCannotMutateDirectory(t *testing.T) {
	ctx := context.Background()
	external, entry, conn := subsetFixture(t, []string{"first"})
	if _, err := external.Observe(ctx, entry); err != nil {
		t.Fatal(err)
	}
	updateSubsetSpec(t, external, entry, []string{"second"}, false)
	stale := entry.DeepCopy()
	entry.Labels = map[string]string{"concurrent": "change"}
	if err := external.kube.Update(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := external.Update(ctx, stale); !apierrors.IsConflict(err) {
		t.Fatalf("expected optimistic status conflict, got %v", err)
	}
	if len(conn.changes) != 0 || !contains(attributeValues(conn.entry, "member"), "first") || contains(attributeValues(conn.entry, "member"), "second") {
		t.Fatal("stale ownership intent mutated directory")
	}
	persisted := &entryapi.Entry{}
	if err := external.kube.Get(ctx, client.ObjectKeyFromObject(entry), persisted); err != nil {
		t.Fatal(err)
	}
	if contains(persisted.Status.OwnedAttributeValues["member"], "second") {
		t.Fatal("stale intent escaped optimistic lock")
	}
}

func TestSharedReplacementIsAtomicAndPreservesConcurrentValues(t *testing.T) {
	ctx := context.Background()
	external, entry, conn := subsetFixture(t, []string{"old-sentinel"})
	if _, err := external.Observe(ctx, entry); err != nil {
		t.Fatal(err)
	}
	updateSubsetSpec(t, external, entry, []string{"new-sentinel"}, false)
	external.desired = map[string][]string{"description": {"updated"}}
	conn.beforeModify = func() {
		for _, attr := range conn.entry.Attributes {
			if attr.Name == "member" {
				attr.Values = append(attr.Values, "concurrent-human")
			}
		}
	}
	if _, err := external.Update(ctx, entry); err != nil {
		t.Fatal(err)
	}
	values := attributeValues(conn.entry, "member")
	if contains(values, "old-sentinel") || !contains(values, "new-sentinel") || !contains(values, "human") || !contains(values, "concurrent-human") {
		t.Fatalf("shared replacement lost unmanaged values: %v", values)
	}
	if len(conn.changes) != 1 || len(conn.changes[0].Changes) != 3 {
		t.Fatal("shared add, owned retirement, and exact replace were not one atomic LDAP Modify")
	}
}
