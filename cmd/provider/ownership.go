// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	"github.com/go-ldap/ldap/v3"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	maxOwnedAttributes = 256
	maxOwnedValues     = 4096
	maxOwnedBytes      = 256 * 1024
)

func (e *ldapExternal) ownsExactly(key string) bool { _, declared := e.desired[key]; return declared }
func (e *ldapExternal) canClaim(entry *entryapi.Entry, creating bool) bool {
	policy := managed.NewManagementPoliciesResolver(true, entry.GetManagementPolicies())
	return policy.ShouldUpdate() || (creating && policy.ShouldCreate())
}
func cloneOwnership(source map[string][]string) map[string][]string {
	var out map[string][]string
	for key, values := range source {
		if len(values) == 0 {
			continue
		}
		if out == nil {
			out = map[string][]string{}
		}
		out[key] = append([]string{}, values...)
	}
	return out
}
func checkOwnershipLimit(ledger map[string][]string) error {
	values, bytes := 0, 0
	for key, owned := range ledger {
		bytes += len(key)
		for _, value := range owned {
			values++
			bytes += len(value)
		}
	}
	if len(ledger) > maxOwnedAttributes || values > maxOwnedValues || bytes > maxOwnedBytes {
		return fmt.Errorf("subset ownership intent exceeds its safety limit; allow pending changes to converge before adding more values")
	}
	return nil
}

func mergeSharedIntent(intent, shared map[string][]string) map[string][]string {
	for key, values := range shared {
		if len(values) == 0 {
			continue
		}
		if intent == nil {
			intent = map[string][]string{}
		}
		known := sets.New(intent[key]...)
		for _, value := range values {
			if !known.Has(value) {
				known.Insert(value)
				intent[key] = append(intent[key], value)
			}
		}
	}
	return intent
}

// Intent is durable before any LDAP mutation. If an API patch fails, no directory
// write is attempted, so a crash cannot turn a partially applied value into foreign data.
func (e *ldapExternal) prepareOwnership(ctx context.Context, entry *entryapi.Entry, creating bool) error {
	if !entry.GetDeletionTimestamp().IsZero() || !e.canClaim(entry, creating) {
		return nil
	}
	intent := mergeSharedIntent(cloneOwnership(entry.Status.OwnedAttributeValues), e.shared)
	if err := checkOwnershipLimit(intent); err != nil {
		// Verified absence can release old intent even when unrelated desired values
		// are not yet current; never discard a present unconfirmed claim for quota.
		compacted, compactErr := e.compactConfirmedIntent(ctx, e.actualDN(entry), entry)
		if compactErr != nil {
			return compactErr
		}
		intent = mergeSharedIntent(compacted, e.shared)
		if err := checkOwnershipLimit(intent); err != nil {
			return err
		}
	}
	if reflect.DeepEqual(entry.Status.OwnedAttributeValues, intent) {
		return nil
	}
	if e.kube == nil {
		return fmt.Errorf("subset ownership requires a Kubernetes status client")
	}
	previous := entry.DeepCopy()
	entry.Status.OwnedAttributeValues = intent
	if err := e.kube.Status().Patch(ctx, entry, client.MergeFromWithOptions(previous, client.MergeFromWithOptimisticLock{})); err != nil {
		entry.Status.OwnedAttributeValues = previous.Status.OwnedAttributeValues
		return fmt.Errorf("persist subset ownership intent: %w", err)
	}
	return nil
}
func (e *ldapExternal) compactOwnership(entry *entryapi.Entry) {
	policy := managed.NewManagementPoliciesResolver(true, entry.GetManagementPolicies())
	if policy.ShouldUpdate() {
		entry.Status.OwnedAttributeValues = cloneOwnership(e.shared)
	}
}

// retiredValues returns only previously claimed stored values that no current
// minimum protects. RFC3876 supplies server equality for aliases and normalized DNs.
func (e *ldapExternal) retiredValues(ctx context.Context, observed *ldap.Entry, entry *entryapi.Entry) (map[string][]string, error) {
	retired := map[string][]string{}
	for key, claims := range entry.Status.OwnedAttributeValues {
		if e.ownsExactly(key) {
			continue
		}
		wanted := e.shared[key]
		declared := sets.New(wanted...)
		var candidates []string
		for _, claim := range claims {
			if !declared.Has(claim) {
				candidates = append(candidates, claim)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		values, err := e.retireAttribute(ctx, observed, key, candidates, wanted)
		if err != nil {
			return nil, err
		}
		if len(values) != 0 {
			retired[key] = values
		}
	}
	return retired, nil
}

func (e *ldapExternal) retireAttribute(ctx context.Context, observed *ldap.Entry, key string, candidates, wanted []string) ([]string, error) {
	// Different values that coexist on one LDAP attribute are distinct under
	// its equality rule. Only compare spellings from this single observation.
	snapshot := sets.New(attributeValues(observed, key)...)
	stored := sets.New[string]()
	for batch := range slices.Chunk(candidates, matchBatchSize) {
		matches, err := e.matchedValues(ctx, observed.DN, key, batch, nil)
		if err != nil {
			return nil, err
		}
		for _, value := range matches {
			if !snapshot.Has(value) {
				return nil, errRetirementChanged
			}
			stored.Insert(value)
		}
		for _, claim := range batch {
			if snapshot.Has(claim) && !slices.Contains(matches, claim) {
				return nil, errRetirementChanged
			}
		}
	}

	var unmatchedWanted []string
	for _, value := range wanted {
		if snapshot.Has(value) {
			stored.Delete(value)
		} else {
			unmatchedWanted = append(unmatchedWanted, value)
		}
	}
	if len(unmatchedWanted) == 0 {
		return sets.List(stored), nil
	}
	// Keep each candidate present during the protected-value lookup. Otherwise
	// temporary absence could make an equivalent desired assertion look unrelated.
	for present := range slices.Chunk(stored.UnsortedList(), matchBatchSize) {
		for batch := range slices.Chunk(unmatchedWanted, matchBatchSize) {
			matches, err := e.matchedValues(ctx, observed.DN, key, batch, present)
			if err != nil {
				return nil, err
			}
			for _, value := range matches {
				if !snapshot.Has(value) {
					return nil, errRetirementChanged
				}
				stored.Delete(value)
			}
		}
	}
	return sets.List(stored), nil
}

func (e *ldapExternal) compactConfirmedIntent(ctx context.Context, dn string, entry *entryapi.Entry) (map[string][]string, error) {
	var kept map[string][]string
	for key, claims := range entry.Status.OwnedAttributeValues {
		current := sets.New(e.shared[key]...)
		for _, claim := range claims {
			retain := current.Has(claim)
			if !retain {
				matching, err := e.matchedValues(ctx, dn, key, []string{claim}, nil)
				if err != nil && !errors.Is(err, errRetirementEntryAbsent) {
					return nil, err
				}
				retain = len(matching) > 0
			}
			if retain {
				if kept == nil {
					kept = map[string][]string{}
				}
				kept[key] = append(kept[key], claim)
			}
		}
	}
	return kept, nil
}
