// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"reflect"

	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	maxOwnedAttributes = 256
	maxOwnedValues     = 4096
	maxOwnedBytes      = 256 * 1024
)

func (e *ldapExternal) isSubset(key string) bool {
	return e.ownership[key] == entryapi.AttributeOwnershipSubset
}
func (e *ldapExternal) ownsExactly(key string) bool {
	_, declared := e.desired[key]
	return declared && !e.isSubset(key)
}
func (e *ldapExternal) subsetDesired() map[string][]string {
	var out map[string][]string
	for key, values := range e.desired {
		if e.isSubset(key) && len(values) > 0 {
			if out == nil {
				out = map[string][]string{}
			}
			out[key] = append([]string{}, values...)
		}
	}
	return out
}
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

// Intent is durable before any LDAP mutation. If an API patch fails, no directory
// write is attempted, so a crash cannot turn a partially applied value into foreign data.
func (e *ldapExternal) prepareOwnership(ctx context.Context, entry *entryapi.Entry, creating bool) error {
	if !entry.GetDeletionTimestamp().IsZero() || !e.canClaim(entry, creating) {
		return nil
	}
	intent := cloneOwnership(entry.Status.OwnedAttributeValues)
	for key, values := range e.subsetDesired() {
		if intent == nil {
			intent = map[string][]string{}
		}
		for _, value := range values {
			if !contains(intent[key], value) {
				intent[key] = append(intent[key], value)
			}
		}
	}
	if err := checkOwnershipLimit(intent); err != nil {
		// Verified absence can release old intent even when unrelated desired values
		// are not yet current; never discard a present unconfirmed claim for quota.
		compacted, compactErr := e.compactConfirmedIntent(ctx, e.actualDN(entry), entry)
		if compactErr != nil {
			return compactErr
		}
		intent = compacted
		for key, values := range e.subsetDesired() {
			if intent == nil {
				intent = map[string][]string{}
			}
			for _, value := range values {
				if !contains(intent[key], value) {
					intent[key] = append(intent[key], value)
				}
			}
		}
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
		entry.Status.OwnedAttributeValues = e.subsetDesired()
	}
}

// retiredValues returns only previously claimed stored values that no current
// minimum protects. RFC3876 supplies server equality for aliases and normalized DNs.
func (e *ldapExternal) retiredValues(ctx context.Context, dn string, entry *entryapi.Entry) (map[string][]string, error) {
	retired := map[string][]string{}
	for key, claims := range entry.Status.OwnedAttributeValues {
		if e.ownsExactly(key) {
			continue
		}
		wanted := append([]string{}, e.additive[key]...)
		if e.isSubset(key) {
			wanted = append(wanted, e.desired[key]...)
		}
		candidates := []string{}
		for _, claim := range claims {
			if !contains(wanted, claim) {
				candidates = append(candidates, claim)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		protected := map[string]bool{}
		for _, value := range wanted {
			matching, err := e.matchedValues(ctx, dn, key, value)
			if err != nil {
				return nil, err
			}
			for _, stored := range matching {
				protected[stored] = true
			}
		}
		for _, claim := range candidates {
			matching, err := e.matchedValues(ctx, dn, key, claim)
			if err != nil {
				return nil, err
			}
			for _, stored := range matching {
				if !protected[stored] && !contains(retired[key], stored) {
					retired[key] = append(retired[key], stored)
				}
			}
		}
	}
	return retired, nil
}

func (e *ldapExternal) compactConfirmedIntent(ctx context.Context, dn string, entry *entryapi.Entry) (map[string][]string, error) {
	current := e.subsetDesired()
	var kept map[string][]string
	for key, claims := range entry.Status.OwnedAttributeValues {
		for _, claim := range claims {
			retain := contains(current[key], claim)
			if !retain {
				matching, err := e.matchedValues(ctx, dn, key, claim)
				if err != nil {
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
