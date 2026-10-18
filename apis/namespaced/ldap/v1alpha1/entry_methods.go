// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
)

var _ resource.ModernManaged = &Entry{}

func (e *Entry) GetCondition(t xpv2.ConditionType) xpv2.Condition { return e.Status.GetCondition(t) }
func (e *Entry) SetConditions(c ...xpv2.Condition)                { e.Status.SetConditions(c...) }
func (e *Entry) GetManagementPolicies() xpv2.ManagementPolicies   { return e.Spec.ManagementPolicies }
func (e *Entry) SetManagementPolicies(v xpv2.ManagementPolicies)  { e.Spec.ManagementPolicies = v }
func (e *Entry) GetProviderConfigReference() *xpv2.ProviderConfigReference {
	return e.Spec.ProviderConfigReference
}
func (e *Entry) SetProviderConfigReference(v *xpv2.ProviderConfigReference) {
	e.Spec.ProviderConfigReference = v
}
func (e *Entry) GetWriteConnectionSecretToReference() *xpv2.LocalSecretReference {
	return e.Spec.WriteConnectionSecretToReference
}
func (e *Entry) SetWriteConnectionSecretToReference(v *xpv2.LocalSecretReference) {
	e.Spec.WriteConnectionSecretToReference = v
}
func (e *EntryList) GetItems() []resource.Managed {
	out := make([]resource.Managed, len(e.Items))
	for i := range e.Items {
		out[i] = &e.Items[i]
	}
	return out
}
