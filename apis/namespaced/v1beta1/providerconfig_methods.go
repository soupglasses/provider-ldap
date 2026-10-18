// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package v1beta1

import (
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
)

func (p *ProviderConfig) GetCondition(t xpv2.ConditionType) xpv2.Condition {
	return p.Status.GetCondition(t)
}

func (p *ProviderConfig) SetConditions(c ...xpv2.Condition) {
	p.Status.SetConditions(c...)
}

func (p *ProviderConfig) GetUsers() int64 {
	return p.Status.Users
}

func (p *ProviderConfig) SetUsers(n int64) {
	p.Status.Users = n
}

func (p *ClusterProviderConfig) GetCondition(t xpv2.ConditionType) xpv2.Condition {
	return p.Status.GetCondition(t)
}

func (p *ClusterProviderConfig) SetConditions(c ...xpv2.Condition) {
	p.Status.SetConditions(c...)
}

func (p *ClusterProviderConfig) GetUsers() int64 {
	return p.Status.Users
}

func (p *ClusterProviderConfig) SetUsers(n int64) {
	p.Status.Users = n
}

func (p *ProviderConfigUsage) GetProviderConfigReference() xpv2.ProviderConfigReference {
	return p.ProviderConfigReference
}
func (p *ProviderConfigUsage) SetProviderConfigReference(v xpv2.ProviderConfigReference) {
	p.ProviderConfigReference = v
}
func (p *ProviderConfigUsage) GetResourceReference() xpv2.TypedReference  { return p.ResourceReference }
func (p *ProviderConfigUsage) SetResourceReference(v xpv2.TypedReference) { p.ResourceReference = v }
func (p *ProviderConfigUsageList) GetItems() []resource.ProviderConfigUsage {
	out := make([]resource.ProviderConfigUsage, len(p.Items))
	for i := range p.Items {
		out[i] = &p.Items[i]
	}
	return out
}
