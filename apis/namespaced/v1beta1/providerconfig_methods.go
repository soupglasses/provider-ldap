// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: MIT

package v1beta1

import (
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
