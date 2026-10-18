// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: MIT

package main

import (
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	configapi "github.com/soupglasses/provider-ldap/apis/namespaced/v1beta1"
)

var (
	_ resource.ProviderConfig           = &configapi.ProviderConfig{}
	_ resource.ProviderConfig           = &configapi.ClusterProviderConfig{}
	_ resource.TypedProviderConfigUsage = &configapi.ProviderConfigUsage{}
	_ resource.ProviderConfigUsageList  = &configapi.ProviderConfigUsageList{}
)
