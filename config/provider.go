// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: MIT

package config

import (
	_ "embed"

	ujconfig "github.com/crossplane/upjet/v2/pkg/config"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	ldapprovider "github.com/l-with/terraform-provider-ldap/ldap"
)

//go:embed schema.json
var providerSchema []byte

func SDKProvider() *schema.Provider {
	p := ldapprovider.Provider()
	p.ResourcesMap["ldap_entry"].Schema["data_json"].Sensitive = true
	p.ResourcesMap["ldap_entry"].Schema["data_json_create_defaults"].Sensitive = true
	p.Schema["bind_password"].Sensitive = true
	return p
}

func WithSchema(raw []byte, group string) *ujconfig.Provider {
	p := ujconfig.NewProvider(raw, "ldap", "github.com/soupglasses/provider-ldap", []byte("name: l-with/ldap\nresources: {}\n"), ujconfig.WithRootGroup(group), ujconfig.WithFeaturesPackage("internal/features"), ujconfig.WithIncludeList([]string{}), ujconfig.WithTerraformPluginSDKIncludeList([]string{"ldap_entry$"}), ujconfig.WithTerraformProvider(SDKProvider()))
	p.BasePackages = ujconfig.BasePackages{}
	p.AddResourceConfigurator("ldap_entry", func(r *ujconfig.Resource) {
		r.Kind = "Entry"
		r.ShortGroup = ""
		r.UseAsync = false
		r.ExternalName = ujconfig.ParameterAsIdentifier("dn")
	})
	p.ConfigureResources()
	return p
}

func Namespaced() *ujconfig.Provider { return WithSchema(providerSchema, "ldap.ops.finnes.dev") }
