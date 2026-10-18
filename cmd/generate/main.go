// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/crossplane/upjet/v2/pkg/pipeline"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	localconfig "github.com/soupglasses/provider-ldap/config"
)

func attributes(in []*tfprotov5.SchemaAttribute) map[string]any {
	out := map[string]any{}
	for _, a := range in {
		raw, err := a.Type.MarshalJSON()
		if err != nil {
			panic(err)
		}
		out[a.Name] = map[string]any{"description": a.Description, "required": a.Required, "optional": a.Optional, "computed": a.Computed, "sensitive": a.Sensitive, "type": json.RawMessage(raw)}
	}
	return out
}

func main() {
	provider := localconfig.SDKProvider()
	response, err := provider.GRPCProvider().GetProviderSchema(context.Background(), &tfprotov5.GetProviderSchemaRequest{})
	if err != nil {
		panic(err)
	}
	if len(response.Diagnostics) != 0 {
		panic(fmt.Sprint(response.Diagnostics))
	}
	resources := map[string]any{}
	for name, schema := range response.ResourceSchemas {
		if len(schema.Block.BlockTypes) != 0 {
			panic("unexpected nested blocks: " + name)
		}
		resources[name] = map[string]any{"version": schema.Version, "block": map[string]any{"attributes": attributes(schema.Block.Attributes)}}
	}
	doc := map[string]any{"format_version": "1.0", "provider_schemas": map[string]any{"registry.terraform.io/l-with/ldap": map[string]any{"resource_schemas": resources}}}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile("config/schema.json", raw, 0600); err != nil {
		panic(err)
	}
	root, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	pipeline.Run(localconfig.WithSchema(raw, "ldap.cluster.ops.finnes.dev"), localconfig.WithSchema(raw, "ldap.ops.finnes.dev"), root)
}
