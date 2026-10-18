// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Only the OID/NAME header of the server's valid RFC4512 AttributeTypeDescription
// is needed. Anchoring before DESC avoids treating quoted descriptions as aliases.
var attributeTypeHeader = regexp.MustCompile(`(?i)^\(\s*([0-9]+(?:\.[0-9]+)+)(?:\s+NAME\s+(?:'([A-Za-z][A-Za-z0-9-]*)'|\(\s*((?:'[A-Za-z][A-Za-z0-9-]*'\s*)+)\)))?`)
var schemaName = regexp.MustCompile(`'([A-Za-z][A-Za-z0-9-]*)'`)

type attributeSchema map[string]string

func parseAttributeSchema(definitions []string) (attributeSchema, error) {
	out := attributeSchema{}
	for _, definition := range definitions {
		header := attributeTypeHeader.FindStringSubmatch(strings.TrimSpace(definition))
		if header == nil {
			return nil, fmt.Errorf("directory published an invalid attribute schema header")
		}
		oid := header[1]
		out[oid] = oid
		if header[2] != "" {
			out[strings.ToLower(header[2])] = oid
		}
		for _, name := range schemaName.FindAllStringSubmatch(header[3], -1) {
			out[strings.ToLower(name[1])] = oid
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("directory did not publish readable attributeTypes")
	}
	return out, nil
}
func (s attributeSchema) key(description string) (string, error) {
	parts := strings.Split(canonicalAttributeName(description), ";")
	if s == nil {
		return strings.Join(parts, ";"), nil
	}
	oid, ok := s[parts[0]]
	if !ok {
		return "", fmt.Errorf("attribute %s is not advertised by the directory schema", description)
	}
	parts[0] = oid
	return strings.Join(parts, ";"), nil
}
func (e *ldapExternal) canonicalAttributes(source map[string][]string) (map[string][]string, error) {
	out := map[string][]string{}
	for name, values := range source {
		key, err := e.schema.key(name)
		if err != nil {
			return nil, err
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("attribute %s aliases another declared attribute", name)
		}
		out[key] = values
	}
	return out, nil
}
func (e *ldapExternal) loadSchema(ctx context.Context, dn string) error {
	parsed, err := parseDN(dn)
	if err != nil {
		return err
	}
	schemaDN := ""
	// New entries inherit their nearest existing ancestor's subschema.
	for offset := 0; offset <= len(parsed.RDNs); offset++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		base := (&ldap.DN{RDNs: parsed.RDNs[offset:]}).String()
		result, err := e.conn.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"subschemaSubentry"}, nil))
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			continue
		}
		if err != nil {
			return e.operationError(ctx, "discover subschema", err)
		}
		if len(result.Entries) == 1 {
			schemaDN = result.Entries[0].GetEqualFoldAttributeValue("subschemaSubentry")
		}
		if schemaDN != "" {
			break
		}
	}
	if schemaDN == "" {
		return fmt.Errorf("directory did not publish a readable subschemaSubentry")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := e.conn.Search(ldap.NewSearchRequest(schemaDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=subschema)", []string{"attributeTypes"}, nil))
	if err != nil {
		return e.operationError(ctx, "read attribute schema", err)
	}
	if len(result.Entries) != 1 {
		return fmt.Errorf("directory subschema search did not return exactly one entry")
	}
	e.schema, err = parseAttributeSchema(result.Entries[0].GetEqualFoldAttributeValues("attributeTypes"))
	if err != nil {
		return err
	}
	e.desired, err = e.canonicalAttributes(e.desired)
	if err != nil {
		return err
	}
	e.shared, err = e.canonicalAttributes(e.shared)
	if err != nil {
		return err
	}
	for key := range e.desired {
		if _, ok := e.shared[key]; ok {
			return fmt.Errorf("exact-owned attribute %s aliases a shared attribute", key)
		}
	}
	parsedDN, err := parseDN(dn)
	if err != nil {
		return err
	}
	for _, naming := range parsedDN.RDNs[0].Attributes {
		key, err := e.schema.key(naming.Type)
		if err != nil {
			return err
		}
		if values, owned := e.desired[key]; owned && !contains(values, naming.Value) {
			return fmt.Errorf("exact-owned naming attribute %s must contain the DN naming value", key)
		}
		for description := range e.secretVersions {
			secretKey, err := e.schema.key(description)
			if err != nil {
				return err
			}
			if secretKey == key {
				return fmt.Errorf("DN naming attributes cannot use Secret references")
			}
		}
	}
	return nil
}
