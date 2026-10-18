// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const matchedValuesControlOID = "1.2.826.0.1.3344810.2.3"

// RFC3876 lets the server decide equality without reproducing its matching rules.
// It is required only when the same attribute has present and absent value policies.
func (e *ldapExternal) matchedValues(ctx context.Context, dn, key, value string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filter, err := ldap.CompileFilter(fmt.Sprintf("(%s=%s)", key, ldap.EscapeFilter(value)))
	if err != nil {
		return nil, fmt.Errorf("cannot encode attribute value policy filter")
	}
	sequence := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ValuesReturnFilter")
	sequence.AppendChild(filter)
	control := ldap.NewControlString(matchedValuesControlOID, true, string(sequence.Bytes()))
	result, err := e.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{key}, []ldap.Control{control}))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailableCriticalExtension) {
		return nil, fmt.Errorf("mixed additive and absent policies require the LDAP RFC3876 matched-values control")
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, nil
	}
	if err != nil {
		return nil, e.operationError(ctx, "validate attribute value policies", err)
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("attribute value policy search did not return exactly one entry")
	}
	var values []string
	for _, attr := range result.Entries[0].Attributes {
		canonical, err := e.schema.key(attr.Name)
		if err != nil {
			return nil, err
		}
		if canonical == key {
			values = append(values, attr.Values...)
		}
	}
	return values, nil
}
func (e *ldapExternal) validateValuePolicies(ctx context.Context, dn string) error {
	for key, present := range e.additive {
		absent := e.absent[key]
		if len(present) == 0 || len(absent) == 0 {
			continue
		}
		seen := map[string]bool{}
		for _, value := range present {
			matches, err := e.matchedValues(ctx, dn, key, value)
			if err != nil {
				return err
			}
			for _, matched := range matches {
				seen[matched] = true
			}
		}
		for _, value := range absent {
			matches, err := e.matchedValues(ctx, dn, key, value)
			if err != nil {
				return err
			}
			for _, matched := range matches {
				if seen[matched] {
					return fmt.Errorf("attribute %s declares directory-equivalent values both present and absent", key)
				}
			}
		}
	}
	return nil
}
