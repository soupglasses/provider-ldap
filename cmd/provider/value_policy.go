// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const matchedValuesControlOID = "1.2.826.0.1.3344810.2.3"

// A new observation is needed when a writer changes the values used to decide ownership.
var errRetirementChanged = errors.New("LDAP attribute changed while planning shared value retirement")
var errRetirementEntryAbsent = fmt.Errorf("%w: entry is absent", errRetirementChanged)

const matchBatchSize = 64

// RFC3876 lets the directory decide equality. A guarded search matches only
// while every candidate is present, including under an equivalent spelling.
func (e *ldapExternal) matchedValues(ctx context.Context, dn, key string, assertions, required []string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sequence := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ValuesReturnFilter")
	for _, value := range assertions {
		filter, err := ldap.CompileFilter(fmt.Sprintf("(%s=%s)", key, ldap.EscapeFilter(value)))
		if err != nil {
			return nil, fmt.Errorf("cannot encode attribute value policy filter")
		}
		sequence.AppendChild(filter)
	}
	control := ldap.NewControlString(matchedValuesControlOID, true, string(sequence.Bytes()))
	entryFilter := "(objectClass=*)"
	bound := e.identity != nil && e.identity.uuid != ""
	if len(required) > 0 || bound {
		var guard strings.Builder
		guard.WriteString("(&")
		if bound {
			fmt.Fprintf(&guard, "(entryUUID=%s)", ldap.EscapeFilter(e.identity.uuid))
		}
		for _, value := range required {
			fmt.Fprintf(&guard, "(%s=%s)", key, ldap.EscapeFilter(value))
		}
		guard.WriteByte(')')
		entryFilter = guard.String()
	}
	result, err := e.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, entryFilter, []string{key}, []ldap.Control{control}))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailableCriticalExtension) {
		return nil, fmt.Errorf("selective attribute retirement requires the LDAP RFC3876 matched-values control")
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, errRetirementEntryAbsent
	}
	if err != nil {
		return nil, e.operationError(ctx, "validate attribute value policies", err)
	}
	if len(result.Entries) == 0 {
		return nil, errRetirementChanged
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
