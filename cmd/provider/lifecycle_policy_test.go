// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestSchemaCanonicalRDNPolicies(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		desired, additive, absent map[string][]string
		versions                  map[string]string
		reason                    string
	}{
		{name: "owned alias drops RDN", desired: map[string][]string{"commonName": {"other"}}, reason: "DN naming value"},
		{name: "secret alias of RDN", desired: map[string][]string{"2.5.4.3": {"Group"}}, versions: map[string]string{"2.5.4.3": "17"}, reason: "Secret references"},
		{name: "absent alias of RDN", absent: map[string][]string{"2.5.4.3": {"Group"}}, reason: "declared absent"},
		{name: "exact and additive aliases", desired: map[string][]string{"cn": {"Group"}}, additive: map[string][]string{"2.5.4.3": {"Other"}}, reason: "aliases an additive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &fixtureLDAP{searchFn: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
				attributes := map[string][]string{"subschemaSubentry": {"cn=subschema"}}
				if request.BaseDN == "cn=subschema" {
					attributes = map[string][]string{"attributeTypes": {"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )"}}
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(request.BaseDN, attributes)}}, nil
			}}
			external := &ldapExternal{conn: conn, desired: tc.desired, additive: tc.additive, absent: tc.absent, secretVersions: tc.versions}
			if err := external.loadSchema(context.Background(), "cn=Group,dc=example"); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("invalid RDN ownership accepted: %v", err)
			}
		})
	}
}
func TestUUIDSurvivesSchemaCanonicalization(t *testing.T) {
	schema, err := parseAttributeSchema([]string{"( 1.3.6.1.1.16.4 NAME 'entryUUID' EQUALITY UUIDMatch )"})
	if err != nil {
		t.Fatal(err)
	}
	conn := &fixtureLDAP{entry: ldap.NewEntry("cn=group,dc=example", map[string][]string{"entryUUID": {"stable-id"}})}
	external := &ldapExternal{conn: conn, schema: schema}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = conn.entry.DN
	if _, err := external.Observe(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if entry.Status.AtProvider.UUID != "stable-id" {
		t.Fatal("canonicalization erased LDAP UUID")
	}
}
func matchedValueFixture(t *testing.T, conn *fixtureLDAP) {
	t.Helper()
	conn.searchFn = func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if len(request.Controls) == 0 {
			return &ldap.SearchResult{Entries: []*ldap.Entry{conn.entry}}, nil
		}
		control := request.Controls[0].(*ldap.ControlString)
		packet, err := ber.DecodePacketErr([]byte(control.ControlValue))
		if err != nil {
			t.Fatal(err)
		}
		assertion := packet.Children[0]
		key := string(assertion.Children[0].Data.Bytes())
		value := string(assertion.Children[1].Data.Bytes())
		result := ldap.NewEntry(conn.entry.DN, map[string][]string{})
		for _, current := range attributeValues(conn.entry, key) {
			if strings.EqualFold(current, value) {
				result.Attributes = append(result.Attributes, &ldap.EntryAttribute{Name: key, Values: []string{current}})
			}
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{result}}, nil
	}
}
func TestAtomicSentinelReplacementPreservesHumanValues(t *testing.T) {
	dn := "cn=group,dc=example"
	conn := &fixtureLDAP{entry: ldap.NewEntry(dn, map[string][]string{"member": {"old-sentinel", "human"}, "description": {"old"}})}
	matchedValueFixture(t, conn)
	conn.beforeModify = func() {
		for _, attr := range conn.entry.Attributes {
			if attr.Name == "member" {
				attr.Values = append(attr.Values, "concurrent-human")
			}
		}
	}
	external := &ldapExternal{conn: conn, desired: map[string][]string{"description": {"new"}}, additive: map[string][]string{"member": {"new-sentinel"}}, absent: map[string][]string{"member": {"old-sentinel"}}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = dn
	if _, err := external.Update(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	values := attributeValues(conn.entry, "member")
	if contains(values, "old-sentinel") || !contains(values, "new-sentinel") || !contains(values, "human") || !contains(values, "concurrent-human") {
		t.Fatalf("atomic replacement lost unmanaged values: %v", values)
	}
	if len(conn.changes) != 1 || len(conn.changes[0].Changes) != 3 {
		t.Fatal("present/exact/absent policies were not one atomic Modify")
	}
}
func TestUnstoredEquivalentPoliciesNeverDeleteAfterDetection(t *testing.T) {
	dn := "uid=service,dc=example"
	conn := &fixtureLDAP{entry: ldap.NewEntry(dn, map[string][]string{"cn": {"Bob"}})}
	matchedValueFixture(t, conn)
	external := &ldapExternal{conn: conn, additive: map[string][]string{"cn": {"Alice"}}, absent: map[string][]string{"cn": {"alice"}}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = dn
	// A directory can compare these literals only after a matching value exists.
	if _, err := external.Update(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := external.Observe(context.Background(), entry); err == nil || !strings.Contains(err.Error(), "directory-equivalent") {
			t.Fatalf("equivalent policies not rejected after observation: %v", err)
		}
		if _, err := external.Update(context.Background(), entry); err == nil {
			t.Fatal("conflicting absence policy was applied")
		}
	}
	if len(conn.changes) != 1 || !contains(attributeValues(conn.entry, "cn"), "Alice") || !contains(attributeValues(conn.entry, "cn"), "Bob") {
		t.Fatal("invalid policy deleted or oscillated values after detection")
	}
}
func TestCancellationClosesBoundLDAPConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	searching := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		socket, err := listener.Accept()
		if err != nil {
			return
		}
		defer socket.Close()
		_, err = ber.ReadPacket(socket)
		if err != nil {
			return
		}
		_, err = socket.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
		if err != nil {
			return
		}
		if _, err := ber.ReadPacket(socket); err != nil {
			return
		}
		close(searching)
		data := make([]byte, 1)
		_, _ = socket.Read(data)
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	tls := false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := dialLDAP(ctx, ConnectionDocument{Host: "127.0.0.1", Port: number, BindDN: "cn=admin", Password: "synthetic", TLS: &tls})
	if err != nil {
		t.Fatal(err)
	}
	external := &ldapExternal{conn: conn}
	external.cancelOnContext(ctx)
	defer external.Disconnect(context.Background())
	entry := testEntry("ProviderConfig", "fixture")
	done := make(chan error, 1)
	go func() { _, err := external.Observe(ctx, entry); done <- err }()
	select {
	case <-searching:
	case <-time.After(2 * time.Second):
		t.Fatal("directory search was not received")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked read did not cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bound read ignored cancellation")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("bound LDAP socket leaked after cancellation")
	}
}
