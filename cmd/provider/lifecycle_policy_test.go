// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	configapi "github.com/soupglasses/provider-ldap/apis/namespaced/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSchemaCanonicalRDNPolicies(t *testing.T) {
	for _, tc := range []struct {
		name            string
		desired, shared map[string][]string
		versions        map[string]string
		reason          string
	}{
		{name: "owned alias drops RDN", desired: map[string][]string{"commonName": {"other"}}, reason: "DN naming value"},
		{name: "secret alias of RDN", desired: map[string][]string{"2.5.4.3": {"Group"}}, versions: map[string]string{"2.5.4.3": "17"}, reason: "Secret references"},
		{name: "exact and shared aliases", desired: map[string][]string{"cn": {"Group"}}, shared: map[string][]string{"2.5.4.3": {"Other"}}, reason: "aliases a shared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &fixtureLDAP{searchFn: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
				attributes := map[string][]string{"subschemaSubentry": {"cn=subschema"}}
				if request.BaseDN == "cn=subschema" {
					attributes = map[string][]string{"attributeTypes": {"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )"}}
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(request.BaseDN, attributes)}}, nil
			}}
			external := &ldapExternal{conn: conn, desired: tc.desired, shared: tc.shared, secretVersions: tc.versions}
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
	port := listener.Addr().(*net.TCPAddr).Port
	pc := &configapi.ProviderConfig{ObjectMeta: metav1.ObjectMeta{Namespace: "media", Name: "fixture"}, Spec: configapi.ProviderConfigSpec{Credentials: credentials("media")}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "media", Name: "credentials"}, Data: map[string][]byte{
		"connection.yaml": fmt.Appendf(nil, "host: 127.0.0.1\nport: %d\nbindDN: cn=admin\npassword: synthetic\ntls: false\n", port),
	}}
	connector := &ldapConnector{kube: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(pc, secret).Build()}
	entry := testEntry("ProviderConfig", "fixture")
	// A deleting Entry skips schema discovery. Its first search belongs to Observe.
	now := metav1.Now()
	entry.SetDeletionTimestamp(&now)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	external, err := connector.Connect(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	defer external.Disconnect(context.Background())
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
