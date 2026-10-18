// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	"github.com/go-ldap/ldap/v3"
)

func TestSchemaAliasesConvergeAndRejectDuplicateOwnership(t *testing.T) {
	schema, err := parseAttributeSchema([]string{
		"( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'NAME is not metadata here' SUP name )",
		"( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch )",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, description := range []string{"cn", "commonName", "2.5.4.3", "CN"} {
		key, err := schema.key(description)
		if err != nil || key != "2.5.4.3" {
			t.Fatalf("alias %q not canonicalized: %s %v", description, key, err)
		}
	}
	conn := &fixtureLDAP{entry: ldap.NewEntry("uid=service,dc=example", map[string][]string{"cn": {"Service"}})}
	external := &ldapExternal{conn: conn, schema: schema, desired: map[string][]string{"2.5.4.3": {"Service"}}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = conn.entry.DN
	observation, err := external.Observe(context.Background(), entry)
	if err != nil || !observation.ResourceUpToDate {
		t.Fatalf("OID-owned attribute failed convergence: %v", err)
	}
	if _, err := external.canonicalAttributes(map[string][]string{"cn": {"one"}, "2.5.4.3": {"two"}}); err == nil {
		t.Fatal("duplicate alias ownership accepted")
	}
	if _, err := schema.key("notPublished"); err == nil {
		t.Fatal("unknown schema attribute accepted")
	}
}
func TestVerifiedObservationAcknowledgesGenerationAndSecretVersion(t *testing.T) {
	conn := &fixtureLDAP{entry: ldap.NewEntry("uid=service,dc=example", map[string][]string{"userPassword": {"old"}})}
	external := &ldapExternal{conn: conn, desired: map[string][]string{"userPassword": {"new"}}, secretVersions: map[string]string{"userpassword": "17"}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = conn.entry.DN
	entry.Generation = 2
	observation, err := external.Observe(context.Background(), entry)
	if err != nil || observation.ResourceUpToDate {
		t.Fatalf("drift not detected: %v", err)
	}
	if entry.Status.AtProvider.ObservedGeneration != 0 || len(entry.Status.AtProvider.ObservedSecretVersions) != 0 {
		t.Fatal("unverified state acknowledged")
	}
	if _, err := external.Update(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if entry.Status.AtProvider.ObservedGeneration != 0 {
		t.Fatal("successful write acknowledged before verification")
	}
	observation, err = external.Observe(context.Background(), entry)
	if err != nil || !observation.ResourceUpToDate || entry.Status.AtProvider.ObservedGeneration != 2 || entry.Status.AtProvider.ObservedSecretVersions["userpassword"] != "17" {
		t.Fatalf("verified metadata not acknowledged: %v", err)
	}
}
func TestCanceledOperationsDoNotIssueDirectoryWrites(t *testing.T) {
	conn := &fixtureLDAP{entry: ldap.NewEntry("cn=group,dc=example", map[string][]string{})}
	external := &ldapExternal{conn: conn, desired: map[string][]string{"description": {"managed"}}}
	entry := testEntry("ProviderConfig", "fixture")
	entry.Spec.ForProvider.DN = conn.entry.DN
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, operation := range []func(context.Context, resource.Managed) error{
		func(ctx context.Context, mg resource.Managed) error { _, err := external.Create(ctx, mg); return err },
		func(ctx context.Context, mg resource.Managed) error { _, err := external.Update(ctx, mg); return err },
		func(ctx context.Context, mg resource.Managed) error { _, err := external.Delete(ctx, mg); return err },
	} {
		if err := operation(ctx, entry); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled operation proceeded: %v", err)
		}
	}
	if len(conn.changes) > 0 || conn.created != nil || conn.entry == nil {
		t.Fatal("canceled operation changed directory")
	}
}
func TestBindCancellationClosesBlockedSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data := make([]byte, 4096)
		if _, err := conn.Read(data); err != nil {
			return
		}
		close(received)
		_, _ = conn.Read(data)
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number := 0
	fmt.Sscanf(port, "%d", &number)
	enabled := false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := dialLDAP(ctx, ConnectionDocument{Host: "127.0.0.1", Port: number, BindDN: "cn=admin", Password: "synthetic", TLS: &enabled})
		done <- err
	}()
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("bind was not received")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("bind did not report cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bind ignored cancellation")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled bind retained its socket")
	}
}
