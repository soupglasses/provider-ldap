// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"k8s.io/apimachinery/pkg/util/wait"
)

// TestLDAPState observes the external service; Chainsaw owns Kubernetes lifecycle assertions.
func TestLDAPState(t *testing.T) {
	dn := os.Getenv("LDAP_EXPECT_DN")
	if dn == "" {
		t.Skip("requires the LDAP end-to-end fixture")
	}
	want := map[string][]string{}
	if raw := os.Getenv("LDAP_EXPECT_JSON"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &want); err != nil {
			t.Fatal(err)
		}
	}
	conn, err := ldap.DialURL("ldap://127.0.0.1:1389")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.Bind("cn=admin,dc=example,dc=test", "disposable-fixture-password"); err != nil {
		t.Fatal(err)
	}
	check := func() error {
		result, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"*"}, nil))
		if os.Getenv("LDAP_EXPECT_ABSENT") == "true" {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				return nil
			}
			return fmt.Errorf("entry still exists or could not be checked: %v", err)
		}
		if err != nil {
			return err
		}
		if len(result.Entries) != 1 {
			return fmt.Errorf("expected one LDAP entry, got %d", len(result.Entries))
		}
		for attribute, expected := range want {
			got := slices.Clone(result.Entries[0].GetAttributeValues(attribute))
			expected = slices.Clone(expected)
			slices.Sort(got)
			slices.Sort(expected)
			if !slices.Equal(got, expected) {
				return fmt.Errorf("attribute %s did not match", attribute)
			}
		}
		return nil
	}
	var last error
	if err := wait.PollUntilContextTimeout(context.Background(), 250*time.Millisecond, 45*time.Second, true, func(context.Context) (bool, error) {
		last = check()
		return last == nil, nil
	}); err != nil {
		t.Fatalf("external LDAP state did not converge: %v: %v", err, last)
	}
	if value := os.Getenv("LDAP_STABLE_FOR"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), duration)
		defer cancel()
		err = wait.PollUntilContextCancel(ctx, 250*time.Millisecond, true, func(context.Context) (bool, error) {
			return false, check()
		})
		if ctx.Err() == nil {
			t.Fatalf("external LDAP state changed during observation: %v", err)
		}
	}
}

func TestLDAPBind(t *testing.T) {
	password := os.Getenv("LDAP_BIND_PASSWORD")
	if password == "" {
		t.Skip("requires generated fixture credentials")
	}
	var last error
	err := wait.PollUntilContextTimeout(context.Background(), 250*time.Millisecond, 45*time.Second, true, func(context.Context) (bool, error) {
		conn, err := ldap.DialURL("ldap://127.0.0.1:1389")
		if err != nil {
			last = err
			return false, nil
		}
		defer conn.Close()
		last = conn.Bind("uid=generated,ou=users,dc=example,dc=test", password)
		return last == nil, nil
	})
	if err != nil {
		t.Fatalf("generated credentials did not authenticate: %v: %v", err, last)
	}
}
