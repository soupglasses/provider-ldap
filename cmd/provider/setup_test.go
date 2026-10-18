// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	xpresource "github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	"github.com/crossplane/upjet/v2/pkg/terraform"
	"io"
	"net"
	"strconv"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldapclient "github.com/l-with/terraform-provider-ldap/client"
	"k8s.io/apimachinery/pkg/types"
	"testing"

	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	configapi "github.com/soupglasses/provider-ldap/apis/namespaced/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEntryOwnership(t *testing.T) {
	bases := []string{"ou=system,dc=example,dc=test", "ou=groups,dc=example,dc=test", "ou=services,dc=example,dc=test"}
	for _, tc := range []struct {
		name, dn string
		allowed  bool
	}{
		{"client", "cn=media.client,ou=services,dc=example,dc=test", true},
		{"service", "uid=media.jellyfin,ou=system,dc=example,dc=test", true},
		{"group", "cn=media.viewers,ou=groups,dc=example,dc=test", true},
		{"case normalized", "UID=MEDIA.Jellyfin,OU=SYSTEM,DC=EXAMPLE,DC=TEST", true},
		{"escaped dot", `uid=media\2ejellyfin,ou=system,dc=example,dc=test`, true},
		{"other namespace", "uid=identity.jellyfin,ou=system,dc=example,dc=test", false},
		{"ambiguous prefix", "uid=mediacenter.jellyfin,ou=system,dc=example,dc=test", false},
		{"missing separator", "uid=media,ou=system,dc=example,dc=test", false},
		{"human user", "uid=media.jellyfin,ou=users,dc=example,dc=test", false},
		{"base itself", "ou=system,dc=example,dc=test", false},
		{"descendant", "uid=media.jellyfin,ou=other,ou=system,dc=example,dc=test", false},
		{"escaped separator", `uid=media.jellyfin\,ou=system,dc=example,dc=test`, false},
		{"multivalued leaf", "uid=media.jellyfin+cn=admin,ou=system,dc=example,dc=test", false},
		{"multivalued parent", "uid=media.jellyfin,ou=system+cn=admin,dc=example,dc=test", false},
		{"invalid", "not a DN", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEntryDN(tc.dn, "media", bases)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v, error=%v", tc.allowed, err)
			}
		})
	}
	if err := validateEntryDN("uid=media.jellyfin,ou=system,dc=example,dc=test", "media", nil); err == nil {
		t.Fatal("empty allowed bases accepted")
	}
}

func TestClusterProviderAuthorization(t *testing.T) {
	const backendLabel = "directory.example.test/backend"
	for _, tc := range []struct {
		name, label, dn string
		tls, allowed    bool
	}{
		{"opted in", "directory", "uid=media.jellyfin,ou=system,dc=example,dc=test", true, true},
		{"not opted in", "", "uid=media.jellyfin,ou=system,dc=example,dc=test", true, false},
		{"different backend", "other", "uid=media.jellyfin,ou=system,dc=example,dc=test", true, false},
		{"other namespace DN", "directory", "uid=identity.jellyfin,ou=system,dc=example,dc=test", true, false},
		{"plaintext root bind", "directory", "uid=media.jellyfin,ou=system,dc=example,dc=test", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := configapi.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			pc := &configapi.ClusterProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "directory"}, Spec: configapi.ClusterProviderConfigSpec{
				ProviderConfigSpec: configapi.ProviderConfigSpec{TLS: tc.tls, CredentialsSecretRef: configapi.CredentialsReference{Namespace: "identity", Name: "openldap", Key: "LDAP_ROOT_PASSWORD"}},
				NamespaceSelector:  &metav1.LabelSelector{MatchLabels: map[string]string{backendLabel: "directory"}},
				AllowedBases:       []string{"ou=system,dc=example,dc=test"},
			}}
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "media", Labels: map[string]string{backendLabel: tc.label}}}
			k := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pc, ns).Build()
			entry := testEntry(t, "ClusterProviderConfig", "directory")
			entry.Annotations = map[string]string{"crossplane.io/external-name": tc.dn}
			spec, _, err := providerSettings(context.Background(), k, entry)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v, error=%v", tc.allowed, err)
			}
			if tc.allowed && spec.CredentialsSecretRef.Namespace != "identity" {
				t.Fatal("central credential namespace lost")
			}
		})
	}
}

func TestClusterProviderNamespaceSelector(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selector *metav1.LabelSelector
		allowed  bool
	}{
		{"missing", nil, false},
		{"empty", &metav1.LabelSelector{}, false},
		{"empty labels", &metav1.LabelSelector{MatchLabels: map[string]string{}}, false},
		{"invalid key", &metav1.LabelSelector{MatchLabels: map[string]string{"invalid key": "yes"}}, false},
		{"invalid operator", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "directory", Operator: "Invalid"}}}, false},
		{"matching labels", &metav1.LabelSelector{MatchLabels: map[string]string{"directory": "shared"}}, true},
		{"nonmatching labels", &metav1.LabelSelector{MatchLabels: map[string]string{"directory": "other"}}, false},
		{"matching expression", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "directory", Operator: metav1.LabelSelectorOpIn, Values: []string{"shared"}}}}, true},
		{"nonmatching expression", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "directory", Operator: metav1.LabelSelectorOpDoesNotExist}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := configapi.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			pc := &configapi.ClusterProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "shared"}, Spec: configapi.ClusterProviderConfigSpec{
				ProviderConfigSpec: configapi.ProviderConfigSpec{TLS: true, CredentialsSecretRef: configapi.CredentialsReference{Namespace: "platform", Name: "directory", Key: "password"}},
				NamespaceSelector:  tc.selector,
				AllowedBases:       []string{"ou=system,dc=example,dc=test"},
			}}
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "media", Labels: map[string]string{"directory": "shared"}}}
			k := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pc, ns).Build()
			entry := testEntry(t, "ClusterProviderConfig", "shared")
			entry.Annotations = map[string]string{"crossplane.io/external-name": "uid=media.service,ou=system,dc=example,dc=test"}
			_, _, err := providerSettings(context.Background(), k, entry)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v, error=%v", tc.allowed, err)
			}
			if !tc.allowed {
				entry.SetUID(types.UID("denied-selector"))
				entry.SetGroupVersionKind(entryapi.CRDGroupVersion.WithKind("Entry"))
				tracker := xpresource.NewProviderConfigUsageTracker(k, &configapi.ProviderConfigUsage{})
				if _, err := setupLDAP(context.Background(), k, entry, tracker); err == nil {
					t.Fatal("unauthorized shared provider connection accepted")
				}
				usages := &configapi.ProviderConfigUsageList{}
				if err := k.List(context.Background(), usages); err != nil {
					t.Fatal(err)
				}
				if len(usages.Items) != 0 {
					t.Fatal("unauthorized connection created a provider usage")
				}
			}
		})
	}
}

func TestNamespacedProviderCannotReadAnotherNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := configapi.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"", "media", "identity"} {
		pc := &configapi.ProviderConfig{ObjectMeta: metav1.ObjectMeta{Namespace: "media", Name: "local"}, Spec: configapi.ProviderConfigSpec{CredentialsSecretRef: configapi.CredentialsReference{Namespace: namespace}}}
		k := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pc).Build()
		spec, _, err := providerSettings(context.Background(), k, testEntry(t, "ProviderConfig", "local"))
		if namespace == "identity" {
			if err == nil {
				t.Fatal("cross-namespace credential reference accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if spec.CredentialsSecretRef.Namespace != "media" {
			t.Fatal("local credential namespace not resolved")
		}
	}
}

func testEntry(t *testing.T, kind, name string) *entryapi.Entry {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"metadata": map[string]any{"namespace": "media", "annotations": map[string]any{"crossplane.io/external-name": "uid=media.service,ou=system,dc=example,dc=test"}}, "spec": map[string]any{"providerConfigRef": map[string]any{"kind": kind, "name": name}}})
	if err != nil {
		t.Fatal(err)
	}
	entry := &entryapi.Entry{}
	if err := json.Unmarshal(raw, entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

// Exercise a real LDAP bind and Crossplane disconnection without a directory process.
func TestReconciliationConnectionLifecycle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var sockets []net.Conn
	boundPasswords := make(chan string, 8)
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, socket := range sockets {
			socket.Close()
		}
	})
	go func() {
		for {
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			sockets = append(sockets, socket)
			mu.Unlock()
			go func() {
				defer socket.Close()
				packet, err := ber.ReadPacket(socket)
				if err != nil {
					return
				}
				boundPasswords <- string(packet.Children[1].Children[2].Data.Bytes())
				// LDAP BindResponse: message ID 1, successful result, empty matched DN and diagnostic.
				if _, err := socket.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, socket)
			}()
		}
	}()
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := configapi.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pc := &configapi.ProviderConfig{ObjectMeta: metav1.ObjectMeta{Namespace: "media", Name: "local"}, Spec: configapi.ProviderConfigSpec{
		Host: "127.0.0.1", Port: port, BindDN: "cn=fixture", TLS: false,
		CredentialsSecretRef: configapi.CredentialsReference{Name: "credentials", Key: "password"},
	}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "media", Name: "credentials"}, Data: map[string][]byte{"password": []byte("disposable-one")}}
	k := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pc, secret).Build()
	entry := testEntry(t, "ProviderConfig", "local")
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("connect failure=%v", fail), func(t *testing.T) {
			var opened *ldapclient.Client
			connector := &ldapConnector{newConnector: func(sf terraform.SetupFn) managed.ExternalConnector {
				return managed.ExternalConnectorFn(func(ctx context.Context, mg xpresource.Managed) (managed.ExternalClient, error) {
					setup, err := sf(ctx, k, mg)
					if err != nil {
						return nil, err
					}
					opened = setup.Meta.(*ldapclient.Client)
					if password := <-boundPasswords; password != string(secret.Data["password"]) {
						t.Fatalf("bound with stale credentials: %q", password)
					}
					if fail {
						return nil, errors.New("failure after bind")
					}
					return managed.ExternalClientFns{DisconnectFn: func(context.Context) error { return nil }}, nil
				})
			}}
			external, err := connector.Connect(context.Background(), entry)
			if fail {
				if err == nil || opened == nil || !opened.Conn.IsClosing() {
					t.Fatal("failed connection retained a bound LDAP socket")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opened.Conn.IsClosing() {
				t.Fatal("socket closed before reconciliation completed")
			}
			first := opened.Conn
			if err = external.Disconnect(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !first.IsClosing() {
				t.Fatal("Disconnect retained a bound LDAP socket")
			}
			if err = k.Get(context.Background(), types.NamespacedName{Namespace: "media", Name: "credentials"}, secret); err != nil {
				t.Fatal(err)
			}
			secret.Data["password"] = []byte("disposable-two")
			if err = k.Update(context.Background(), secret); err != nil {
				t.Fatal(err)
			}
			next, err := connector.Connect(context.Background(), entry)
			if err != nil {
				t.Fatal(err)
			}
			if opened.Conn == first {
				t.Fatal("next reconciliation reused a closed credential connection")
			}
			if err = next.Disconnect(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNamespacedProviderRequiresExternalDN(t *testing.T) {
	for _, dn := range []string{"", "not a DN"} {
		entry := testEntry(t, "ProviderConfig", "local")
		entry.Annotations["crossplane.io/external-name"] = dn
		_, _, err := providerSettings(context.Background(), fake.NewClientBuilder().Build(), entry)
		if err == nil {
			t.Fatalf("invalid DN %q accepted", dn)
		}
	}
}
