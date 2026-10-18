// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	"k8s.io/apimachinery/pkg/types"
	"strings"
	"testing"

	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
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

func testEntry(kind, name string) *entryapi.Entry {
	return &entryapi.Entry{ObjectMeta: metav1.ObjectMeta{Namespace: "media"}, Spec: entryapi.EntrySpec{ManagedResourceSpec: xpv2.ManagedResourceSpec{ProviderConfigReference: &xpv2.ProviderConfigReference{Kind: kind, Name: name}}, ForProvider: entryapi.EntryParameters{DN: "uid=media.service,ou=system,dc=example,dc=test"}}}
}
func credentials(namespace string) configapi.ProviderCredentials {
	return configapi.ProviderCredentials{Source: xpv2.CredentialsSourceSecret, CommonCredentialSelectors: xpv2.CommonCredentialSelectors{SecretRef: &xpv2.SecretKeySelector{SecretReference: xpv2.SecretReference{Namespace: namespace, Name: "credentials"}, Key: "connection.yaml"}}}
}
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, configapi.AddToScheme, entryapi.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}
func TestNamespacedProviderCredentialBoundary(t *testing.T) {
	for _, namespace := range []string{"", "media", "other"} {
		pc := &configapi.ProviderConfig{ObjectMeta: metav1.ObjectMeta{Namespace: "media", Name: "local"}, Spec: configapi.ProviderConfigSpec{Credentials: credentials(namespace)}}
		kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(pc).Build()
		creds, _, err := providerSettings(context.Background(), kube, testEntry("ProviderConfig", "local"))
		if namespace == "other" {
			if err == nil {
				t.Fatal("accepted cross-namespace credentials")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if creds.SecretRef.Namespace != "media" {
			t.Fatal("local credential namespace not resolved")
		}
	}
}
func TestClusterProviderAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name            string
		selector        *metav1.LabelSelector
		namespaceLabels map[string]string
		dn              string
		allowed         bool
	}{
		{"missing selector", nil, nil, "uid=media.service,ou=system,dc=example,dc=test", false},
		{"empty selector", &metav1.LabelSelector{}, nil, "uid=media.service,ou=system,dc=example,dc=test", false},
		{"invalid selector", &metav1.LabelSelector{MatchLabels: map[string]string{"bad key": "yes"}}, nil, "uid=media.service,ou=system,dc=example,dc=test", false},
		{"denied namespace", &metav1.LabelSelector{MatchLabels: map[string]string{"directory": "shared"}}, nil, "uid=media.service,ou=system,dc=example,dc=test", false},
		{"authorized namespace", &metav1.LabelSelector{MatchLabels: map[string]string{"directory": "shared"}}, map[string]string{"directory": "shared"}, "uid=media.service,ou=system,dc=example,dc=test", true},
		{"matching expression", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "directory", Operator: metav1.LabelSelectorOpIn, Values: []string{"shared"}}}}, map[string]string{"directory": "shared"}, "uid=media.service,ou=system,dc=example,dc=test", true},
		{"wrong DN prefix", &metav1.LabelSelector{MatchLabels: map[string]string{"directory": "shared"}}, map[string]string{"directory": "shared"}, "uid=other.service,ou=system,dc=example,dc=test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := &configapi.ClusterProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "shared"}, Spec: configapi.ClusterProviderConfigSpec{ProviderConfigSpec: configapi.ProviderConfigSpec{Credentials: credentials("platform")}, NamespaceSelector: tc.selector, AllowedBases: []string{"ou=system,dc=example,dc=test"}}}
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "media", Labels: tc.namespaceLabels}}
			kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(pc, ns).Build()
			entry := testEntry("ClusterProviderConfig", "shared")
			entry.Spec.ForProvider.DN = tc.dn
			_, shared, err := providerSettings(context.Background(), kube, entry)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v error=%v", tc.allowed, err)
			}
			if tc.allowed && !shared {
				t.Fatal("lost shared configuration boundary")
			}
		})
	}
}
func TestSharedCredentialsRequireTLS(t *testing.T) {
	pc := &configapi.ClusterProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "shared"}, Spec: configapi.ClusterProviderConfigSpec{ProviderConfigSpec: configapi.ProviderConfigSpec{Credentials: credentials("platform")}, NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"directory": "shared"}}, AllowedBases: []string{"ou=system,dc=example,dc=test"}}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "media", Labels: map[string]string{"directory": "shared"}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "platform"}, Data: map[string][]byte{"connection.yaml": []byte("host: localhost\nbindDN: cn=admin\npassword: secret\ntls: false\n")}}
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(pc, ns, secret).Build()
	if _, err := connectionSettings(context.Background(), kube, testEntry("ClusterProviderConfig", "shared")); err == nil {
		t.Fatal("shared plaintext connection accepted")
	}
}
func TestConnectionDocument(t *testing.T) {
	cfg, err := parseConnection([]byte("host: directory.example\nbindDN: cn=admin\npassword: test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !*cfg.TLS || cfg.Port != 636 {
		t.Fatal("connection defaults must use verified TLS on port 636")
	}
	for _, doc := range []string{"host: [credential-value]", "host: localhost\nbindDN: cn=admin\npassword: credential-value\nunknown: leaked", "host: localhost\nbindDN: cn=admin\npassword: credential-value\nport: 0"} {
		if _, err := parseConnection([]byte(doc)); err == nil || strings.Contains(err.Error(), "credential-value") {
			t.Fatalf("invalid connection accepted or credential leaked: %v", err)
		}
	}
}

func TestProviderUsageFollowsMissingReference(t *testing.T) {
	ctx := context.Background()
	pc := &configapi.ProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "media"}, Spec: configapi.ProviderConfigSpec{Credentials: credentials("media")}}
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(pc).Build()
	connector := &ldapConnector{kube: kube, tracker: resource.NewProviderConfigUsageTracker(kube, &configapi.ProviderConfigUsage{})}
	entry := testEntry("ProviderConfig", "first")
	entry.Name = "service"
	entry.UID = types.UID("fixture-uid")
	entry.SetGroupVersionKind(entryapi.CRDGroupVersion.WithKind("Entry"))
	// Missing credentials stop before binding, but the reference must still be tracked.
	if _, err := connector.Connect(ctx, entry); err == nil {
		t.Fatal("connection without credentials succeeded")
	}
	entry.Spec.ProviderConfigReference.Name = "missing-backend"
	if _, err := connector.Connect(ctx, entry); err == nil {
		t.Fatal("missing provider was accepted")
	}
	usages := &configapi.ProviderConfigUsageList{}
	if err := kube.List(ctx, usages); err != nil {
		t.Fatal(err)
	}
	if len(usages.Items) != 1 || usages.Items[0].GetProviderConfigReference().Name != "missing-backend" {
		t.Fatal("usage retained the previous provider reference")
	}
}
func TestTrackedSharedReferenceDoesNotBypassAuthorization(t *testing.T) {
	ctx := context.Background()
	pc := &configapi.ClusterProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "shared"}, Spec: configapi.ClusterProviderConfigSpec{ProviderConfigSpec: configapi.ProviderConfigSpec{Credentials: credentials("platform")}, NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"directory": "shared"}}, AllowedBases: []string{"ou=system,dc=example,dc=test"}}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "media"}}
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(pc, ns).Build()
	connector := &ldapConnector{kube: kube, tracker: resource.NewProviderConfigUsageTracker(kube, &configapi.ProviderConfigUsage{})}
	entry := testEntry("ClusterProviderConfig", "shared")
	entry.Name = "service"
	entry.UID = types.UID("denied-uid")
	entry.SetGroupVersionKind(entryapi.CRDGroupVersion.WithKind("Entry"))
	if _, err := connector.Connect(ctx, entry); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("shared reference bypassed namespace authorization: %v", err)
	}
}
