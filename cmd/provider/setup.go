// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	"github.com/go-ldap/ldap/v3"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	configapi "github.com/soupglasses/provider-ldap/apis/namespaced/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const ldapTimeout = 10 * time.Second

// ConnectionDocument is decoded only in memory from the provider credential Secret.
type ConnectionDocument struct {
	Host          string `json:"host"`
	Port          int    `json:"port,omitempty"`
	BindDN        string `json:"bindDN"`
	Password      string `json:"password"`
	TLS           *bool  `json:"tls,omitempty"`
	TLSServerName string `json:"tlsServerName,omitempty"`
}

func parseConnection(data []byte) (ConnectionDocument, error) {
	out := ConnectionDocument{Port: 636}
	if err := yaml.UnmarshalStrict(data, &out); err != nil {
		return out, fmt.Errorf("credentials must contain a valid YAML or JSON LDAP connection document")
	}
	if out.Host == "" || out.BindDN == "" || out.Password == "" || out.Port < 1 || out.Port > 65535 {
		return out, fmt.Errorf("connection document requires host, bindDN, nonempty password and a valid port")
	}
	if out.TLS == nil {
		value := true
		out.TLS = &value
	}
	if _, err := ldap.ParseDN(out.BindDN); err != nil {
		return out, fmt.Errorf("connection document bindDN is invalid")
	}
	return out, nil
}

// validateEntryDN uses parsed RDNs so escaping and case changes cannot escape the ownership boundary.
func validateEntryDN(raw, namespace string, bases []string) error {
	dn, err := ldap.ParseDN(raw)
	if err != nil || len(dn.RDNs) < 2 {
		return fmt.Errorf("entry requires a valid child DN")
	}
	for _, rdn := range dn.RDNs {
		if len(rdn.Attributes) != 1 {
			return fmt.Errorf("multivalued RDNs are not permitted")
		}
	}
	if !strings.HasPrefix(strings.ToLower(dn.RDNs[0].Attributes[0].Value), namespace+".") {
		return fmt.Errorf("entry RDN must start with its namespace followed by a dot")
	}
	parent := &ldap.DN{RDNs: dn.RDNs[1:]}
	for _, rawBase := range bases {
		base, err := ldap.ParseDN(rawBase)
		if err != nil || len(base.RDNs) == 0 {
			return fmt.Errorf("provider has an invalid allowed base")
		}
		for _, rdn := range base.RDNs {
			if len(rdn.Attributes) != 1 {
				return fmt.Errorf("provider allowed bases must not contain multivalued RDNs")
			}
		}
		if parent.EqualFold(base) {
			return nil
		}
	}
	return fmt.Errorf("entry must be a direct child of an allowed base")
}

// providerSettings authorizes the reference before any credentials are retrieved.
func providerSettings(ctx context.Context, k client.Client, entry *entryapi.Entry) (configapi.ProviderCredentials, bool, error) {
	if _, err := parseDN(entry.Spec.ForProvider.DN); err != nil {
		return configapi.ProviderCredentials{}, false, err
	}
	ref := entry.GetProviderConfigReference()
	if ref == nil || ref.Name == "" {
		return configapi.ProviderCredentials{}, false, fmt.Errorf("a provider configuration reference is required")
	}
	var creds configapi.ProviderCredentials
	shared := false
	switch ref.Kind {
	case "ProviderConfig":
		pc := &configapi.ProviderConfig{}
		if err := k.Get(ctx, types.NamespacedName{Namespace: entry.Namespace, Name: ref.Name}, pc); err != nil {
			return creds, false, err
		}
		creds = pc.Spec.Credentials
		if creds.SecretRef == nil || (creds.SecretRef.Namespace != "" && creds.SecretRef.Namespace != entry.Namespace) {
			return creds, false, fmt.Errorf("namespaced provider credentials must remain in the entry namespace")
		}
		copy := *creds.SecretRef
		copy.Namespace = entry.Namespace
		creds.SecretRef = &copy
	case "ClusterProviderConfig":
		shared = true
		pc := &configapi.ClusterProviderConfig{}
		if err := k.Get(ctx, types.NamespacedName{Name: ref.Name}, pc); err != nil {
			return creds, false, err
		}
		selector, err := metav1.LabelSelectorAsSelector(pc.Spec.NamespaceSelector)
		if pc.Spec.NamespaceSelector == nil || err != nil || selector.Empty() {
			return creds, false, fmt.Errorf("cluster provider requires a valid nonempty namespace selector")
		}
		namespace := &corev1.Namespace{}
		if err := k.Get(ctx, types.NamespacedName{Name: entry.Namespace}, namespace); err != nil {
			return creds, false, err
		}
		if !selector.Matches(labels.Set(namespace.Labels)) {
			return creds, false, fmt.Errorf("entry namespace is not authorized by the directory backend")
		}
		if err := validateEntryDN(entry.Spec.ForProvider.DN, entry.Namespace, pc.Spec.AllowedBases); err != nil {
			return creds, false, err
		}
		creds = pc.Spec.Credentials
		if creds.SecretRef == nil || creds.SecretRef.Namespace == "" {
			return creds, false, fmt.Errorf("shared credentials require an explicit Secret namespace")
		}
	default:
		return creds, false, fmt.Errorf("unsupported provider configuration kind")
	}
	if creds.Source != xpv2.CredentialsSourceSecret || creds.SecretRef == nil || creds.SecretRef.Name == "" || creds.SecretRef.Key == "" || creds.Env != nil || creds.Fs != nil {
		return creds, false, fmt.Errorf("provider credentials require source Secret and a complete secretRef")
	}
	return creds, shared, nil
}

func connectionSettings(ctx context.Context, k client.Client, entry *entryapi.Entry) (ConnectionDocument, error) {
	creds, shared, err := providerSettings(ctx, k, entry)
	if err != nil {
		return ConnectionDocument{}, err
	}
	data, err := resource.CommonCredentialExtractor(ctx, creds.Source, k, creds.CommonCredentialSelectors)
	if err != nil {
		return ConnectionDocument{}, fmt.Errorf("read LDAP credentials: %w", err)
	}
	cfg, err := parseConnection(data)
	if err != nil {
		return cfg, err
	}
	if shared && !*cfg.TLS {
		return cfg, fmt.Errorf("shared credentials require verified TLS")
	}
	return cfg, nil
}
func dialLDAP(spec ConnectionDocument) (*ldap.Conn, error) {
	scheme := "ldaps"
	if !*spec.TLS {
		scheme = "ldap"
	}
	address := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port))}).String()
	conn, err := ldap.DialURL(address, ldap.DialWithDialer(&net.Dialer{Timeout: ldapTimeout}), ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: spec.TLSServerName}))
	if err != nil {
		return nil, directoryError("connect", err)
	}
	conn.SetTimeout(ldapTimeout)
	if err := conn.Bind(spec.BindDN, spec.Password); err != nil {
		conn.Close()
		return nil, directoryError("bind", err)
	}
	return conn, nil
}

// LDAP diagnostics can quote rejected values. Keep credentials out of conditions and events.
func directoryError(operation string, err error) error {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return fmt.Errorf("LDAP %s failed (result %d)", operation, ldapErr.ResultCode)
	}
	return fmt.Errorf("LDAP %s failed", operation)
}
