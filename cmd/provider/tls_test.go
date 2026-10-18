// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestVerifiedTLS(t *testing.T) {
	// Each subprocess loads its own system roots; x509 caches them process-wide.
	if os.Getenv("LDAP_TLS_TEST_ADDRESS") != "" {
		host, port, err := net.SplitHostPort(os.Getenv("LDAP_TLS_TEST_ADDRESS"))
		if err != nil {
			t.Fatal(err)
		}
		number, err := strconv.Atoi(port)
		if err != nil {
			t.Fatal(err)
		}
		enabled := true
		conn, err := dialLDAP(context.Background(), ConnectionDocument{Host: host, Port: number, BindDN: "cn=test", Password: "synthetic-password", TLS: &enabled, TLSServerName: os.Getenv("LDAP_TLS_TEST_SERVER_NAME")})
		if conn != nil {
			conn.Close()
		}
		if wantSuccess := os.Getenv("LDAP_TLS_TEST_SUCCESS") == "true"; (err == nil) != wantSuccess {
			t.Fatalf("TLS connection success = %v, expected %v: %v", err == nil, wantSuccess, err)
		}
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LDAP test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"directory.example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	defer func() { listener.Close(); <-done }()
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				request, err := ber.ReadPacket(conn)
				if err != nil || len(request.Children) < 2 {
					return
				}
				response := ber.NewSequence("LDAPMessage")
				response.AppendChild(request.Children[0])
				result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "BindResponse")
				result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
				result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
				result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
				response.AppendChild(result)
				_, _ = conn.Write(response.Bytes())
			}()
		}
	}()
	for _, test := range []struct {
		name, serverName, rootFile string
		success                    bool
	}{
		{"trusted", "directory.example.test", roots, true},
		{"wrong-hostname", "other.example.test", roots, false},
		{"untrusted", "directory.example.test", filepath.Join(t.TempDir(), "missing-ca.pem"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestVerifiedTLS$")
			cmd.Env = append(os.Environ(), "LDAP_TLS_TEST_ADDRESS="+listener.Addr().String(), "LDAP_TLS_TEST_SERVER_NAME="+test.serverName, "LDAP_TLS_TEST_SUCCESS="+strconv.FormatBool(test.success), "SSL_CERT_FILE="+test.rootFile, "SSL_CERT_DIR="+t.TempDir())
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("TLS probe: %v\n%s", err, output)
			}
		})
	}
}
