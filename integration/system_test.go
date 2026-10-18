//go:build system

// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestKubernetesReconciliation(t *testing.T) {
	ns := os.Getenv("POD_NAMESPACE")
	ip := os.Getenv("TEST_POD_IP")
	if ns == "" || ip == "" {
		t.Skip("requires the disposable integration Pod's in-cluster environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cfg, err := rest.InClusterConfig()
	if err != nil {
		t.Fatal(err)
	}
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := startLDAP(t)
	suffix := fmt.Sprintf("%x", time.Now().UnixNano())
	providerName := "fixture-" + suffix
	docName := "attributes-" + suffix
	entryName := "client-" + suffix
	secret, err := kube.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: providerName}, Data: map[string][]byte{"password": []byte(fixturePassword)}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = kube.CoreV1().Secrets(ns).Delete(context.Background(), secret.Name, metav1.DeleteOptions{})
	})
	pcGVR := schema.GroupVersionResource{Group: "ldap.ops.finnes.dev", Version: "v1beta1", Resource: "providerconfigs"}
	entryGVR := schema.GroupVersionResource{Group: "ldap.ops.finnes.dev", Version: "v1alpha1", Resource: "entries"}
	pc := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "ldap.ops.finnes.dev/v1beta1", "kind": "ProviderConfig", "metadata": map[string]any{"name": providerName, "namespace": ns}, "spec": map[string]any{"host": ip, "port": int64(f.port), "bindDN": "cn=admin," + baseDN, "tls": false, "credentialsSecretRef": map[string]any{"name": providerName, "key": "password"}}}}
	if _, err = dyn.Resource(pcGVR).Namespace(ns).Create(ctx, pc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = dyn.Resource(pcGVR).Namespace(ns).Delete(context.Background(), providerName, metav1.DeleteOptions{})
	})
	dn := "uid=service,ou=users," + baseDN
	attrs := map[string][]string{"objectClass": {"inetOrgPerson"}, "cn": {"Service"}, "sn": {"Account"}, "userPassword": {"fixture-client-secret-1"}}
	defaults := map[string][]string{"description": {"external-description"}}
	_, err = kube.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: docName}, Data: map[string][]byte{"attributes.json": []byte(encoded(t, attrs)), "defaults.json": []byte(encoded(t, defaults))}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = kube.CoreV1().Secrets(ns).Delete(context.Background(), docName, metav1.DeleteOptions{}) })
	entry := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "ldap.ops.finnes.dev/v1alpha1", "kind": "Entry", "metadata": map[string]any{"name": entryName, "namespace": ns, "annotations": map[string]any{"crossplane.io/external-name": dn}}, "spec": map[string]any{"managementPolicies": []any{"Observe", "Create", "Update"}, "providerConfigRef": map[string]any{"kind": "ProviderConfig", "name": providerName}, "forProvider": map[string]any{"dataJsonSecretRef": map[string]any{"name": docName, "key": "attributes.json"}, "dataJsonCreateDefaultsSecretRef": map[string]any{"name": docName, "key": "defaults.json"}, "restrictAttributes": []any{"objectClass", "cn", "sn", "userPassword"}}}}}
	if _, err = dyn.Resource(entryGVR).Namespace(ns).Create(ctx, entry, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = dyn.Resource(entryGVR).Namespace(ns).Delete(context.Background(), entryName, metav1.DeleteOptions{})
	})
	waitReady := func() {
		t.Helper()
		err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 60*time.Second, true, func(ctx context.Context) (bool, error) {
			current, err := dyn.Resource(entryGVR).Namespace(ns).Get(ctx, entryName, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			conditions, _, _ := unstructured.NestedSlice(current.Object, "status", "conditions")
			for _, raw := range conditions {
				c := raw.(map[string]any)
				if c["type"] == "Ready" && c["status"] == "True" {
					return true, nil
				}
			}
			return false, nil
		})
		if err != nil {
			current, _ := dyn.Resource(entryGVR).Namespace(ns).Get(ctx, entryName, metav1.GetOptions{})
			if current != nil {
				status, _, _ := unstructured.NestedMap(current.Object, "status")
				t.Logf("Entry conditions: %v", status["conditions"])
			}
			t.Fatal("Entry did not become Ready:", err)
		}
	}
	waitValue := func(attribute, value string) {
		t.Helper()
		err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 45*time.Second, true, func(context.Context) (bool, error) {
			result, err := f.conn.Search(ldapSearch(dn))
			if err != nil {
				return false, nil
			}
			return len(result.Entries) == 1 && result.Entries[0].GetAttributeValue(attribute) == value, nil
		})
		if err != nil {
			t.Fatalf("LDAP attribute %s did not converge: %v", attribute, err)
		}
	}
	waitReady()
	waitValue("cn", "Service")
	t.Log("CR created a standard inetOrgPerson entry and reached Ready")
	modify(t, f.conn, dn, map[string][]string{"cn": {"wrong"}, "description": {"externally-updated"}, "telephoneNumber": {"555-0100"}})
	waitValue("cn", "Service")
	if read(t, f.conn, dn).GetAttributeValue("description") != "externally-updated" || read(t, f.conn, dn).GetAttributeValue("telephoneNumber") != "555-0100" {
		t.Fatal("controller overwrote runtime attributes")
	}
	t.Log("polling repaired LDAP drift without a Kubernetes manifest change")
	attrs["userPassword"] = []string{"fixture-client-secret-2"}
	doc, err := kube.CoreV1().Secrets(ns).Get(ctx, docName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	doc.Data["attributes.json"] = []byte(encoded(t, attrs))
	if _, err = kube.CoreV1().Secrets(ns).Update(ctx, doc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitValue("userPassword", "fixture-client-secret-2")
	current, err := dyn.Resource(entryGVR).Namespace(ns).Get(ctx, entryName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	status, _, _ := unstructured.NestedMap(current.Object, "status")
	raw, _ := json.Marshal(status)
	if strings.Contains(string(raw), "fixture-client-secret") {
		t.Fatal("credential document leaked into CR status")
	}
	t.Log("Secret rotation propagated and credential contents stayed out of CR status")
	selector := "app.kubernetes.io/name=ldap-provider"
	providerNamespace := os.Getenv("PROVIDER_NAMESPACE")
	pods, err := kube.CoreV1().Pods(providerNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil || len(pods.Items) != 1 {
		t.Fatalf("expected one provider Pod: %v", err)
	}
	if err = kube.CoreV1().Pods(providerNamespace).Delete(ctx, pods.Items[0].Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	err = wait.PollUntilContextTimeout(ctx, time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		next, err := kube.CoreV1().Pods(providerNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return false, err
		}
		for _, p := range next.Items {
			if p.UID == pods.Items[0].UID {
				continue
			}
			for _, condition := range p.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					return true, nil
				}
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatal("provider restart failed:", err)
	}
	modify(t, f.conn, dn, map[string][]string{"cn": {"wrong-after-restart"}})
	waitValue("cn", "Service")
	t.Log("controller restart reconstructed ownership from the external DN and repaired drift without tfstate")
	// Missing local credentials must report failure without creating a directory entry.
	isolated := pc.DeepCopy()
	isolated.SetResourceVersion("")
	isolated.SetUID("")
	isolated.SetName(providerName + "-missing")
	_ = unstructured.SetNestedField(isolated.Object, "absent-local-credential", "spec", "credentialsSecretRef", "name")
	if _, err = dyn.Resource(pcGVR).Namespace(ns).Create(ctx, isolated, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = dyn.Resource(pcGVR).Namespace(ns).Delete(context.Background(), isolated.GetName(), metav1.DeleteOptions{})
	})
	bad := entry.DeepCopy()
	bad.SetResourceVersion("")
	bad.SetUID("")
	bad.SetName(entryName + "-missing")
	bad.SetAnnotations(map[string]string{"crossplane.io/external-name": "uid=must-not-exist,ou=users," + baseDN})
	_ = unstructured.SetNestedField(bad.Object, isolated.GetName(), "spec", "providerConfigRef", "name")
	if _, err = dyn.Resource(entryGVR).Namespace(ns).Create(ctx, bad, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = dyn.Resource(entryGVR).Namespace(ns).Delete(context.Background(), bad.GetName(), metav1.DeleteOptions{})
	})
	err = wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		obj, err := dyn.Resource(entryGVR).Namespace(ns).Get(ctx, bad.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
		for _, raw := range conditions {
			c := raw.(map[string]any)
			if c["type"] == "Synced" && c["status"] == "False" {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatal("missing credentials did not report reconciliation failure:", err)
	}
	if _, err = f.conn.Search(ldapSearch(bad.GetAnnotations()["crossplane.io/external-name"])); err == nil {
		t.Fatal("entry created without configured credentials")
	}
	t.Log("missing local provider credentials failed closed")
	// Orphaning the management CR preserves the LDAP entry for deliberate re-adoption.
	if err = dyn.Resource(entryGVR).Namespace(ns).Delete(ctx, entryName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	err = wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := dyn.Resource(entryGVR).Namespace(ns).Get(ctx, entryName, metav1.GetOptions{})
		return apierrors.IsNotFound(err), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	read(t, f.conn, dn)
	t.Log("deleting a CR without Delete policy retained the directory entry")
	// Observe-only adoption must leave a conflicting desired value untouched.
	adopted := entry.DeepCopy()
	_ = unstructured.SetNestedSlice(adopted.Object, []any{"Observe"}, "spec", "managementPolicies")
	if _, err = dyn.Resource(entryGVR).Namespace(ns).Create(ctx, adopted, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitReady()
	modify(t, f.conn, dn, map[string][]string{"cn": {"externally-managed"}})
	changed := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 5*time.Second, true, func(context.Context) (bool, error) {
		return read(t, f.conn, dn).GetAttributeValue("cn") != "externally-managed", nil
	})
	if changed == nil || ctx.Err() != nil {
		t.Fatal("Observe-only adoption changed the external entry or failed to finish")
	}
	t.Log("Observe-only adoption preserved external drift across polling intervals")
	adopted, err = dyn.Resource(entryGVR).Namespace(ns).Get(ctx, entryName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedSlice(adopted.Object, []any{"Observe", "Create", "Update", "Delete"}, "spec", "managementPolicies")
	if _, err = dyn.Resource(entryGVR).Namespace(ns).Update(ctx, adopted, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitValue("cn", "Service")
	err = wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		config, err := dyn.Resource(pcGVR).Namespace(ns).Get(ctx, providerName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		users, _, _ := unstructured.NestedInt64(config.Object, "status", "users")
		return len(config.GetFinalizers()) > 0 && users > 0, nil
	})
	if err != nil {
		t.Fatal("provider usage did not establish deletion protection:", err)
	}
	if err = dyn.Resource(pcGVR).Namespace(ns).Delete(ctx, providerName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	err = wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		config, err := dyn.Resource(pcGVR).Namespace(ns).Get(ctx, providerName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		users, _, _ := unstructured.NestedInt64(config.Object, "status", "users")
		return config.GetDeletionTimestamp() != nil && len(config.GetFinalizers()) > 0 && users > 0, nil
	})
	if err != nil {
		t.Fatal("in-use provider configuration was not protected:", err)
	}
	t.Log("native usage tracking protected a terminating provider configuration")
	if err = dyn.Resource(entryGVR).Namespace(ns).Delete(ctx, entryName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	err = wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		_, getErr := dyn.Resource(entryGVR).Namespace(ns).Get(ctx, entryName, metav1.GetOptions{})
		_, ldapErr := f.conn.Search(ldapSearch(dn))
		return apierrors.IsNotFound(getErr) && ldap.IsErrorWithCode(ldapErr, ldap.LDAPResultNoSuchObject), nil
	})
	if err != nil {
		t.Fatal("Delete policy did not remove the directory entry:", err)
	}
	t.Log("re-adoption resumed reconciliation and explicit Delete removed the external entry")
	err = wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 45*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := dyn.Resource(pcGVR).Namespace(ns).Get(ctx, providerName, metav1.GetOptions{})
		return apierrors.IsNotFound(err), nil
	})
	if err != nil {
		t.Fatal("unused terminating provider configuration was not released:", err)
	}
	t.Log("removing the final managed entry released its provider configuration")

}

func ldapSearch(dn string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"*"}, nil)
}
