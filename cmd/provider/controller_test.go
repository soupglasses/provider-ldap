// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"
	"time"

	"github.com/crossplane/crossplane-runtime/v2/pkg/controller"
	"github.com/crossplane/crossplane-runtime/v2/pkg/logging"
	"github.com/crossplane/crossplane-runtime/v2/pkg/meta"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	managerfake "github.com/crossplane/crossplane-runtime/v2/pkg/resource/fake"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	"github.com/go-ldap/ldap/v3"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	crevent "sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	configapi "github.com/soupglasses/provider-ldap/apis/namespaced/v1beta1"
)

var (
	_ resource.ProviderConfig           = &configapi.ProviderConfig{}
	_ resource.ProviderConfig           = &configapi.ClusterProviderConfig{}
	_ resource.TypedProviderConfigUsage = &configapi.ProviderConfigUsage{}
	_ resource.ProviderConfigUsageList  = &configapi.ProviderConfigUsageList{}
)

type reconcilerTestManager struct{ *managerfake.Manager }

func (m *reconcilerTestManager) GetEventRecorderFor(string) record.EventRecorder {
	return record.NewFakeRecorder(100)
}

func TestRecentlyCreatedEntryDeletesWithoutConsistencyDelay(t *testing.T) {
	ctx := context.Background()
	entry := testEntry("ProviderConfig", "directory")
	entry.Name = "group"
	entry.UID = types.UID("group-uid")
	entry.Spec.ForProvider.DN = "cn=group,dc=example"
	entry.Spec.ManagementPolicies = xpv2.ManagementPolicies{xpv2.ManagementActionObserve, xpv2.ManagementActionCreate, xpv2.ManagementActionUpdate, xpv2.ManagementActionDelete}
	entry.Finalizers = []string{managed.FinalizerName}
	now := metav1.Now()
	entry.SetDeletionTimestamp(&now)
	meta.SetExternalName(entry, entry.Spec.ForProvider.DN)
	meta.SetExternalCreateSucceeded(entry, time.Now())
	scheme := testScheme(t)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&entryapi.Entry{}).WithObjects(entry).Build()
	mgr := &reconcilerTestManager{Manager: &managerfake.Manager{Client: kube, Scheme: scheme}}
	directory := &fixtureLDAP{entry: ldap.NewEntry(entry.Spec.ForProvider.DN, map[string][]string{})}
	r := newEntryReconciler(mgr, controller.Options{Logger: logging.NewNopLogger(), PollInterval: time.Minute},
		managed.WithExternalConnector(managed.ExternalConnectorFn(func(context.Context, resource.Managed) (managed.ExternalClient, error) {
			return &ldapExternal{conn: directory}, nil
		})))
	request := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: entry.Namespace, Name: entry.Name}}
	// First reconcile deletes LDAP; the next confirms absence and releases the finalizer immediately.
	for range 2 {
		if _, err := r.Reconcile(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	if directory.entry != nil {
		t.Fatal("LDAP deletion was not issued")
	}
	remaining := &entryapi.Entry{}
	if err := kube.Get(ctx, request.NamespacedName, remaining); !apierrors.IsNotFound(err) {
		t.Fatalf("recent creation kept the deleted Entry finalized: %v", err)
	}
}
func TestDeletionEventEnqueuesWithoutStatusLoops(t *testing.T) {
	old := testEntry("ProviderConfig", "directory")
	deleting := old.DeepCopy()
	now := metav1.Now()
	deleting.SetDeletionTimestamp(&now)
	if !entryEventFilter().Update(crevent.UpdateEvent{ObjectOld: old, ObjectNew: deleting}) {
		t.Fatal("deletion metadata update was ignored")
	}
	statusOnly := old.DeepCopy()
	statusOnly.Status.AtProvider.UUID = "observed"
	if entryEventFilter().Update(crevent.UpdateEvent{ObjectOld: old, ObjectNew: statusOnly}) {
		t.Fatal("status-only update caused an immediate reconcile loop")
	}
}
