// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/crossplane/crossplane-runtime/v2/pkg/controller"
	"github.com/crossplane/crossplane-runtime/v2/pkg/event"
	"github.com/crossplane/crossplane-runtime/v2/pkg/meta"
	"github.com/crossplane/crossplane-runtime/v2/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/providerconfig"
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	configapi "github.com/soupglasses/provider-ldap/apis/namespaced/v1beta1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crevent "sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ldapConnector struct {
	kube    client.Client
	tracker *resource.ProviderConfigUsageTracker
}

func (c *ldapConnector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	entry, ok := mg.(*entryapi.Entry)
	if !ok {
		return nil, fmt.Errorf("managed resource is not an LDAP Entry")
	}
	// Usage records the current reference, even when its backend is missing or unauthorized.
	if c.tracker != nil {
		if err := c.tracker.Track(ctx, entry); err != nil {
			return nil, fmt.Errorf("track provider configuration usage: %w", err)
		}
	}
	if entry.GetDeletionTimestamp().IsZero() {
		if err := validateParameters(entry.Spec.ForProvider); err != nil {
			return nil, err
		}
	} else if _, err := parseDN(entry.Spec.ForProvider.DN); err != nil {
		return nil, err
	}
	cfg, err := connectionSettings(ctx, c.kube, entry)
	if err != nil {
		return nil, err
	}
	var desired map[string][]string
	var versions map[string]string
	if entry.GetDeletionTimestamp().IsZero() {
		desired, versions, err = resolveAttributes(ctx, c.kube, entry)
		if err != nil {
			return nil, err
		}
	}
	scope, err := identityScopeFor(ctx, c.kube, entry)
	if err != nil {
		return nil, err
	}
	conn, err := dialLDAP(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var shared map[string][]string
	if entry.GetDeletionTimestamp().IsZero() {
		shared = entry.Spec.ForProvider.SharedAttributes
	}
	external := &ldapExternal{conn: conn, desired: desired, shared: shared, secretVersions: versions, kube: c.kube, identity: &entryIdentity{kube: c.kube, scope: scope}}
	if _, err := external.refreshIdentity(ctx, entry); err != nil {
		external.Disconnect(ctx)
		return nil, err
	}
	if entry.GetDeletionTimestamp().IsZero() {
		if err := external.loadSchema(ctx, entry.Spec.ForProvider.DN); err != nil {
			external.Disconnect(ctx)
			return nil, err
		}
	}
	return external, nil
}

// Set the initial adoption anchor once; subsequent reconciles preserve the bound UUID.
type dnInitializer struct{ kube client.Client }

func (i *dnInitializer) Initialize(ctx context.Context, mg resource.Managed) error {
	entry, ok := mg.(*entryapi.Entry)
	if !ok {
		return fmt.Errorf("managed resource is not an LDAP Entry")
	}
	if _, err := parseDN(entry.Spec.ForProvider.DN); err != nil {
		return err
	}
	if meta.GetExternalName(entry) != "" {
		return nil
	}
	meta.SetExternalName(entry, entry.Spec.ForProvider.DN)
	return i.kube.Update(ctx, entry)
}

// Add targets are durably recorded before creation, so a lost reply is observable by DN. UUIDs protect subsequent mutations.
func newEntryReconciler(mgr ctrl.Manager, o controller.Options, extra ...managed.ReconcilerOption) *managed.Reconciler {
	kind := entryapi.CRDGroupVersion.WithKind("Entry")
	name := managed.ControllerName(kind.String())
	options := []managed.ReconcilerOption{
		managed.WithExternalConnector(&ldapConnector{kube: mgr.GetClient(), tracker: resource.NewProviderConfigUsageTracker(mgr.GetClient(), &configapi.ProviderConfigUsage{})}),
		managed.WithInitializers(&dnInitializer{kube: mgr.GetClient()}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithTimeout(time.Minute), managed.WithPollInterval(o.PollInterval), managed.WithManagementPolicies(),
		managed.WithCreationGracePeriod(0), managed.WithDeterministicExternalName(true),
	}
	return managed.NewReconciler(mgr, resource.ManagedKind(kind), append(options, extra...)...)
}

// Deletion must enqueue immediately, even when its metadata update does not change generation.
func entryEventFilter() predicate.Predicate {
	return predicate.Or(resource.DesiredStateChanged(), predicate.Funcs{UpdateFunc: func(e crevent.UpdateEvent) bool {
		return e.ObjectOld.GetDeletionTimestamp().IsZero() && !e.ObjectNew.GetDeletionTimestamp().IsZero()
	}})
}
func setupEntryController(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(entryapi.CRDGroupVersion.WithKind("Entry").String())
	r := newEntryReconciler(mgr, o)
	return ctrl.NewControllerManagedBy(mgr).Named(name).WithOptions(o.ForControllerRuntime()).WithEventFilter(entryEventFilter()).For(&entryapi.Entry{}).Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}
func setupProviderConfigControllers(mgr ctrl.Manager) error {
	for _, pc := range []client.Object{&configapi.ProviderConfig{}, &configapi.ClusterProviderConfig{}} {
		kind := "ProviderConfig"
		if _, ok := pc.(*configapi.ClusterProviderConfig); ok {
			kind = "ClusterProviderConfig"
		}
		kinds := resource.ProviderConfigKinds{Config: configapi.SchemeBuilder.GroupVersion.WithKind(kind), Usage: configapi.SchemeBuilder.GroupVersion.WithKind("ProviderConfigUsage"), UsageList: configapi.SchemeBuilder.GroupVersion.WithKind("ProviderConfigUsageList")}
		if err := ctrl.NewControllerManagedBy(mgr).Named(providerconfig.ControllerName(kind)).For(pc).Watches(&configapi.ProviderConfigUsage{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
			usage := obj.(*configapi.ProviderConfigUsage)
			ref := usage.GetProviderConfigReference()
			if ref.Kind != kind {
				return nil
			}
			namespace := usage.Namespace
			if kind == "ClusterProviderConfig" {
				namespace = ""
			}
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: namespace, Name: ref.Name}}}
		})).Complete(providerconfig.NewReconciler(mgr, kinds)); err != nil {
			return err
		}
	}
	return nil
}
