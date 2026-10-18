// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"time"

	"github.com/crossplane/crossplane-runtime/v2/pkg/feature"
	"github.com/crossplane/crossplane-runtime/v2/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/providerconfig"
	xpresource "github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	tjcontroller "github.com/crossplane/upjet/v2/pkg/controller"
	"github.com/crossplane/upjet/v2/pkg/controller/handler"
	"github.com/crossplane/upjet/v2/pkg/metrics"
	"github.com/crossplane/upjet/v2/pkg/terraform"
	ldapclient "github.com/l-with/terraform-provider-ldap/client"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	configapi "github.com/soupglasses/provider-ldap/apis/namespaced/v1beta1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crhandler "sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// LDAP sockets belong to one synchronous reconciliation. The SDK connector has no
// connection teardown, so close them through Crossplane's external client lifecycle.
type ldapConnector struct {
	tracker      *xpresource.ProviderConfigUsageTracker
	newConnector func(terraform.SetupFn) managed.ExternalConnector
}

func (c *ldapConnector) Connect(ctx context.Context, mg xpresource.Managed) (managed.ExternalClient, error) {
	var conn *ldapclient.Client
	connector := c.newConnector(func(ctx context.Context, k client.Client, mg xpresource.Managed) (terraform.Setup, error) {
		setup, err := setupLDAP(ctx, k, mg, c.tracker)
		if err == nil {
			conn = setup.Meta.(*ldapclient.Client)
		}
		return setup, err
	})
	external, err := connector.Connect(ctx, mg)
	if err != nil {
		if conn != nil {
			conn.Conn.Close()
		}
		return nil, err
	}
	return &ldapExternal{ExternalClient: external, conn: conn}, nil
}

type ldapExternal struct {
	managed.ExternalClient
	conn *ldapclient.Client
}

func (e *ldapExternal) Disconnect(ctx context.Context) error {
	if e.conn != nil {
		defer e.conn.Conn.Close()
	}
	return e.ExternalClient.Disconnect(ctx)
}

func setupEntryController(mgr ctrl.Manager, o tjcontroller.Options) error {
	kind := entryapi.CRDGroupVersion.WithKind("Entry")
	name := managed.ControllerName(kind.String())
	metricRecorder := metrics.NewMetricRecorder(kind, mgr, o.PollInterval)
	eventHandler := handler.NewEventHandler(handler.WithLogger(o.Logger.WithValues("gvk", kind)))
	connector := &ldapConnector{tracker: xpresource.NewProviderConfigUsageTracker(mgr.GetClient(), &configapi.ProviderConfigUsage{}), newConnector: func(setup terraform.SetupFn) managed.ExternalConnector {
		return tjcontroller.NewTerraformPluginSDKConnector(mgr.GetClient(), setup, o.Provider.Resources["ldap_entry"], o.OperationTrackerStore,
			tjcontroller.WithTerraformPluginSDKLogger(o.Logger),
			tjcontroller.WithTerraformPluginSDKMetricRecorder(metricRecorder),
			tjcontroller.WithTerraformPluginSDKManagementPolicies(o.Features.Enabled(feature.EnableBetaManagementPolicies)))
	}}
	r := managed.NewReconciler(mgr, xpresource.ManagedKind(kind),
		managed.WithExternalConnector(connector), managed.WithLogger(o.Logger),
		managed.WithFinalizer(tjcontroller.NewOperationTrackerFinalizer(o.OperationTrackerStore, xpresource.NewAPIFinalizer(mgr.GetClient(), managed.FinalizerName))),
		managed.WithInitializers(managed.NewNameAsExternalName(mgr.GetClient())),
		managed.WithTimeout(3*time.Minute), managed.WithPollInterval(o.PollInterval), managed.WithManagementPolicies())
	return ctrl.NewControllerManagedBy(mgr).Named(name).WithOptions(o.ForControllerRuntime()).
		WithEventFilter(xpresource.DesiredStateChanged()).Watches(&entryapi.Entry{}, eventHandler).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

func setupProviderConfigControllers(mgr ctrl.Manager) error {
	for _, pc := range []client.Object{&configapi.ProviderConfig{}, &configapi.ClusterProviderConfig{}} {
		kind := "ProviderConfig"
		if _, ok := pc.(*configapi.ClusterProviderConfig); ok {
			kind = "ClusterProviderConfig"
		}
		kinds := xpresource.ProviderConfigKinds{
			Config:    configapi.SchemeBuilder.GroupVersion.WithKind(kind),
			Usage:     configapi.SchemeBuilder.GroupVersion.WithKind("ProviderConfigUsage"),
			UsageList: configapi.SchemeBuilder.GroupVersion.WithKind("ProviderConfigUsageList"),
		}
		if err := ctrl.NewControllerManagedBy(mgr).Named(providerconfig.ControllerName(kind)).For(pc).
			Watches(&configapi.ProviderConfigUsage{}, crhandler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
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
