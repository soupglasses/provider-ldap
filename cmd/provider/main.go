// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	xpcontroller "github.com/crossplane/crossplane-runtime/v2/pkg/controller"
	"github.com/crossplane/crossplane-runtime/v2/pkg/logging"
	"github.com/crossplane/crossplane-runtime/v2/pkg/ratelimiter"
	entryapi "github.com/soupglasses/provider-ldap/apis/namespaced/ldap/v1alpha1"
	configapi "github.com/soupglasses/provider-ldap/apis/namespaced/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	var interval time.Duration
	flag.DurationVar(&interval, "poll-interval", time.Minute, "External LDAP drift polling interval")
	flag.Parse()
	logger := zap.New(zap.UseDevMode(false))
	ctrl.SetLogger(logger)
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = entryapi.AddToScheme(scheme)
	_ = configapi.AddToScheme(scheme)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: ":8081", Client: client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}, &corev1.Namespace{}}}}})
	if err != nil {
		panic(err)
	}
	options := xpcontroller.Options{Logger: logging.NewLogrLogger(logger), GlobalRateLimiter: ratelimiter.NewGlobal(10), PollInterval: interval, MaxConcurrentReconciles: 4}
	if err = setupEntryController(mgr, options); err != nil {
		panic(err)
	}
	if err = setupProviderConfigControllers(mgr); err != nil {
		panic(err)
	}
	_ = mgr.AddHealthzCheck("healthz", healthz.Ping)
	_ = mgr.AddReadyzCheck("readyz", healthz.Ping)
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
