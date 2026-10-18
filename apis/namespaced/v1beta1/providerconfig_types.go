// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: MIT

// +kubebuilder:object:generate=true
// +groupName=ldap.ops.finnes.dev
package v1beta1

import (
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

type CredentialsReference struct {
	// Namespace is required for cluster configurations and local for namespaced configurations.
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace,omitempty"`
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}
type ProviderConfigSpec struct {
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int `json:"port"`
	// +kubebuilder:validation:MinLength=1
	BindDN string `json:"bindDN"`
	// TLSServerName selects the certificate name when it differs from the connection host.
	TLSServerName string `json:"tlsServerName,omitempty"`
	// +kubebuilder:default=true
	TLS                  bool                 `json:"tls"`
	CredentialsSecretRef CredentialsReference `json:"credentialsSecretRef"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:subresource:status
type ProviderConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ProviderConfigSpec        `json:"spec"`
	Status            xpv2.ProviderConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ProviderConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProviderConfig `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
type ClusterProviderConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ClusterProviderConfigSpec `json:"spec"`
	Status            xpv2.ProviderConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.tls && has(self.credentialsSecretRef.namespace) && size(self.credentialsSecretRef.namespace) > 0",message="shared credentials require TLS and an explicit secret namespace"
type ClusterProviderConfigSpec struct {
	ProviderConfigSpec `json:",inline"`
	// NamespaceSelector authorizes namespaces to use these shared credentials.
	// An empty selector is forbidden to prevent accidentally granting cluster-wide access.
	// +kubebuilder:validation:XValidation:rule="(has(self.matchLabels) && size(self.matchLabels) > 0) || (has(self.matchExpressions) && size(self.matchExpressions) > 0)",message="namespaceSelector must contain at least one label requirement"
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector"`
	// Entries must be direct children of one of these DNs and use a namespace-prefixed RDN.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MinLength=1
	AllowedBases []string `json:"allowedBases"`
}

// +kubebuilder:object:root=true
type ClusterProviderConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterProviderConfig `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced
type ProviderConfigUsage struct {
	metav1.TypeMeta               `json:",inline"`
	metav1.ObjectMeta             `json:"metadata,omitempty"`
	xpv2.TypedProviderConfigUsage `json:",inline"`
}

// +kubebuilder:object:root=true
type ProviderConfigUsageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProviderConfigUsage `json:"items"`
}

var SchemeBuilder = &scheme.Builder{GroupVersion: schema.GroupVersion{Group: "ldap.ops.finnes.dev", Version: "v1beta1"}}
var AddToScheme = SchemeBuilder.AddToScheme

func init() {
	SchemeBuilder.Register(&ProviderConfig{}, &ProviderConfigList{}, &ClusterProviderConfig{}, &ClusterProviderConfigList{}, &ProviderConfigUsage{}, &ProviderConfigUsageList{})
}
