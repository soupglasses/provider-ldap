// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:object:generate=true
// +groupName=ldap.finnes.dev
package v1beta1

import (
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// ProviderCredentials selects a YAML or JSON connection document in a Secret.
// +kubebuilder:validation:XValidation:rule="has(self.secretRef) && !has(self.env) && !has(self.fs)",message="credentials must specify only a Secret reference"
type ProviderCredentials struct {
	// +kubebuilder:validation:Enum=Secret
	Source                         xpv2.CredentialsSource `json:"source"`
	xpv2.CommonCredentialSelectors `json:",inline"`
}
type ProviderConfigSpec struct {
	Credentials ProviderCredentials `json:"credentials"`
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

// +kubebuilder:validation:XValidation:rule="has(self.credentials.secretRef) && size(self.credentials.secretRef.namespace) > 0",message="shared credentials require an explicit secret namespace"
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

var SchemeBuilder = &scheme.Builder{GroupVersion: schema.GroupVersion{Group: "ldap.finnes.dev", Version: "v1beta1"}}
var AddToScheme = SchemeBuilder.AddToScheme

func init() {
	SchemeBuilder.Register(&ProviderConfig{}, &ProviderConfigList{}, &ClusterProviderConfig{}, &ClusterProviderConfigList{}, &ProviderConfigUsage{}, &ProviderConfigUsageList{})
}
