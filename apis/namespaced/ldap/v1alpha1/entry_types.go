// SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:object:generate=true
// +groupName=ldap.finnes.dev
package v1alpha1

import (
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// AttributeOwnershipPolicy controls whether an attribute owns its complete set or only declared values.
// +kubebuilder:validation:Enum=Exact;Subset
type AttributeOwnershipPolicy string

const (
	AttributeOwnershipExact  AttributeOwnershipPolicy = "Exact"
	AttributeOwnershipSubset AttributeOwnershipPolicy = "Subset"
)

// EntryParameters declares attribute ownership. LDAP attribute names are case insensitive.
type EntryParameters struct {
	// DN is the desired distinguished name. Changes rename the same LDAP entry.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=8192
	DN string `json:"dn"`
	// Attributes declares desired values. Exact ownership is the default.
	// Subset ownership preserves unmanaged values and removes previously claimed values when omitted.
	// +optional
	// +kubebuilder:validation:MaxProperties=128
	Attributes map[string][]string `json:"attributes,omitempty"`
	// AttributeOwnership selects Exact (default) or Subset for keys in Attributes.
	// Secret references always use Exact ownership.
	// +optional
	// +kubebuilder:validation:MaxProperties=128
	AttributeOwnership map[string]AttributeOwnershipPolicy `json:"attributeOwnership,omitempty"`
	// AttributeSecretRefs owns a single value from a local Secret for each declared attribute.
	// Secret values are never copied to status or connection details.
	// +optional
	// +kubebuilder:validation:MaxProperties=128
	AttributeSecretRefs map[string]xpv2.LocalSecretKeySelector `json:"attributeSecretRefs,omitempty"`
	// AdditiveAttributes ensures values are present with atomic LDAP Add operations, preserving all other values.
	// +optional
	// +kubebuilder:validation:MaxProperties=128
	AdditiveAttributes map[string][]string `json:"additiveAttributes,omitempty"`
	// AbsentAttributes removes only these values, preserving all other values.
	// Values must be distinct from additive values under the directory's equality rules.
	// +optional
	// +kubebuilder:validation:MaxProperties=128
	AbsentAttributes map[string][]string `json:"absentAttributes,omitempty"`
}

type EntryObservation struct {
	// ObservedGeneration is acknowledged only after observing full external convergence.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// ObservedSecretVersions acknowledges verified Secret input versions; it contains no values.
	ObservedSecretVersions map[string]string `json:"observedSecretVersions,omitempty"`
	DN                     string            `json:"dn,omitempty"`
	UUID                   string            `json:"uuid,omitempty"`
}
type EntrySpec struct {
	xpv2.ManagedResourceSpec `json:",inline"`
	ForProvider              EntryParameters `json:"forProvider"`
}
type EntryStatus struct {
	// OwnedAttributeValues is a bounded durable intent ledger for inline Subset values.
	// It is persisted before directory writes and compacted only after verified observation.
	// Secret values are never recorded here.
	// +optional
	// +kubebuilder:validation:MaxProperties=256
	OwnedAttributeValues       map[string][]string `json:"ownedAttributeValues,omitempty"`
	xpv2.ManagedResourceStatus `json:",inline"`
	AtProvider                 EntryObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,ldap}
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="DN",type="string",JSONPath=".spec.forProvider.dn"
type Entry struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              EntrySpec   `json:"spec"`
	Status            EntryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type EntryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Entry `json:"items"`
}

var CRDGroupVersion = schema.GroupVersion{Group: "ldap.finnes.dev", Version: "v1alpha1"}
var SchemeBuilder = &scheme.Builder{GroupVersion: CRDGroupVersion}
var AddToScheme = SchemeBuilder.AddToScheme

func init() { SchemeBuilder.Register(&Entry{}, &EntryList{}) }
