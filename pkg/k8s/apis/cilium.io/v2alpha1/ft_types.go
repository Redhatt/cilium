/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium}
// +kubebuilder:object:root=true

// PacketTagging describes the specification used by network logging.
// There can be at most one copy of this resource in the cluster.
// This will be enforced using validation proposed in
// https://github.com/kubernetes-sigs/kubebuilder/issues/1074
// If the resource does not exist, logging will be disabled.
type CiliumFlowTagger struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired configuration for flow tagger resource.
	Spec FlowTaggerSpec `json:"spec,omitempty"`

	// Status for the flow tagger
	Status FlowTaggerStatus `json:"status,omitempty"`
}

// FlowTaggerSpec provides the specification of the FlowTagger resource.
type FlowTaggerSpec struct {
	// Source IP address for the flow tagger
	SourceIP string `json:"sourceIP" validate:"required"`
	// Destination IP address for the flow tagger
	DestinationIP string `json:"destinationIP" validate:"required"`
	// Source port
	SourcePort uint16 `json:"sourcePort,omitempty"`
	// Destination port
	DestinationPort uint16 `json:"destPort,omitempty"`
	// Trace ID.
	TraceID uint64 `json:"traceID" validate:"required"`

	// The amount of time this flow tag is applied for. After the time is reached,
	// the flow tag is disabled.
	// If empty, this flow tagging is enabled for an hour by default.
	//
	// +optional
	Lifetime *Lifetime `json:"lifetime,omitempty"`
}

type Lifetime struct {
	// The time when this flow tag expires
	// and becomes inactive. Expiration must be a time in the future.
	//
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=date-time
	// +optional
	// +deepequal-gen=false
	Expiration *metav1.Time `json:"expiration,omitempty"`

	// The amount of time the flow tag will be active for, starting from
	// when it is reconciled.
	// +optional
	// +deepequal-gen=false
	Duration *metav1.Duration `json:"duration,omitempty"`
}

// Defines the observed state of the `FlowTagger` resource.
type FlowTaggerStatus struct {
	// The observed state of the `FlowTagger` resource.
	// If `ready` is `true`, it means that all flow tags are successfully applied.
	// If `ready` is `false`, it means that it failed to apply flow tag to some/all flows.
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=date-time
	// The time when this flow tag expires and becomes inactive.
	// +deepequal-gen=false
	Endtime *metav1.Time `json:"endTime,omitempty"`

	// TraceId assigned for this flow tagger.
	TraceID uint64 `json:"traceID" validate:"required"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumFlowTaggerList contains a list of `FlowTagger` objects.
type CiliumFlowTaggerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a slice of FlowTagger resources.
	Items []CiliumFlowTagger `json:"items"`
}
