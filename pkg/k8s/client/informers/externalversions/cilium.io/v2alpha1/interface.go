// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by informer-gen. DO NOT EDIT.

package v2alpha1

import (
	internalinterfaces "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// CiliumBGPAdvertisements returns a CiliumBGPAdvertisementInformer.
	CiliumBGPAdvertisements() CiliumBGPAdvertisementInformer
	// CiliumBGPClusterConfigs returns a CiliumBGPClusterConfigInformer.
	CiliumBGPClusterConfigs() CiliumBGPClusterConfigInformer
	// CiliumBGPNodeConfigs returns a CiliumBGPNodeConfigInformer.
	CiliumBGPNodeConfigs() CiliumBGPNodeConfigInformer
	// CiliumBGPNodeConfigOverrides returns a CiliumBGPNodeConfigOverrideInformer.
	CiliumBGPNodeConfigOverrides() CiliumBGPNodeConfigOverrideInformer
	// CiliumBGPPeerConfigs returns a CiliumBGPPeerConfigInformer.
	CiliumBGPPeerConfigs() CiliumBGPPeerConfigInformer
	// CiliumBGPPeeringPolicies returns a CiliumBGPPeeringPolicyInformer.
	CiliumBGPPeeringPolicies() CiliumBGPPeeringPolicyInformer
	// CiliumCIDRGroups returns a CiliumCIDRGroupInformer.
	CiliumCIDRGroups() CiliumCIDRGroupInformer
	// CiliumEndpointSlices returns a CiliumEndpointSliceInformer.
	CiliumEndpointSlices() CiliumEndpointSliceInformer
	// CiliumFlowTaggers returns a CiliumFlowTaggerInformer.
	CiliumFlowTaggers() CiliumFlowTaggerInformer
	// CiliumGatewayClassConfigs returns a CiliumGatewayClassConfigInformer.
	CiliumGatewayClassConfigs() CiliumGatewayClassConfigInformer
	// CiliumL2AnnouncementPolicies returns a CiliumL2AnnouncementPolicyInformer.
	CiliumL2AnnouncementPolicies() CiliumL2AnnouncementPolicyInformer
	// CiliumLoadBalancerIPPools returns a CiliumLoadBalancerIPPoolInformer.
	CiliumLoadBalancerIPPools() CiliumLoadBalancerIPPoolInformer
	// CiliumNodeConfigs returns a CiliumNodeConfigInformer.
	CiliumNodeConfigs() CiliumNodeConfigInformer
	// CiliumPodIPPools returns a CiliumPodIPPoolInformer.
	CiliumPodIPPools() CiliumPodIPPoolInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// CiliumBGPAdvertisements returns a CiliumBGPAdvertisementInformer.
func (v *version) CiliumBGPAdvertisements() CiliumBGPAdvertisementInformer {
	return &ciliumBGPAdvertisementInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumBGPClusterConfigs returns a CiliumBGPClusterConfigInformer.
func (v *version) CiliumBGPClusterConfigs() CiliumBGPClusterConfigInformer {
	return &ciliumBGPClusterConfigInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumBGPNodeConfigs returns a CiliumBGPNodeConfigInformer.
func (v *version) CiliumBGPNodeConfigs() CiliumBGPNodeConfigInformer {
	return &ciliumBGPNodeConfigInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumBGPNodeConfigOverrides returns a CiliumBGPNodeConfigOverrideInformer.
func (v *version) CiliumBGPNodeConfigOverrides() CiliumBGPNodeConfigOverrideInformer {
	return &ciliumBGPNodeConfigOverrideInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumBGPPeerConfigs returns a CiliumBGPPeerConfigInformer.
func (v *version) CiliumBGPPeerConfigs() CiliumBGPPeerConfigInformer {
	return &ciliumBGPPeerConfigInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumBGPPeeringPolicies returns a CiliumBGPPeeringPolicyInformer.
func (v *version) CiliumBGPPeeringPolicies() CiliumBGPPeeringPolicyInformer {
	return &ciliumBGPPeeringPolicyInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumCIDRGroups returns a CiliumCIDRGroupInformer.
func (v *version) CiliumCIDRGroups() CiliumCIDRGroupInformer {
	return &ciliumCIDRGroupInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumEndpointSlices returns a CiliumEndpointSliceInformer.
func (v *version) CiliumEndpointSlices() CiliumEndpointSliceInformer {
	return &ciliumEndpointSliceInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumFlowTaggers returns a CiliumFlowTaggerInformer.
func (v *version) CiliumFlowTaggers() CiliumFlowTaggerInformer {
	return &ciliumFlowTaggerInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumGatewayClassConfigs returns a CiliumGatewayClassConfigInformer.
func (v *version) CiliumGatewayClassConfigs() CiliumGatewayClassConfigInformer {
	return &ciliumGatewayClassConfigInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumL2AnnouncementPolicies returns a CiliumL2AnnouncementPolicyInformer.
func (v *version) CiliumL2AnnouncementPolicies() CiliumL2AnnouncementPolicyInformer {
	return &ciliumL2AnnouncementPolicyInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumLoadBalancerIPPools returns a CiliumLoadBalancerIPPoolInformer.
func (v *version) CiliumLoadBalancerIPPools() CiliumLoadBalancerIPPoolInformer {
	return &ciliumLoadBalancerIPPoolInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CiliumNodeConfigs returns a CiliumNodeConfigInformer.
func (v *version) CiliumNodeConfigs() CiliumNodeConfigInformer {
	return &ciliumNodeConfigInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// CiliumPodIPPools returns a CiliumPodIPPoolInformer.
func (v *version) CiliumPodIPPools() CiliumPodIPPoolInformer {
	return &ciliumPodIPPoolInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
