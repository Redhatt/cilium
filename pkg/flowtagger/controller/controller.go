// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file keeps the logic for packettracing CRD controller.
// It watches the packettracing CRD and make the call
// to configure the loggers.
package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/flowtagger/taggeragent"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	klog "k8s.io/klog/v2"
)

const (
	informerSyncPeriod = 15 * time.Minute
	createOperation    = "create"
	updateOperation    = "update"
)

type Controller struct {
	kubeClient kubernetes.Interface

	flowtaggerClient   versioned.Interface
	flowtaggerInformer cache.SharedIndexInformer
	eventBroadcaster   record.EventBroadcaster
	eventRecorder      record.EventRecorder
	ipcache            *ipcache.IPCache

	stopCh chan struct{}

	taggeragent taggeragent.TaggingAgent
}

func NewController(clientset k8sClient.Clientset, flowtaggerClient versioned.Interface, ipcache *ipcache.IPCache, opts ...func(*Controller)) *Controller {
	broadcaster := record.NewBroadcaster()
	broadcaster.StartLogging(klog.Infof)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: clientset.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "flow-tagger-controller"})

	flowtaggerInformerFactory := externalversions.NewSharedInformerFactory(flowtaggerClient, informerSyncPeriod)

	c := &Controller{
		kubeClient:         clientset,
		flowtaggerClient:   flowtaggerClient,
		flowtaggerInformer: flowtaggerInformerFactory.Cilium().V2alpha1().CiliumFlowTaggers().Informer(),
		eventRecorder:      recorder,
		eventBroadcaster:   broadcaster,
		taggeragent:        *taggeragent.NewDefaultTaggingAgent(),
		ipcache:            ipcache,
		stopCh:             make(chan struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}

	c.flowtaggerInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.updateHandler(obj, createOperation) },
		UpdateFunc: func(old, curr interface{}) { c.updateHandler(curr, updateOperation) },
		DeleteFunc: c.delHandler,
	})

	// TODO: DONT KNOW :D
	// c.kubeClient.CoreV1().Services("default").Get()
	// c.kubeClient.CoreV1().Pods("default").Get()

	return c
}

func (c *Controller) validateObj(obj interface{}) (*v2alpha1.CiliumFlowTagger, error) {
	nl, ok := obj.(*v2alpha1.CiliumFlowTagger)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T", obj)
	}
	// TODO: implement the validation
	return nl, nil
}

func (c *Controller) updateHandler(obj interface{}, operation string) {
	o, err := c.validateObj(obj)
	if err != nil {
		// Note that when validation fails, although the CR is already in etcd, it doesn't
		// take effect and the system is still in the old state.
		klog.Errorf("Flow Tagger obj %v is invalid, err %v", obj, err)
		c.eventRecorder.Eventf(o, v1.EventTypeWarning, "InvalidFlowTagger", err.Error())
		return
	}

	sourceIdentity, ok := c.ipcache.LookupByIP(o.Spec.SourceIP)
	if !ok {
		err := fmt.Errorf("ip addr: %s not found in ipcache", o.Spec.SourceIP)
		klog.Errorf("Flow Tagger ipcache lookup, err %v", err)
		c.eventRecorder.Eventf(o, v1.EventTypeWarning, "KeyUpdateError ", err.Error())
		return
	}
	destinationIdentity, ok := c.ipcache.LookupByIP(o.Spec.DestinationIP)
	if !ok {
		err := fmt.Errorf("ip addr: %s not found in ipcache", o.Spec.DestinationIP)
		klog.Errorf("Flow Tagger ipcache lookup, err %v", err)
		c.eventRecorder.Eventf(o, v1.EventTypeWarning, "KeyUpdateError ", err.Error())
		return
	}

	packetTaggingKey := taggeragent.PacketTaggingKey{
		SourceID:        sourceIdentity.ID.String(),
		DestinationID:   destinationIdentity.ID.String(),
		SourcePort:      o.Spec.SourcePort,
		DestinationPort: o.Spec.DestinationPort,
		TraceID:         o.Spec.TraceID,
	}

	if err := c.taggeragent.AddKey(packetTaggingKey); err != nil {
		klog.Errorf("Flow Tagger key %v update, err %v", packetTaggingKey, err)
		c.eventRecorder.Eventf(o, v1.EventTypeWarning, "KeyUpdateError ", err.Error())
		return
	}
	c.eventRecorder.Eventf(o, v1.EventTypeNormal, "UpdatetFlowTagger",
		fmt.Sprintf("%sd packet tracing (resourceVersion = %s); %#v ", operation, o.ResourceVersion, packetTaggingKey))
}

func (c *Controller) delHandler(obj interface{}) {
	o, ok := obj.(*v2alpha1.CiliumFlowTagger)
	if !ok {
		deletedObj, deletedOk := obj.(cache.DeletedFinalStateUnknown)
		if deletedOk {
			o, ok = deletedObj.Obj.(*v2alpha1.CiliumFlowTagger)
		}
		if !ok {
			klog.Warningf("Cannot recover the deleted flow tagger obj %v", obj)
			return
		}
	}

	packetTaggingKey := taggeragent.PacketTaggingKey{
		SourceID:        o.Spec.SourceIP,
		DestinationID:   o.Spec.DestinationIP,
		SourcePort:      o.Spec.SourcePort,
		DestinationPort: o.Spec.DestinationPort,
		TraceID:         o.Spec.TraceID,
	}
	if err := c.taggeragent.DeleteKey(packetTaggingKey); err != nil {
		klog.Errorf("Flow Tagger key %v delete, err %v", packetTaggingKey, err)
		c.eventRecorder.Eventf(o, v1.EventTypeWarning, "KeyDeleteError ", err.Error())
		return
	}
	klog.Infof("Delete flow tagger obj %v", o)
	c.eventRecorder.Eventf(o, v1.EventTypeNormal, "DeleteFlowTagger",
		"deleted flow tagger")
}

// run starts flow tagger controller.
func (c *Controller) Start(ctx context.Context) {
	klog.Info("Starting flow tagger controller")
	go c.flowtaggerInformer.Run(c.stopCh)
	if ok := cache.WaitForNamedCacheSync("flow tagger", ctx.Done(), c.flowtaggerInformer.HasSynced); !ok {
		klog.Error("Failed to wait for flow tagger caches to sync")
		return
	}
}

func (c *Controller) Stop() {
	klog.Info("Shutting down flow tagger controller")
	close(c.stopCh)
}
