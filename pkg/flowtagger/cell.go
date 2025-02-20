package flowtagger

import (
	"fmt"

	"github.com/cilium/cilium/pkg/flowtagger/controller"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"flow-tagger",
	"Flow Tagger",
	cell.Provide(flowTaggerClient),
	cell.Invoke(flowTaggerRegister),
)

func flowTaggerClient(clientset k8sClient.Clientset) (*versioned.Clientset, error) {
	if !clientset.IsEnabled() {
		return nil, nil
	}

	flowTagerClient, err := versioned.NewForConfig(clientset.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("create flow tagger client: %v", err)
	}
	return flowTagerClient, nil
}

type flowTaggerParams struct {
	cell.In

	Lifecycle    cell.Lifecycle
	DaemonConfig *option.DaemonConfig
	ClientSet    k8sClient.Clientset
	FTClient     *versioned.Clientset
	IPCache      *ipcache.IPCache
}

func flowTaggerRegister(params flowTaggerParams) {
	// if !params.DaemonConfig.EnableHubble {
	// 	return
	// }

	var c *controller.Controller
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			c = controller.NewController(params.ClientSet, params.FTClient, params.IPCache)
			c.Start(ctx)
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			c.Stop()
			return nil
		},
	})
}
