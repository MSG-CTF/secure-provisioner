package k3s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// shortcut: live tests use Node image status, use agent evidence if truncation hides cached fixtures.
func livePreparedImageNodes(registry *Registry) func(context.Context, string, string, []string) []string {
	return func(ctx context.Context, target, arch string, images []string) []string {
		cluster, err := registry.LookupForCreate(target)
		if err != nil {
			return nil
		}
		nodes, err := cluster.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil
		}
		var ready []string
		for _, node := range nodes.Items {
			if !imageNodeEligible(node, arch) {
				continue
			}
			cached := map[string]bool{}
			for _, image := range node.Status.Images {
				for _, name := range image.Names {
					cached[name] = true
				}
			}
			complete := true
			for _, image := range images {
				complete = complete && cached[image]
			}
			if complete {
				ready = append(ready, node.Name)
			}
		}
		return ready
	}
}

func TestLivePreparationFixtureUsesRealCachedNodeNames(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "actual-vm"}, Status: corev1.NodeStatus{
		NodeInfo:   corev1.NodeSystemInfo{OperatingSystem: "linux", Architecture: "amd64", BootID: "boot", MachineID: "machine"},
		Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		Images:     []corev1.ContainerImage{{Names: []string{"web-image", "db-image"}}},
	}}
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, fake.NewSimpleClientset(node))
	prepared := livePreparedImageNodes(registry)
	if got := prepared(context.Background(), "aws-dev", "AMD64", []string{"web-image", "db-image"}); len(got) != 1 || got[0] != "actual-vm" {
		t.Fatalf("real node missing: %+v", got)
	}
	if got := prepared(context.Background(), "aws-dev", "AMD64", []string{"web-image", "missing-image"}); len(got) != 0 {
		t.Fatalf("partial graph accepted: %+v", got)
	}
	if got := prepared(context.Background(), "aws-dev", "ARM64", []string{"web-image"}); len(got) != 0 {
		t.Fatalf("wrong platform accepted: %+v", got)
	}
}
