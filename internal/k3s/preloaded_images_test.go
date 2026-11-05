package k3s

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAdapterRejectsMissingPreparedImagesBeforeResourceMutations(t *testing.T) {
	for _, configured := range []bool{false, true} {
		command := validMultiCreateCommand("aws-dev")
		client := readyMultiContainerClient(t, command)
		adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
		adapter.config.ReadyImageNodes = nil
		if configured {
			adapter.config.ReadyImageNodes = func(_ context.Context, target, arch string, images []string) []string {
				if target != "aws-dev" || arch != "AMD64" || len(images) != len(command.Containers) {
					t.Errorf("readiness lookup did not cover the whole workload: %s %s %+v", target, arch, images)
				}
				return nil
			}
		}
		_, err := adapter.CreateWorkload(context.Background(), command)
		if runtimeErrorCode(t, err) != "IMAGE_NOT_READY" {
			t.Fatalf("missing images error = %v", err)
		}
		var runtimeErr *RuntimeError
		if !errors.As(err, &runtimeErr) || !runtimeErr.Retryable() {
			t.Fatalf("missing preparation must be retryable: %v", err)
		}
		assertNoMutations(t, client.Actions())
	}
}

func TestAdapterRestrictsWholeWorkloadToPreparedNodes(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	client := readyMultiContainerClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	adapter.config.ReadyImageNodes = func(context.Context, string, string, []string) []string { return []string{"prepared-vm"} }
	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	namespace, _ := NamespaceForInstance(command.InstanceID)
	deployments, err := client.AppsV1().Deployments(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil || len(deployments.Items) != len(command.Containers) {
		t.Fatalf("deployments=%+v err=%v", deployments, err)
	}
	for _, deployment := range deployments.Items {
		pod := deployment.Spec.Template.Spec
		if pod.Containers[0].ImagePullPolicy != corev1.PullNever || pod.Affinity == nil || pod.Affinity.NodeAffinity == nil || pod.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
			t.Fatalf("deployment %s can fall back to an unprepared node or registry", deployment.Name)
		}
		terms := pod.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		if len(terms) != 1 || len(terms[0].MatchFields) != 1 || len(terms[0].MatchFields[0].Values) != 1 || terms[0].MatchFields[0].Values[0] != "prepared-vm" {
			t.Fatalf("deployment %s placement = %+v", deployment.Name, terms)
		}
	}
}
