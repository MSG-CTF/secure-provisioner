package k3s

import (
	"context"
	"errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
	"time"
)

func TestQueuedVMRequiredImageCannotCreateKubernetesResources(t *testing.T) {
	for _, operationID := range []string{"", "accepted-before-policy-upgrade"} {
		command := validCreateCommand("aws-dev")
		client := readyClient(t, command)
		registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "unused")}, client)
		adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond,
			RequiresVMImage: func(image string) bool { return image == command.Containers[0].Image },
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = adapter.CreateWorkloadForOperation(context.Background(), command, operationID)
		if runtimeErrorCode(t, err) != "VM_POLICY_REJECTED" {
			t.Fatalf("queued image bypassed VM requirement: %v", err)
		}
		var cleaned interface{ CreateCleanupCompleted() bool }
		if !errors.As(err, &cleaned) || !cleaned.CreateCleanupCompleted() {
			t.Fatalf("absent namespace not confirmed: %v", err)
		}
		for _, action := range client.Actions() {
			if action.GetVerb() != "get" || action.GetResource().Resource != "namespaces" {
				t.Fatalf("VM rejection mutated/read workload resources: %v", action)
			}
		}
	}
}

func TestVMPolicyStillCleansInterruptedKubernetesAttempt(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Namespace.Annotations = map[string]string{"msgctf.io/operation-id": "old-create-operation"}
	resources.Namespace.UID = types.UID("owned-generation")
	resources.Namespace.ResourceVersion = "17"
	client := fake.NewSimpleClientset(resources.Namespace)
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "unused")}, client)
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond,
		RequiresVMImage: func(string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.CreateWorkloadForOperation(t.Context(), command, "old-create-operation")
	if err == nil {
		t.Fatal("interrupted K3s create succeeded after VM restriction")
	}
	if _, err := client.CoreV1().Namespaces().Get(t.Context(), resources.Namespace.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("owned namespace remains: %v", err)
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "update" || action.GetVerb() == "patch" {
			t.Fatalf("policy change recreated workload: %v", action)
		}
	}
}
