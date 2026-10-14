package k3s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestFailedCreateRetriesCleanupWithoutCreatingAgain(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	client.PrependReactor("create", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("apply failed") })
	deletionBlocked := true
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		if deletionBlocked {
			return true, nil, errors.New("delete temporarily unavailable")
		}
		return false, nil, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{Type: operations.OperationTypeCreate, CreateCommand: &command}
	_, failure := executor.Execute(context.Background(), operation)
	var pending interface {
		PendingCreateCleanup() provisioner.CreateCleanup
	}
	if !errors.As(failure, &pending) || pending.PendingCreateCleanup().NamespaceUID == "" {
		t.Fatal("owned namespace UID was not retained")
	}
	checkpoint := pending.PendingCreateCleanup()
	operation.Result.CreateCleanup = &checkpoint
	deletionBlocked = false
	_, failure = executor.Execute(context.Background(), operation)
	var complete interface{ CreateCleanupCompleted() bool }
	if !errors.As(failure, &complete) || !complete.CreateCleanupCompleted() {
		t.Fatal("cleanup was not confirmed")
	}
	assertCreateActionCount(t, client, "namespaces", 1)
}

func TestFailedCreateCleanupPreservesReplacementNamespace(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Namespace.UID = "replacement"
	client := fake.NewSimpleClientset(resources.Namespace)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	failure := adapter.CleanupFailedCreate(context.Background(), command, provisioner.CreateCleanup{NamespaceUID: "original", FailureCode: "WORKLOAD_NOT_READY"})
	var proof interface{ CreateCleanupCompleted() bool }
	if errors.As(failure, &proof) {
		t.Fatal("replacement namespace must not confirm cleanup")
	}
	if _, err := client.CoreV1().Namespaces().Get(t.Context(), resources.Namespace.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("replacement namespace was removed")
	}
}

func TestCleanupProofRequiresNamespaceDeletion(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		resources, err := BuildResourceSet(validCluster("aws-dev"), validCreateCommand("aws-dev"))
		if err != nil {
			t.Fatal(err)
		}
		client := fake.NewSimpleClientset(resources.Namespace)
		if blocked {
			client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("delete failed") })
		}
		adapter := &Adapter{config: AdapterConfig{RollbackTimeout: time.Second, PollInterval: time.Millisecond}}
		failure := adapter.failWithRollback(client, resources.Namespace, "WORKLOAD_NOT_READY", errors.New("readiness failed"))
		var proof interface{ CreateCleanupCompleted() bool }
		if got := errors.As(classifyRuntimeExecutionError(failure), &proof); got == blocked {
			t.Fatalf("blocked=%v proof=%v", blocked, got)
		}
		if !blocked {
			namespaces, _ := client.CoreV1().Namespaces().List(t.Context(), metav1.ListOptions{})
			if len(namespaces.Items) != 0 {
				t.Fatal("namespace remains")
			}
		}
	}
}
