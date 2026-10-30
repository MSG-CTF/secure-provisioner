package k3s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// Regression: Kubernetes may commit a Namespace while the Runtime loses the
// Create response or exits before it can checkpoint the observed UID in DB.
func TestReclaimedCreateCleansNamespaceCommittedBeforeResponse(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	client.PrependReactor("create", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		created := action.(k8stesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
		created.UID = types.UID("committed-namespace-uid")
		created.ResourceVersion = "17"
		if err := client.Tracker().Create(action.GetResource(), created, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, context.DeadlineExceeded
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{ID: "operation-123", Type: operations.OperationTypeCreate, CreateCommand: &command}
	if _, err := executor.Execute(context.Background(), operation); err == nil {
		t.Fatal("first create unexpectedly succeeded after lost Namespace response")
	}
	namespaceName, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := client.CoreV1().Namespaces().Get(t.Context(), namespaceName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := namespace.Annotations["msgctf.io/operation-id"]; got != operation.ID {
		t.Fatalf("durable Namespace operation proof = %q, want %q", got, operation.ID)
	}
	client.PrependReactor("delete", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		preconditions := action.(k8stesting.DeleteAction).GetDeleteOptions().Preconditions
		if preconditions == nil || preconditions.UID == nil || *preconditions.UID != types.UID("committed-namespace-uid") ||
			preconditions.ResourceVersion == nil || *preconditions.ResourceVersion != "17" {
			t.Errorf("recovery delete preconditions = %#v, want observed UID and ResourceVersion", preconditions)
		}
		return false, nil, nil
	})
	operation.CreateLeaseReclaimed = true
	if _, err := executor.Execute(context.Background(), operation); err == nil {
		t.Fatal("reclaimed create unexpectedly succeeded instead of cleaning incomplete attempt")
	}
	if _, err := client.CoreV1().Namespaces().Get(t.Context(), namespaceName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("incomplete Namespace remains after recovery: %v", err)
	}
	assertCreateActionCount(t, client, "namespaces", 1)
	assertDeleteActionCount(t, client, "namespaces", 1)
	assertNoChildResourceMutations(t, client.Actions())
}

func TestReclaimedCreatePreservesNamespaceFromDifferentOperation(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Namespace.Annotations = map[string]string{"msgctf.io/operation-id": "different-operation"}
	resources.Namespace.UID = types.UID("foreign-namespace-uid")
	resources.Namespace.ResourceVersion = "23"
	client := fake.NewSimpleClientset(resources.Namespace)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{ID: "operation-123", Type: operations.OperationTypeCreate, CreateCommand: &command, CreateLeaseReclaimed: true}
	_, err = executor.Execute(context.Background(), operation)
	if code, _ := operations.ClassifyExecutionError(err); code != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("wrong-operation Namespace error code = %q, want RESOURCE_OWNERSHIP_CONFLICT", code)
	}
	if _, err := client.CoreV1().Namespaces().Get(t.Context(), resources.Namespace.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign Namespace was removed: %v", err)
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
	assertNoChildResourceMutations(t, client.Actions())
}

func TestReclaimedCreateCleansNamespaceAfterTargetDisabled(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Namespace.Annotations = map[string]string{"msgctf.io/operation-id": "operation-123"}
	resources.Namespace.UID = types.UID("committed-namespace-uid")
	resources.Namespace.ResourceVersion = "17"
	client := fake.NewSimpleClientset(resources.Namespace)
	config := validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")
	config.Enabled = false
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{config}, client))
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{ID: "operation-123", Type: operations.OperationTypeCreate, CreateCommand: &command, CreateLeaseReclaimed: true}
	if _, err := executor.Execute(context.Background(), operation); err == nil {
		t.Fatal("recovered create unexpectedly succeeded")
	}
	if _, err := client.CoreV1().Namespaces().Get(t.Context(), resources.Namespace.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("orphaned Namespace remains after target disabled: %v", err)
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestReclaimedCreateCleansNamespaceBeforeFlagPolicyRejectsCommand(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Namespace.Annotations = map[string]string{"msgctf.io/operation-id": "operation-123"}
	resources.Namespace.UID = types.UID("committed-namespace-uid")
	resources.Namespace.ResourceVersion = "17"
	client := fake.NewSimpleClientset(resources.Namespace)
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client)
	adapter, err := NewAdapter(registry, AdapterConfig{
		ReadyTimeout: time.Second, PollInterval: time.Millisecond,
		RequiredFlagImages: []string{command.Containers[0].Image},
	})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{ID: "operation-123", Type: operations.OperationTypeCreate, CreateCommand: &command, CreateLeaseReclaimed: true}
	if _, err := executor.Execute(context.Background(), operation); err == nil {
		t.Fatal("recovered create unexpectedly succeeded")
	}
	if _, err := client.CoreV1().Namespaces().Get(t.Context(), resources.Namespace.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("orphaned Namespace remains after flag policy change: %v", err)
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestReclaimedCreateRecordsExactUIDWhenRecoveryDeleteFails(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Namespace.Annotations = map[string]string{"msgctf.io/operation-id": "operation-123"}
	resources.Namespace.UID = types.UID("committed-namespace-uid")
	resources.Namespace.ResourceVersion = "17"
	client := fake.NewSimpleClientset(resources.Namespace)
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("delete temporarily unavailable")
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{ID: "operation-123", Type: operations.OperationTypeCreate, CreateCommand: &command, CreateLeaseReclaimed: true}
	_, err = executor.Execute(context.Background(), operation)
	var pending interface {
		PendingCreateCleanup() provisioner.CreateCleanup
	}
	if !errors.As(err, &pending) {
		t.Fatalf("recovery error = %v, want pending cleanup with observed Namespace UID", err)
	}
	if cleanup := pending.PendingCreateCleanup(); cleanup.NamespaceUID != "committed-namespace-uid" {
		t.Fatalf("pending cleanup UID = %q, want observed Namespace generation", cleanup.NamespaceUID)
	}
	if _, getErr := client.CoreV1().Namespaces().Get(t.Context(), resources.Namespace.Name, metav1.GetOptions{}); getErr != nil {
		t.Fatalf("failed cleanup unexpectedly removed Namespace: %v", getErr)
	}
}

func TestReclaimedCreateWaitsForOwnedTerminatingNamespace(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	deletionTime := metav1.NewTime(time.Unix(100, 0))
	resources.Namespace.Annotations = map[string]string{"msgctf.io/operation-id": "operation-123"}
	resources.Namespace.UID = types.UID("committed-namespace-uid")
	resources.Namespace.ResourceVersion = "17"
	resources.Namespace.DeletionTimestamp = &deletionTime
	client := fake.NewSimpleClientset(resources.Namespace)
	getCount := 0
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		getCount++
		if getCount == 3 {
			if err := client.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("namespaces"), "", resources.Namespace.Name); err != nil {
				t.Fatal(err)
			}
		}
		return false, nil, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{ID: "operation-123", Type: operations.OperationTypeCreate, CreateCommand: &command, CreateLeaseReclaimed: true}
	_, err = executor.Execute(context.Background(), operation)
	if code, _ := operations.ClassifyExecutionError(err); code != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("terminating Namespace recovery code = %q, want RESOURCE_APPLY_FAILED", code)
	}
	if _, err := client.CoreV1().Namespaces().Get(t.Context(), resources.Namespace.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("terminating Namespace remains after wait: %v", err)
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestReclaimedCreateRecordsTerminatingNamespaceWhenDeletionStalls(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	deletionTime := metav1.NewTime(time.Unix(100, 0))
	resources.Namespace.Annotations = map[string]string{"msgctf.io/operation-id": "operation-123"}
	resources.Namespace.UID = types.UID("committed-namespace-uid")
	resources.Namespace.ResourceVersion = "17"
	resources.Namespace.DeletionTimestamp = &deletionTime
	client := fake.NewSimpleClientset(resources.Namespace)
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client)
	adapter, err := NewAdapter(registry, AdapterConfig{
		ReadyTimeout: time.Second, PollInterval: time.Millisecond, RollbackTimeout: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{ID: "operation-123", Type: operations.OperationTypeCreate, CreateCommand: &command, CreateLeaseReclaimed: true}
	_, err = executor.Execute(context.Background(), operation)
	var pending interface {
		PendingCreateCleanup() provisioner.CreateCleanup
	}
	if !errors.As(err, &pending) {
		t.Fatalf("terminating Namespace recovery error = %v, want pending cleanup", err)
	}
	if cleanup := pending.PendingCreateCleanup(); cleanup.NamespaceUID != "committed-namespace-uid" {
		t.Fatalf("pending cleanup UID = %q, want terminating generation", cleanup.NamespaceUID)
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestReclaimedCreateRejectsTerminatingNamespaceWithoutExactProof(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*corev1.Namespace)
	}{
		{name: "different operation", change: func(namespace *corev1.Namespace) {
			namespace.Annotations["msgctf.io/operation-id"] = "different-operation"
		}},
		{name: "different owner", change: func(namespace *corev1.Namespace) {
			namespace.Labels["msgctf.io/team-id"] = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "missing UID", change: func(namespace *corev1.Namespace) { namespace.UID = "" }},
		{name: "missing resource version", change: func(namespace *corev1.Namespace) { namespace.ResourceVersion = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if err != nil {
				t.Fatal(err)
			}
			deletionTime := metav1.NewTime(time.Unix(100, 0))
			resources.Namespace.Annotations = map[string]string{"msgctf.io/operation-id": "operation-123"}
			resources.Namespace.UID = types.UID("committed-namespace-uid")
			resources.Namespace.ResourceVersion = "17"
			resources.Namespace.DeletionTimestamp = &deletionTime
			test.change(resources.Namespace)
			client := fake.NewSimpleClientset(resources.Namespace)
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
			executor, err := NewExecutor(adapter)
			if err != nil {
				t.Fatal(err)
			}
			operation := operations.Operation{ID: "operation-123", Type: operations.OperationTypeCreate, CreateCommand: &command, CreateLeaseReclaimed: true}
			_, err = executor.Execute(context.Background(), operation)
			if code, _ := operations.ClassifyExecutionError(err); code != "RESOURCE_OWNERSHIP_CONFLICT" {
				t.Fatalf("unsafe terminating Namespace error code = %q, want RESOURCE_OWNERSHIP_CONFLICT", code)
			}
			assertDeleteActionCount(t, client, "namespaces", 0)
		})
	}
}
