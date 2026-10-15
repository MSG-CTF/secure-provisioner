package k3s

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// These tests create only a uniquely named Namespace and require an explicit
// opt-in because they exercise deletion against a real K3s API server.
func TestK3sIntegrationReclaimedCreateRemovesCommittedNamespace(t *testing.T) {
	registry, client, targetID := liveRecoveryCluster(t)
	command, created := createLiveRecoveryNamespace(t, client, targetID, integrationUUID(t))

	adapter, err := NewAdapter(registry, AdapterConfig{
		ReadyTimeout: time.Minute, PollInterval: 200 * time.Millisecond, RollbackTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{
		ID: created.Annotations[operationIDAnnotation], Type: operations.OperationTypeCreate,
		CreateCommand: &command, CreateLeaseReclaimed: true,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, operation); err == nil {
		t.Fatal("reclaimed create unexpectedly succeeded")
	} else {
		if code, _ := operations.ClassifyExecutionError(err); code != "RESOURCE_APPLY_FAILED" {
			t.Fatalf("reclaimed create error code = %q, want RESOURCE_APPLY_FAILED: %v", code, err)
		}
		var complete interface{ CreateCleanupCompleted() bool }
		if !errors.As(err, &complete) || !complete.CreateCleanupCompleted() {
			t.Fatalf("reclaimed create did not confirm Namespace cleanup: %v", err)
		}
	}
	if _, err := client.CoreV1().Namespaces().Get(ctx, created.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("committed Namespace remains after reclaimed create: %v", err)
	}
}

func TestK3sIntegrationReclaimedCreatePreservesDifferentOperation(t *testing.T) {
	registry, client, targetID := liveRecoveryCluster(t)
	command, created := createLiveRecoveryNamespace(t, client, targetID, integrationUUID(t))

	adapter, err := NewAdapter(registry, AdapterConfig{
		ReadyTimeout: time.Minute, PollInterval: 200 * time.Millisecond, RollbackTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	operation := operations.Operation{
		ID: integrationUUID(t), Type: operations.OperationTypeCreate,
		CreateCommand: &command, CreateLeaseReclaimed: true,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, err = executor.Execute(ctx, operation)
	if code, _ := operations.ClassifyExecutionError(err); code != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("different-operation recovery code = %q, want RESOURCE_OWNERSHIP_CONFLICT: %v", code, err)
	}
	remaining, err := client.CoreV1().Namespaces().Get(ctx, created.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("different-operation Namespace was removed: %v", err)
	}
	if remaining.UID != created.UID || remaining.Annotations[operationIDAnnotation] != created.Annotations[operationIDAnnotation] {
		t.Fatalf("different-operation Namespace changed identity: UID=%q operation=%q", remaining.UID, remaining.Annotations[operationIDAnnotation])
	}
	deployments, err := client.AppsV1().Deployments(created.Name).List(ctx, metav1.ListOptions{})
	if err != nil || len(deployments.Items) != 0 {
		t.Fatalf("different-operation recovery touched child Deployments: count=%d error=%v", len(deployments.Items), err)
	}
}

func liveRecoveryCluster(t *testing.T) (*Registry, kubernetes.Interface, string) {
	t.Helper()
	if os.Getenv("K3S_INTEGRATION_RECOVERY") != "1" {
		t.Skip("live K3s Namespace recovery requires K3S_INTEGRATION_RECOVERY=1")
	}
	targetID := requireIntegrationEnv(t, "K3S_INTEGRATION_TARGET_ID")
	kubeconfig := requireIntegrationEnv(t, "K3S_INTEGRATION_KUBECONFIG")
	// The disabled target deliberately exercises LookupForMaintenance: recovery
	// must still remove an orphan after operators disable new creates.
	registry, err := NewRegistry([]ClusterConfig{{
		TargetID: targetID, Provider: ProviderLocal, Region: "local", Architecture: "amd64",
		KubeconfigPath: kubeconfig, PublicGateway: "http://127.0.0.1", Enabled: false,
	}}, KubeconfigClientFactory{})
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := registry.LookupForMaintenance(targetID)
	if err != nil {
		t.Fatal(err)
	}
	return registry, cluster.Client, targetID
}

func createLiveRecoveryNamespace(t *testing.T, client kubernetes.Interface, targetID, operationID string) (provisioner.CreateWorkloadCommand, *corev1.Namespace) {
	t.Helper()
	command := validCreateCommand(targetID)
	command.RequestID = integrationUUID(t)
	command.InstanceID = integrationUUID(t)
	name, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	created, err := client.CoreV1().Namespaces().Create(ctx, buildNamespace(command, name, operationID), metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteIntegrationNamespace(t, client, created) })
	if created.UID == "" || created.ResourceVersion == "" || created.Annotations[operationIDAnnotation] != operationID {
		t.Fatalf("K3s did not persist recovery proof: UID=%q RV=%q operation=%q", created.UID, created.ResourceVersion, created.Annotations[operationIDAnnotation])
	}
	return command, created
}
