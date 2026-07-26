package k3s

import (
	"context"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDeleteAdapterUsesOnlyStoredTarget(t *testing.T) {
	binding, namespace := deleteFixture()
	awsClient := fake.NewSimpleClientset(namespace)
	gcpClient := fake.NewSimpleClientset()
	registry, err := NewRegistry([]ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
		validClusterConfig("gcp-dev", ProviderGCP, "gcp-kubeconfig"),
	}, &sequenceFactory{clients: []kubernetes.Interface{awsClient, gcpClient}})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewDeleteAdapter(registry, DeleteAdapterConfig{DeleteTimeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	if err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
		t.Fatalf("DeleteWorkload() error = %v", err)
	}
	if len(gcpClient.Actions()) != 0 {
		t.Fatalf("gcp actions = %#v, want none", gcpClient.Actions())
	}
	if _, err := awsClient.CoreV1().Namespaces().Get(context.Background(), binding.Namespace, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("namespace Get() error = %v, want NotFound", err)
	}
}

func TestDeleteAdapterTreatsMissingNamespaceAsSuccess(t *testing.T) {
	binding, _ := deleteFixture()
	adapter := deleteTestAdapter(t, fake.NewSimpleClientset())

	if err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
		t.Fatalf("DeleteWorkload() error = %v", err)
	}
}

func TestDeleteAdapterRejectsForeignInstanceOwnership(t *testing.T) {
	binding, namespace := deleteFixture()
	namespace.Labels["msgctf.io/instance-id"] = "foreign-instance"
	client := fake.NewSimpleClientset(namespace)
	adapter := deleteTestAdapter(t, client)

	err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding)
	if runtimeErrorCode(t, err) != "RUNTIME_OWNERSHIP_MISMATCH" {
		t.Fatalf("error = %v", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "delete" {
			t.Fatalf("foreign namespace received delete action: %#v", action)
		}
	}
}

func TestDeleteAdapterRejectsCommandBindingMismatch(t *testing.T) {
	binding, namespace := deleteFixture()
	client := fake.NewSimpleClientset(namespace)
	adapter := deleteTestAdapter(t, client)
	command := deleteCommand(binding)
	command.TargetID = "gcp-dev"

	err := adapter.DeleteWorkload(context.Background(), command, binding)
	if runtimeErrorCode(t, err) != "INSTANCE_BINDING_MISMATCH" {
		t.Fatalf("error = %v", err)
	}
	if len(client.Actions()) != 0 {
		t.Fatalf("client actions = %#v, want none", client.Actions())
	}
}

func TestDeleteAdapterAllowsRepeatedDeletion(t *testing.T) {
	binding, namespace := deleteFixture()
	adapter := deleteTestAdapter(t, fake.NewSimpleClientset(namespace))
	command := deleteCommand(binding)

	if err := adapter.DeleteWorkload(context.Background(), command, binding); err != nil {
		t.Fatalf("first DeleteWorkload() error = %v", err)
	}
	if err := adapter.DeleteWorkload(context.Background(), command, binding); err != nil {
		t.Fatalf("second DeleteWorkload() error = %v", err)
	}
}

func deleteFixture() (runtimebinding.Binding, *corev1.Namespace) {
	binding := runtimebinding.Binding{
		InstanceID:        "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:            18,
		TargetID:          "aws-dev",
		Namespace:         "ctf-018f3f1e21b87a91a30b63b3400fd001",
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		State:             runtimebinding.StateCreated,
		CreatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: binding.Namespace,
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "secure-provisioner",
			"msgctf.io/instance-id":        binding.InstanceID,
			"msgctf.io/team-id":            "18",
		},
	}}
	return binding, namespace
}

func deleteCommand(binding runtimebinding.Binding) provisioner.DeleteWorkloadCommand {
	return provisioner.DeleteWorkloadCommand{
		RequestID:         "delete-request-01",
		InstanceID:        binding.InstanceID,
		TeamID:            binding.TeamID,
		RuntimeType:       provisioner.RuntimeTypeKubernetes,
		TargetID:          binding.TargetID,
		RuntimeWorkloadID: binding.RuntimeWorkloadID,
		Reason:            provisioner.DeleteReasonUserRequested,
	}
}

func deleteTestAdapter(t *testing.T, client kubernetes.Interface) *DeleteAdapter {
	t.Helper()
	registry, err := NewRegistry(
		[]ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")},
		&sequenceFactory{clients: []kubernetes.Interface{client}},
	)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewDeleteAdapter(registry, DeleteAdapterConfig{DeleteTimeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}
