package k3s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
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

func TestDeleteAdapterRejectsNamespaceUIDMismatchBeforeDelete(t *testing.T) {
	binding, namespace := deleteFixture()
	namespace.UID = "replacement-namespace-uid"
	client := fake.NewSimpleClientset(namespace)
	adapter := deleteTestAdapter(t, client)

	err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding)
	if runtimeErrorCode(t, err) != "RUNTIME_IDENTITY_MISMATCH" {
		t.Fatalf("error = %v, want RUNTIME_IDENTITY_MISMATCH", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "delete" {
			t.Fatalf("replacement namespace received delete action: %#v", action)
		}
	}
}

func TestDeleteAdapterUsesNamespaceUIDAndResourceVersionPreconditions(t *testing.T) {
	binding, namespace := deleteFixture()
	client := fake.NewSimpleClientset(namespace)
	client.PrependReactor("delete", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		options := action.(k8stesting.DeleteAction).GetDeleteOptions()
		if options.Preconditions == nil || options.Preconditions.UID == nil ||
			string(*options.Preconditions.UID) != binding.NamespaceUID ||
			options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != namespace.ResourceVersion {
			t.Fatalf("delete preconditions = %#v, want UID %q and ResourceVersion %q", options.Preconditions, binding.NamespaceUID, namespace.ResourceVersion)
		}
		return false, nil, nil
	})
	adapter := deleteTestAdapter(t, client)

	if err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
		t.Fatalf("DeleteWorkload() error = %v", err)
	}
}

func TestDeleteAdapterRejectsNamespaceReplacementAfterPreconditionConflict(t *testing.T) {
	binding, namespace := deleteFixture()
	client := fake.NewSimpleClientset(namespace)
	deleteCalls := 0
	client.PrependReactor("delete", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteCalls++
		replacement := namespace.DeepCopy()
		replacement.UID = "replacement-namespace-uid"
		replacement.ResourceVersion = "12"
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), replacement, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "namespaces"}, binding.Namespace, errors.New("precondition mismatch"))
	})
	adapter := deleteTestAdapter(t, client)

	err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding)
	if runtimeErrorCode(t, err) != "RUNTIME_IDENTITY_MISMATCH" {
		t.Fatalf("error = %v, want RUNTIME_IDENTITY_MISMATCH", err)
	}
	if deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want one preconditioned attempt and no delete against replacement", deleteCalls)
	}
	remaining, getErr := client.CoreV1().Namespaces().Get(context.Background(), binding.Namespace, metav1.GetOptions{})
	if getErr != nil || string(remaining.UID) != "replacement-namespace-uid" {
		t.Fatalf("remaining namespace = %#v, error = %v", remaining, getErr)
	}
}

func TestDeleteAdapterRetriesConflictWhileNamespaceUIDIsStable(t *testing.T) {
	binding, namespace := deleteFixture()
	client := fake.NewSimpleClientset(namespace)
	deleteCalls := 0
	client.PrependReactor("delete", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteCalls++
		options := action.(k8stesting.DeleteAction).GetDeleteOptions()
		current, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("namespaces"), "", binding.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		currentNamespace := current.(*corev1.Namespace).DeepCopy()
		if options.Preconditions == nil || options.Preconditions.UID == nil ||
			string(*options.Preconditions.UID) != binding.NamespaceUID ||
			options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != currentNamespace.ResourceVersion {
			t.Fatalf("delete preconditions = %#v, current namespace = %#v", options.Preconditions, currentNamespace.ObjectMeta)
		}
		if deleteCalls == 1 {
			currentNamespace.ResourceVersion = "12"
			if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), currentNamespace, ""); err != nil {
				t.Fatal(err)
			}
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "namespaces"}, binding.Namespace, errors.New("stale resource version"))
		}
		return false, nil, nil
	})
	adapter := deleteTestAdapter(t, client)

	if err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
		t.Fatalf("DeleteWorkload() error = %v", err)
	}
	if deleteCalls != 2 {
		t.Fatalf("delete calls = %d, want 2", deleteCalls)
	}
}

func TestDeleteAdapterRejectsNamespaceReplacementDuringWait(t *testing.T) {
	binding, namespace := deleteFixture()
	client := fake.NewSimpleClientset(namespace)
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		replacement := namespace.DeepCopy()
		replacement.UID = "replacement-namespace-uid"
		replacement.ResourceVersion = "12"
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), replacement, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, nil
	})
	adapter := deleteTestAdapter(t, client)

	err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding)
	if runtimeErrorCode(t, err) != "RUNTIME_IDENTITY_MISMATCH" {
		t.Fatalf("error = %v, want RUNTIME_IDENTITY_MISMATCH", err)
	}
}

func TestDeleteAdapterClassifiesKubernetesAPIErrorsInEveryPhase(t *testing.T) {
	for _, apiError := range []struct {
		name      string
		err       error
		retryable bool
	}{
		{name: "forbidden", err: apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "challenge", errors.New("denied"))},
		{name: "unauthorized", err: apierrors.NewUnauthorized("authentication required")},
		{name: "bad request", err: apierrors.NewBadRequest("malformed request")},
		{name: "invalid", err: apierrors.NewInvalid(schema.GroupKind{Kind: "Namespace"}, "challenge", field.ErrorList{field.Invalid(field.NewPath("metadata", "name"), "challenge", "invalid")})},
		{name: "timeout", err: apierrors.NewTimeoutError("temporary timeout", 1), retryable: true},
	} {
		for _, phase := range []string{"initial-get", "delete", "wait-get"} {
			t.Run(apiError.name+"/"+phase, func(t *testing.T) {
				binding, namespace := deleteFixture()
				client := fake.NewSimpleClientset(namespace)
				switch phase {
				case "initial-get":
					client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
						return true, nil, apiError.err
					})
				case "delete":
					client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
						return true, nil, apiError.err
					})
				case "wait-get":
					client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
						return true, nil, nil
					})
					getCalls := 0
					client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
						getCalls++
						if getCalls == 1 {
							return false, nil, nil
						}
						return true, nil, apiError.err
					})
				}
				adapter := deleteTestAdapter(t, client)

				err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding)
				var runtimeErr *RuntimeError
				if !errors.As(err, &runtimeErr) || runtimeErr.Code() != "TARGET_TEMPORARILY_UNAVAILABLE" || runtimeErr.Retryable() != apiError.retryable {
					t.Fatalf("error = %#v, want TARGET_TEMPORARILY_UNAVAILABLE retryable=%t", err, apiError.retryable)
				}
				if !errors.Is(err, apiError.err) {
					t.Fatalf("error chain = %v, want Kubernetes cause %v", err, apiError.err)
				}
			})
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
		TeamID:            "00000000-0000-4000-8000-000000000018",
		TargetID:          "aws-dev",
		Namespace:         "ctf-018f3f1e21b87a91a30b63b3400fd001",
		NamespaceUID:      "namespace-uid-01",
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		State:             runtimebinding.StateCreated,
		CreatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:            binding.Namespace,
		UID:             "namespace-uid-01",
		ResourceVersion: "11",
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "secure-provisioner",
			"msgctf.io/instance-id":        binding.InstanceID,
			"msgctf.io/team-id":            "00000000-0000-4000-8000-000000000018",
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
