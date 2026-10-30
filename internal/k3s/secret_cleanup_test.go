package k3s

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

type failingSecretCallback func()

func (callback failingSecretCallback) Resolve(context.Context, string, string, string) (map[string]string, error) {
	callback()
	return nil, newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
}

func TestSecretFailureConfirmsCleanupOnlyAfterFreshNamespaceAbsence(t *testing.T) {
	for _, state := range []string{"absent", "namespace_appeared", "forbidden", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			command.Containers[0].SecretRef = testBackendSecretRef
			client := readyClient(t, command)
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "unused")}, client))
			namespace, _ := NamespaceForInstance(command.InstanceID)
			resolved := false
			adapter.config.Secrets = failingSecretCallback(func() { resolved = true })
			readsAfterResolution := 0
			client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
				if !resolved {
					return false, nil, nil
				}
				readsAfterResolution++
				switch state {
				case "namespace_appeared":
					return true, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, UID: "another-attempt"}}, nil
				case "forbidden":
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, namespace, errors.New("denied"))
				case "unavailable":
					return true, nil, apierrors.NewServiceUnavailable("unavailable")
				default:
					return false, nil, nil
				}
			})
			_, failure := adapter.CreateWorkloadForOperation(t.Context(), command, "secret-failure-operation")
			if runtimeErrorCode(t, failure) != "SECRET_RESOLUTION_FAILED" || readsAfterResolution != 1 {
				t.Fatalf("failure=%v fresh reads=%d", failure, readsAfterResolution)
			}
			var proof interface{ CreateCleanupCompleted() bool }
			confirmed := errors.As(failure, &proof) && proof.CreateCleanupCompleted()
			if confirmed != (state == "absent") {
				t.Fatalf("state=%s cleanup confirmed=%v", state, confirmed)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" {
					t.Fatalf("secret failure mutated Kubernetes: %s", action.GetVerb())
				}
			}
		})
	}
}

func TestMissingFlagReferenceConfirmsAbsentNamespace(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "unused")}, client))
	adapter.requiredFlagImages[command.Containers[0].Image] = true
	_, failure := adapter.CreateWorkloadForOperation(t.Context(), command, "missing-flag-operation")
	var proof interface{ CreateCleanupCompleted() bool }
	if runtimeErrorCode(t, failure) != "SECRET_RESOLUTION_FAILED" || !errors.As(failure, &proof) || !proof.CreateCleanupCompleted() {
		t.Fatalf("missing reference did not confirm absent namespace: %v", failure)
	}
}

func TestSecretFailureDoesNotConfirmCleanupWithoutTarget(t *testing.T) {
	command := validCreateCommand("missing")
	client := readyClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "unused")}, client))
	failure := adapter.failBeforeNamespace(command, newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil))
	var proof interface{ CreateCleanupCompleted() bool }
	if errors.As(failure, &proof) {
		t.Fatal("unknown target incorrectly confirmed cleanup")
	}
	if len(client.Actions()) != 0 {
		t.Fatal("unknown target caused Kubernetes access")
	}
}

var _ SecretResolver = failingSecretCallback(nil)
