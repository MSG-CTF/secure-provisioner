package k3s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func stoppedNamespaceFixture() (runtimebinding.Binding, *corev1.Namespace, *appsv1.Deployment, *appsv1.ReplicaSet, *corev1.Service) {
	binding, namespace := deleteFixture()
	metadata := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: binding.Namespace, UID: types.UID(name + "-uid"), ResourceVersion: "9", Labels: map[string]string{
			"msgctf.io/instance-id":        binding.InstanceID,
			"msgctf.io/team-id":            string(binding.TeamID),
			"app.kubernetes.io/managed-by": "secure-provisioner",
		}}
	}
	zero := int32(0)
	return binding, namespace,
		&appsv1.Deployment{ObjectMeta: metadata("web"), Spec: appsv1.DeploymentSpec{Replicas: &zero}},
		&appsv1.ReplicaSet{ObjectMeta: metadata("web-rs"), Spec: appsv1.ReplicaSetSpec{Replicas: &zero}},
		&corev1.Service{ObjectMeta: metadata("web-service")}
}

func TestDeletePreparesStoppedResourcesWithIdentityPreconditions(t *testing.T) {
	binding, namespace, deployment, replicaSet, service := stoppedNamespaceFixture()
	client := fake.NewSimpleClientset(namespace, deployment, replicaSet, service)
	deleted := map[string]bool{}
	client.PrependReactor("delete", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		resource := action.GetResource().Resource
		if resource == "namespaces" {
			if len(deleted) != 3 {
				t.Fatal("namespace submitted before stopped resources")
			}
			return false, nil, nil
		}
		call := action.(k8stesting.DeleteAction)
		options := call.GetDeleteOptions()
		if options.GracePeriodSeconds != nil || options.PropagationPolicy == nil || *options.PropagationPolicy != metav1.DeletePropagationBackground || options.Preconditions == nil || options.Preconditions.UID == nil || string(*options.Preconditions.UID) != call.GetName()+"-uid" || options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != "9" {
			t.Fatalf("unsafe stopped resource deletion: %s %#v", resource, options)
		}
		deleted[resource] = true
		return false, nil, nil
	})
	if err := deleteTestAdapter(t, client).DeleteWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
		t.Fatal(err)
	}
}

func TestDeletePreparationPreservesPodGraceAndActiveControllers(t *testing.T) {
	for _, reason := range []string{"pod", "deployment", "replicaset"} {
		t.Run(reason, func(t *testing.T) {
			binding, namespace, deployment, replicaSet, service := stoppedNamespaceFixture()
			objects := []runtime.Object{namespace, deployment, replicaSet, service}
			one := int32(1)
			switch reason {
			case "pod":
				objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "still-terminating", Namespace: binding.Namespace, Finalizers: []string{"test.example/pod-protection"}}})
			case "deployment":
				deployment.Spec.Replicas = &one
			case "replicaset":
				replicaSet.Spec.Replicas = &one
			}
			client := fake.NewSimpleClientset(objects...)
			client.PrependReactor("delete", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.GetResource().Resource != "namespaces" {
					t.Fatal("active or protected workload received eager deletion")
				}
				return false, nil, nil
			})
			if err := deleteTestAdapter(t, client).DeleteWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeletePreparationDoesNotTouchReplacementNamespace(t *testing.T) {
	binding, namespace, deployment, replicaSet, service := stoppedNamespaceFixture()
	client := fake.NewSimpleClientset(namespace, deployment, replicaSet, service)
	client.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		replacement := namespace.DeepCopy()
		replacement.UID = "replacement"
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), replacement, ""); err != nil {
			t.Fatal(err)
		}
		return false, nil, nil
	})
	client.PrependReactor("delete", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatal("replacement namespace or its content was deleted")
		return true, nil, nil
	})
	err := deleteTestAdapter(t, client).DeleteWorkload(context.Background(), deleteCommand(binding), binding)
	if runtimeErrorCode(t, err) != "RUNTIME_IDENTITY_MISMATCH" {
		t.Fatal(err)
	}
}

func TestDeletePreparationSkipsForeignObjectsAndKeepsFinalizers(t *testing.T) {
	binding, namespace, deployment, replicaSet, service := stoppedNamespaceFixture()
	deployment.Labels["msgctf.io/team-id"] = "another-team"
	service.Finalizers = []string{"test.example/protection"}
	client := fake.NewSimpleClientset(namespace, deployment, replicaSet, service)
	client.PrependReactor("delete", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatal("foreign Deployment was eagerly deleted")
		return true, nil, nil
	})
	client.PrependReactor("delete", "services", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, nil })
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, nil })
	adapter := deleteTestAdapter(t, client)
	adapter.config.DeleteTimeout = 15 * time.Millisecond
	err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding)
	var pending *operations.ProgressPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("remaining finalizer was accepted as cleanup success: %v", err)
	}
	remaining, getErr := client.CoreV1().Services(binding.Namespace).Get(context.Background(), service.Name, metav1.GetOptions{})
	if getErr != nil || len(remaining.Finalizers) != 1 {
		t.Fatal("resource finalizer was changed", getErr)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "patch" || action.GetVerb() == "update" {
			t.Fatal("delete preparation modified an object or finalizer")
		}
	}
}

func TestDeletePreparationFallsBackWithNarrowChildResourceRBAC(t *testing.T) {
	for _, verb := range []string{"list", "delete"} {
		t.Run(verb, func(t *testing.T) {
			binding, namespace, deployment, replicaSet, service := stoppedNamespaceFixture()
			client := fake.NewSimpleClientset(namespace, deployment, replicaSet, service)
			client.PrependReactor(verb, "replicasets", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "replicasets"}, "", errors.New("restricted target"))
			})
			if err := deleteTestAdapter(t, client).DeleteWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeletePreparationRetriesPartialCleanupWithoutRecreatingResources(t *testing.T) {
	binding, namespace, deployment, replicaSet, service := stoppedNamespaceFixture()
	client := fake.NewSimpleClientset(namespace, deployment, replicaSet, service)
	calls := 0
	client.PrependReactor("delete", "replicasets", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 1 {
			return true, nil, apierrors.NewServiceUnavailable("temporary")
		}
		return false, nil, nil
	})
	adapter := deleteTestAdapter(t, client)
	first := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding)
	if first == nil {
		t.Fatal("partial cleanup was reported complete")
	}
	if _, err := client.CoreV1().Namespaces().Get(context.Background(), binding.Namespace, metav1.GetOptions{}); err != nil {
		t.Fatal("namespace was removed after preparation failed", err)
	}
	if err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
		t.Fatal(err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" {
			t.Fatal("cleanup retry recreated workload content")
		}
	}
}

func TestDeletePreparationKeepsStalledChildAPIOnFailureRetry(t *testing.T) {
	binding, namespace, deployment, replicaSet, service := stoppedNamespaceFixture()
	client := fake.NewSimpleClientset(namespace, deployment, replicaSet, service)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	client.PrependReactor("list", "replicasets", func(k8stesting.Action) (bool, runtime.Object, error) { <-ctx.Done(); return true, nil, ctx.Err() })
	err := deleteTestAdapter(t, client).DeleteWorkload(ctx, deleteCommand(binding), binding)
	var pending *operations.ProgressPendingError
	if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &pending) {
		t.Fatalf("stalled child API became normal progress: %v", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "delete" {
			t.Fatal("delete continued after an unresponsive child API")
		}
	}
}
