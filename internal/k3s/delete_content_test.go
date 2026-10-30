package k3s

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func terminatingContentFixture() (runtimebinding.Binding, *corev1.Namespace, []runtime.Object) {
	binding, namespace := deleteFixture()
	now := metav1.NewTime(time.Now().Add(-time.Minute))
	namespace.DeletionTimestamp = &now
	namespace.Spec.Finalizers = []corev1.FinalizerName{"kubernetes"}
	metadata := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: binding.Namespace, UID: types.UID(name + "-uid"), ResourceVersion: "1", Labels: map[string]string{
			"app.kubernetes.io/managed-by": "secure-provisioner", "msgctf.io/instance-id": binding.InstanceID, "msgctf.io/team-id": string(binding.TeamID),
		}}
	}
	objects := []runtime.Object{namespace,
		&corev1.Secret{ObjectMeta: metadata("challenge-env")},
		&corev1.ServiceAccount{ObjectMeta: metadata("challenge-runtime")},
		&corev1.ResourceQuota{ObjectMeta: metadata("resources")},
		&corev1.LimitRange{ObjectMeta: metadata("limits")},
	}
	for i := range 4 {
		objects = append(objects, &networkingv1.NetworkPolicy{ObjectMeta: metadata(fmt.Sprintf("policy-%d", i))})
	}
	return binding, namespace, objects
}

func TestContentPreparationKeepsNamespaceAdmissionPropagationWindow(t *testing.T) {
	binding, namespace, objects := terminatingContentFixture()
	now := metav1.Now()
	namespace.DeletionTimestamp = &now
	client := fake.NewSimpleClientset(objects...)
	if err := prepareTerminatingNamespaceContent(context.Background(), client, namespace, binding); err != nil {
		t.Fatal(err)
	}
	if len(client.Actions()) != 0 {
		t.Fatal("preparation queried or mutated content during admission propagation")
	}
}

func TestTerminatingContentIsBoundedAndNeverCompletesBeforeNamespaceAbsence(t *testing.T) {
	binding, _, objects := terminatingContentFixture()
	client := fake.NewSimpleClientset(objects...)
	deletes := 0
	client.PrependReactor("delete", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetResource().Resource == "namespaces" {
			t.Fatal("accepted namespace deletion was resubmitted")
		}
		call := action.(k8stesting.DeleteAction)
		options := call.GetDeleteOptions()
		if options.GracePeriodSeconds != nil || options.PropagationPolicy == nil || *options.PropagationPolicy != metav1.DeletePropagationBackground ||
			options.Preconditions == nil || options.Preconditions.UID == nil || string(*options.Preconditions.UID) != call.GetName()+"-uid" ||
			options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != "1" {
			t.Fatalf("unsafe content deletion: %s %#v", call.GetName(), options)
		}
		deletes++
		return false, nil, nil
	})
	adapter := deleteTestAdapter(t, client)
	for range 6 {
		before := deletes
		err := adapter.DeleteStoppedWorkload(context.Background(), deleteCommand(binding), binding)
		var pending *operations.ProgressPendingError
		if !errors.As(err, &pending) || deletes-before > terminatingContentDeletesPerStep {
			t.Fatalf("content deletion completed or exceeded its budget: error=%v deletes=%d", err, deletes-before)
		}
	}
	if deletes != len(objects)-1 {
		t.Fatalf("owned content was not removed: deletes=%d", deletes)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "patch" || action.GetVerb() == "update" || action.GetVerb() == "create" {
			t.Fatal("cleanup mutated a finalizer or recreated content")
		}
	}
	if err := client.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("namespaces"), "", binding.Namespace); err != nil {
		t.Fatal(err)
	}
	if err := adapter.DeleteStoppedWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
		t.Fatal("confirmed namespace absence did not finish cleanup", err)
	}
}

func TestContentPreparationPreservesActiveNamespaceAndEveryPod(t *testing.T) {
	for _, active := range []bool{true, false} {
		t.Run(fmt.Sprintf("active=%t", active), func(t *testing.T) {
			binding, namespace, objects := terminatingContentFixture()
			if active {
				namespace.DeletionTimestamp = nil
			} else {
				objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unlabelled-pod", Namespace: binding.Namespace}})
			}
			client := fake.NewSimpleClientset(objects...)
			if err := prepareTerminatingNamespaceContent(context.Background(), client, namespace, binding); err != nil {
				t.Fatal(err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "delete" {
					t.Fatal("isolation controls were removed with an active namespace or remaining Pod")
				}
			}
		})
	}
}

func TestContentPreparationLeavesForeignAndFinalizedObjectsToController(t *testing.T) {
	binding, namespace, objects := terminatingContentFixture()
	secret := objects[1].(*corev1.Secret)
	secret.Labels["msgctf.io/team-id"] = "foreign-team"
	account := objects[2].(*corev1.ServiceAccount)
	account.Finalizers = []string{"example.test/protection"}
	client := fake.NewSimpleClientset(objects...)
	for range 6 {
		_ = prepareTerminatingNamespaceContent(context.Background(), client, namespace, binding)
	}
	for _, resource := range []string{"secrets", "serviceaccounts"} {
		for _, action := range client.Actions() {
			if action.GetVerb() == "delete" && action.GetResource().Resource == resource {
				t.Fatal("foreign or protected content was eagerly deleted")
			}
		}
	}
}

func TestContentPreparationRejectsNamespaceReplacementBeforeMutation(t *testing.T) {
	binding, namespace, objects := terminatingContentFixture()
	client := fake.NewSimpleClientset(objects...)
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		replacement := namespace.DeepCopy()
		replacement.UID = "replacement"
		return true, replacement, nil
	})
	err := prepareTerminatingNamespaceContent(context.Background(), client, namespace, binding)
	if runtimeErrorCode(t, err) != "RUNTIME_IDENTITY_MISMATCH" {
		t.Fatal("namespace replacement passed ownership validation", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "delete" {
			t.Fatal("content of a replacement namespace was deleted")
		}
	}
}

func TestContentPreparationFallbackAndActualFaultRemainDistinct(t *testing.T) {
	for _, failure := range []error{
		apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "networkpolicies"}, "", errors.New("limited role")),
		apierrors.NewServiceUnavailable("unavailable"),
	} {
		binding, namespace, objects := terminatingContentFixture()
		client := fake.NewSimpleClientset(objects...)
		client.PrependReactor("list", "networkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, failure })
		err := prepareTerminatingNamespaceContent(context.Background(), client, namespace, binding)
		var pending *operations.ProgressPendingError
		if apierrors.IsForbidden(failure) {
			if err != nil {
				t.Fatal("optional preparation did not fall back", err)
			}
		} else if err == nil || errors.As(err, &pending) {
			t.Fatal("actual API outage was hidden as cleanup progress", err)
		}
	}
}

func TestContentPreparationPreservesTimeoutFault(t *testing.T) {
	binding, namespace, objects := terminatingContentFixture()
	client := fake.NewSimpleClientset(objects...)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	client.PrependReactor("list", "networkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) { <-ctx.Done(); return true, nil, ctx.Err() })
	err := prepareTerminatingNamespaceContent(ctx, client, namespace, binding)
	var pending *operations.ProgressPendingError
	if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &pending) {
		t.Fatal("stalled API was classified as normal progress", err)
	}
}

func TestContentPreparationBudgetFallsBackWithoutCompletingCleanup(t *testing.T) {
	binding, _, objects := terminatingContentFixture()
	client := fake.NewSimpleClientset(objects...)
	client.PrependReactor("list", "networkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		time.Sleep(2 * terminatingContentPreparationBudget)
		return true, nil, context.DeadlineExceeded
	})
	err := deleteTestAdapter(t, client).DeleteStoppedWorkload(context.Background(), deleteCommand(binding), binding)
	var pending *operations.ProgressPendingError
	if !errors.As(err, &pending) {
		t.Fatal("optional preparation budget inherited fault backoff or completed cleanup", err)
	}
	current, err := client.CoreV1().Namespaces().Get(context.Background(), binding.Namespace, metav1.GetOptions{})
	if err != nil || string(current.UID) != binding.NamespaceUID || len(current.Spec.Finalizers) != 1 {
		t.Fatal("preparation timeout lost namespace ownership or its finalizer", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "delete" {
			t.Fatal("preparation continued mutating after its budget expired")
		}
	}
}
