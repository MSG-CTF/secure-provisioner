package k3s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestStoppedCleanupYieldsAfterOneObservationAndRetainsFinalizers(t *testing.T) {
	binding, namespace := deleteFixture()
	namespace.Spec.Finalizers = []corev1.FinalizerName{"kubernetes"}
	client := fake.NewSimpleClientset(namespace)
	deletes, getsAfterDelete := 0, 0
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		deletes++
		current := namespace.DeepCopy()
		now := metav1.Now()
		current.DeletionTimestamp = &now
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), current, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, nil
	})
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		if deletes > 0 {
			getsAfterDelete++
		}
		return false, nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := deleteTestAdapter(t, client).DeleteStoppedWorkload(ctx, deleteCommand(binding), binding)
	var pending *operations.ProgressPendingError
	if !errors.As(err, &pending) || ctx.Err() != nil || getsAfterDelete != 1 || deletes != 1 {
		t.Fatalf("normal finalization consumed the step deadline: error=%v context=%v lookups=%d deletes=%d", err, ctx.Err(), getsAfterDelete, deletes)
	}
	current, getErr := client.CoreV1().Namespaces().Get(context.Background(), binding.Namespace, metav1.GetOptions{})
	if getErr != nil || len(current.Spec.Finalizers) != 1 || current.Spec.Finalizers[0] != "kubernetes" {
		t.Fatal("finalizer was removed or pending namespace treated as absent", getErr)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "patch" || action.GetVerb() == "update" {
			t.Fatal("cleanup rewrote a finalizer")
		}
	}
	if err := client.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("namespaces"), "", binding.Namespace); err != nil {
		t.Fatal(err)
	}
	if err := deleteTestAdapter(t, client).DeleteStoppedWorkload(context.Background(), deleteCommand(binding), binding); err != nil {
		t.Fatal("confirmed namespace absence did not complete cleanup", err)
	}
}

func TestStoppedCleanupAlreadyDeletingUsesItsValidatedObservation(t *testing.T) {
	binding, namespace := deleteFixture()
	now := metav1.Now()
	namespace.DeletionTimestamp = &now
	client := fake.NewSimpleClientset(namespace)
	gets := 0
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		gets++
		return false, nil, nil
	})
	client.PrependReactor("delete", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatal("accepted deletion was submitted again")
		return true, nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := deleteTestAdapter(t, client).DeleteStoppedWorkload(ctx, deleteCommand(binding), binding)
	var pending *operations.ProgressPendingError
	if !errors.As(err, &pending) || ctx.Err() != nil || gets != 1 {
		t.Fatalf("validated progress was polled again: error=%v context=%v lookups=%d", err, ctx.Err(), gets)
	}
}

func TestStoppedCleanupKeepsInFlightLookupFailureOnFaultRetry(t *testing.T) {
	binding, namespace := deleteFixture()
	client := fake.NewSimpleClientset(namespace)
	deleted := false
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		deleted = true
		return true, nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		if !deleted {
			return false, nil, nil
		}
		<-ctx.Done()
		return true, nil, ctx.Err()
	})
	err := deleteTestAdapter(t, client).DeleteStoppedWorkload(ctx, deleteCommand(binding), binding)
	var pending *operations.ProgressPendingError
	if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &pending) {
		t.Fatalf("unresponsive API was reported as normal finalization: %v", err)
	}
}

func TestStoppedCleanupRejectsReplacementAfterDeleteAcceptance(t *testing.T) {
	binding, namespace := deleteFixture()
	client := fake.NewSimpleClientset(namespace)
	client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		replacement := namespace.DeepCopy()
		replacement.UID = "replacement-namespace"
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), replacement, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, nil
	})
	err := deleteTestAdapter(t, client).DeleteStoppedWorkload(context.Background(), deleteCommand(binding), binding)
	if runtimeErrorCode(t, err) != "RUNTIME_IDENTITY_MISMATCH" {
		t.Fatalf("replacement namespace was accepted: %v", err)
	}
}
