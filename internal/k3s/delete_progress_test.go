package k3s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestAcceptedNamespaceDeletionUsesProgressOnlyAfterSuccessfulLookup(t *testing.T) {
	binding, namespace := deleteFixture()
	now := metav1.Now()
	namespace.DeletionTimestamp = &now
	client := fake.NewSimpleClientset(namespace)
	adapter := deleteTestAdapter(t, client)
	adapter.config.DeleteTimeout = 20 * time.Millisecond
	err := adapter.DeleteWorkload(context.Background(), deleteCommand(binding), binding)
	var pending *operations.ProgressPendingError
	if !errors.As(err, &pending) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("confirmed namespace still present must remain pending: %v", err)
	}
}

func TestNamespaceAPIStallDoesNotUseProgressRetry(t *testing.T) {
	for _, phase := range []string{"initial lookup", "after accepted delete"} {
		t.Run(phase, func(t *testing.T) {
			binding, namespace := deleteFixture()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			client := fake.NewSimpleClientset(namespace)
			gets := 0
			client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
				gets++
				if phase == "after accepted delete" && gets == 1 {
					return false, nil, nil
				}
				<-ctx.Done()
				return true, nil, ctx.Err()
			})
			client.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, nil
			})
			adapter := deleteTestAdapter(t, client)
			err := adapter.DeleteWorkload(ctx, deleteCommand(binding), binding)
			var pending *operations.ProgressPendingError
			if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &pending) {
				t.Fatalf("unresponsive namespace API was classified as progress: %v", err)
			}
		})
	}
}
