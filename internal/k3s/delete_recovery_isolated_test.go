package k3s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/google/uuid"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

func TestIsolatedNamespaceCleanupResumesAfterResponseLoss(t *testing.T) {
	config := isolatedCleanupConfig(t)
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	binding, namespace, _ := terminatingContentFixture()
	binding.InstanceID, binding.TeamID = uuid.NewString(), provisioner.TeamID(uuid.NewString())
	binding.Namespace, _ = NamespaceForInstance(binding.InstanceID)
	binding.RuntimeWorkloadID = RuntimeWorkloadID(binding.TargetID, binding.Namespace)
	namespace.Name, namespace.UID, namespace.ResourceVersion = binding.Namespace, "", ""
	namespace.DeletionTimestamp, namespace.Spec.Finalizers = nil, nil
	namespace.Labels = ownershipLabels(provisioner.CreateWorkloadCommand{InstanceID: binding.InstanceID, TeamID: binding.TeamID})
	created, err := client.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	binding.NamespaceUID = string(created.UID)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		uid := types.UID(binding.NamespaceUID)
		_ = client.CoreV1().Namespaces().Delete(cleanup, binding.Namespace, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	})
	var deleteRequests atomic.Int32
	var responseLost atomic.Bool
	config.WrapTransport = func(transport http.RoundTripper) http.RoundTripper {
		return cleanupRoundTripper(func(request *http.Request) (*http.Response, error) {
			response, err := transport.RoundTrip(request)
			if request.Method == http.MethodDelete && request.URL.Path == "/api/v1/namespaces/"+binding.Namespace {
				deleteRequests.Add(1)
				if err == nil && response.StatusCode >= 200 && response.StatusCode < 300 && responseLost.CompareAndSwap(false, true) {
					response.Body.Close()
					return nil, fmt.Errorf("synthetic response loss after accepted Namespace deletion")
				}
			}
			return response, err
		})
	}
	clients, err := lifecycleClients(config)
	if err != nil {
		t.Fatal(err)
	}
	adapter := deleteTestAdapter(t, clients.Kubernetes)
	err = adapter.DeleteStoppedWorkload(ctx, deleteCommand(binding), binding)
	var pending *operations.ProgressPendingError
	if !responseLost.Load() || err == nil || errors.As(err, &pending) {
		t.Fatal("accepted delete response loss was hidden or completed cleanup", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := adapter.DeleteStoppedWorkload(cancelled, deleteCommand(binding), binding); err == nil {
		t.Fatal("cancelled cleanup continued")
	}
	// Rebuild both the clients and adapter; only the stored binding survives.
	clients, err = lifecycleClients(config)
	if err != nil {
		t.Fatal(err)
	}
	adapter = deleteTestAdapter(t, clients.Kubernetes)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			for ctx.Err() == nil {
				step, finish := context.WithTimeout(ctx, 2*time.Second)
				err := adapter.DeleteStoppedWorkload(step, deleteCommand(binding), binding)
				finish()
				if err == nil {
					results <- nil
					return
				}
				var pending *operations.ProgressPendingError
				if !errors.As(err, &pending) {
					results <- err
					return
				}
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
				}
			}
			results <- ctx.Err()
		}()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal("cleanup could not resume from the stored binding", err)
		}
	}
	if _, err := client.CoreV1().Namespaces().Get(ctx, binding.Namespace, metav1.GetOptions{}); !apierrors.IsNotFound(err) || deleteRequests.Load() != 1 {
		t.Fatalf("duplicate retry resubmitted a delete or completed early: lookup=%v deletes=%d", err, deleteRequests.Load())
	}
	result, _ := json.Marshal(map[string]any{"accepted_delete_requests": deleteRequests.Load(), "duplicate_retries": 2,
		"not_found_results": 2, "cancelled_step_rejected": true, "production_test": false})
	t.Log("ISOLATED_NAMESPACE_RECOVERY=" + string(result))
}
