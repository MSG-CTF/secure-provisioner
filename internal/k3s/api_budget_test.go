package k3s

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/flowcontrol"
)

func TestLocalAPIBudgetBeforeCreateDoesNotAcquireCleanupHold(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	limiter := &lifecycleRateLimiter{flowcontrol.NewTokenBucketRateLimiter(1, 1)}
	limiter.TryAccept()
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, RateLimiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, budgetErr := client.CoreV1().Namespaces().Get(ctx, "not-dispatched", metav1.GetOptions{})
	if budgetErr == nil || requests.Load() != 0 || ctx.Err() != nil {
		t.Fatal("local budget fixture reached a server or expired", budgetErr)
	}
	command := validCreateCommand("aws-dev")
	backend := readyClient(t, command)
	backend.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, budgetErr
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "test")}, backend))
	_, err = adapter.CreateWorkload(context.Background(), command)
	var pending *operations.ProgressPendingError
	var held interface{ HoldRetry() bool }
	if err == nil || errors.As(err, &pending) || errors.As(err, &held) {
		t.Fatal("create before any namespace mutation acquired cleanup-only retry semantics", err)
	}
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) || !runtimeErr.Retryable() {
		t.Fatal("local budget failure stopped using bounded create retries", err)
	}
	for _, action := range backend.Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "delete" || action.GetVerb() == "patch" || action.GetVerb() == "update" {
			t.Fatal("creation mutated resources before a successful preflight")
		}
	}
	store := operations.NewMemoryStore(func() (string, error) { return "budget-create-operation", nil })
	op, _, err := store.EnqueueCreate(command, 1)
	if err != nil {
		t.Fatal(err)
	}
	executor := budgetCreateFailure{operations.NewExecutionError(runtimeErr.Code(), runtimeErr.Retryable(), runtimeErr)}
	worker, err := operations.NewWorker(store, executor, operations.WorkerConfig{Concurrency: 1, WorkerID: "budget-worker",
		PollInterval: time.Millisecond, LeaseDuration: time.Minute, RenewInterval: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	work, finish := context.WithTimeout(context.Background(), 3*time.Second)
	done := make(chan error, 1)
	go func() { done <- worker.Run(work) }()
	defer func() { finish(); <-done }()
	for work.Err() == nil {
		got, err := store.Get(op.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == operations.OperationStatusFailed {
			if got.Attempt != 1 {
				t.Fatalf("create retried beyond its one-attempt budget: %d", got.Attempt)
			}
			return
		}
		if got.Status == operations.OperationStatusRetrying {
			t.Fatal("create ignored its maximum attempts because of cleanup progress")
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("create did not reach its bounded failure state")
}

type budgetCreateFailure struct{ failure error }

func (executor budgetCreateFailure) Execute(context.Context, operations.Operation) (operations.OperationResult, error) {
	return operations.OperationResult{}, executor.failure
}

func TestKubernetesHTTPFailuresCannotMasqueradeAsLocalBudgetProgress(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		reason    metav1.StatusReason
		retryable bool
	}{
		{"bad request", 400, metav1.StatusReasonBadRequest, false},
		{"unauthorized", 401, metav1.StatusReasonUnauthorized, false},
		{"forbidden", 403, metav1.StatusReasonForbidden, false},
		{"conflict", 409, metav1.StatusReasonConflict, true},
		{"server rate limit", 429, metav1.StatusReasonTooManyRequests, true},
		{"server failure", 500, metav1.StatusReasonInternalError, true},
		{"server unavailable", 503, metav1.StatusReasonServiceUnavailable, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_ = json.NewEncoder(w).Encode(metav1.Status{
					TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
					Status:   "Failure", Code: int32(test.status), Reason: test.reason,
					Message: "KUBERNETES_API_BUDGET_BUSY: synthetic server error",
				})
			}))
			defer server.Close()
			clients, err := lifecycleClients(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = clients.Kubernetes.CoreV1().RESTClient().Get().AbsPath("/api/v1/namespaces/fault").MaxRetries(0).Do(ctx).Error()
			var pending *operations.ProgressPendingError
			classified := namespaceAPIError(err)
			var runtimeErr *RuntimeError
			if err == nil || errors.As(classified, &pending) || !errors.As(classified, &runtimeErr) || runtimeErr.Retryable() != test.retryable || requests.Load() != 1 {
				t.Fatalf("server failure became local progress or lost retry semantics: error=%v classified=%v requests=%d", err, classified, requests.Load())
			}
		})
	}
}

func TestLocalAPIBudgetDefersBeforeDispatchAndPreservesCancellation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	limiter := &lifecycleRateLimiter{flowcontrol.NewTokenBucketRateLimiter(1, 1)}
	if !limiter.TryAccept() {
		t.Fatal("empty initial budget")
	}
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, RateLimiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = client.CoreV1().Namespaces().Get(ctx, "not-dispatched", metav1.GetOptions{})
	var budget *lifecycleBudgetError
	if !errors.As(err, &budget) || ctx.Err() != nil || requests.Load() != 0 {
		t.Fatalf("local budget was a remote failure or sent HTTP: error=%v context=%v requests=%d", err, ctx.Err(), requests.Load())
	}
	var pending *operations.ProgressPendingError
	if !errors.As(namespaceAPIError(err), &pending) {
		t.Fatal("namespace error classification lost local admission progress")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := limiter.Wait(cancelled); !errors.Is(err, context.Canceled) || errors.As(err, &pending) {
		t.Fatal("cancelled parent became local budget progress", err)
	}
}

func TestActualKubernetesHTTPTimeoutIsNotLocalBudgetProgress(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL,
		RateLimiter: &lifecycleRateLimiter{flowcontrol.NewTokenBucketRateLimiter(20, 40)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = client.CoreV1().Namespaces().Get(ctx, "stalled-server", metav1.GetOptions{})
	var pending *operations.ProgressPendingError
	if err == nil || errors.As(err, &pending) || requests.Load() != 1 {
		t.Fatal("HTTP timeout was hidden as local API budget contention", err)
	}
}
