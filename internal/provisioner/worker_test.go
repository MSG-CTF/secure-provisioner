package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type workerProbeCluster struct {
	current      atomic.Int32
	maximum      atomic.Int32
	createCalls  atomic.Int32
	failuresLeft atomic.Int32
	permanent    bool
	release      <-chan struct{}
}

func (cluster *workerProbeCluster) create(ctx context.Context, instance Instance, _ Challenge, _ Reservation) (RuntimeResources, error) {
	cluster.createCalls.Add(1)
	current := cluster.current.Add(1)
	defer cluster.current.Add(-1)
	for {
		maximum := cluster.maximum.Load()
		if current <= maximum || cluster.maximum.CompareAndSwap(maximum, current) {
			break
		}
	}
	if cluster.permanent {
		return RuntimeResources{}, fmt.Errorf("%w: kata-qemu", ErrRuntimeClassUnavailable)
	}
	if cluster.failuresLeft.Add(-1) >= 0 {
		return RuntimeResources{}, errors.New("temporary K3s failure")
	}
	if cluster.release != nil {
		select {
		case <-ctx.Done():
			return RuntimeResources{}, ctx.Err()
		case <-cluster.release:
		}
	}
	return RuntimeResources{InstanceID: instance.InstanceID, Namespace: "ctf-" + instance.InstanceID, Endpoint: "http://127.0.0.1:1"}, nil
}

func (cluster *workerProbeCluster) verify(context.Context, RuntimeResources) error { return nil }
func (cluster *workerProbeCluster) delete(context.Context, string) error           { return nil }
func (cluster *workerProbeCluster) get(string) (RuntimeResources, bool) {
	return RuntimeResources{}, false
}

func TestWorkerNeverExceedsConfiguredConcurrency(t *testing.T) {
	release := make(chan struct{})
	cluster := &workerProbeCluster{release: release}
	service, dependencyServer := newWorkerTestService(t, cluster)
	defer dependencyServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for index := 1; index <= 25; index++ {
		request := workerCreateRequest(index)
		if _, err := service.AcceptCreate(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	service.StartWithOptions(ctx, WorkerOptions{Concurrency: 10, PollInterval: time.Millisecond, LeaseDuration: time.Second, MaximumRetries: 3, RetryBaseDelay: time.Millisecond})
	waitForCondition(t, 3*time.Second, func() bool { return cluster.current.Load() == 10 })
	if maximum := cluster.maximum.Load(); maximum > 10 {
		t.Fatalf("maximum concurrency = %d, want <= 10", maximum)
	}
	close(release)
}

func TestWorkerRetriesTemporaryFailure(t *testing.T) {
	cluster := &workerProbeCluster{}
	cluster.failuresLeft.Store(1)
	service, dependencyServer := newWorkerTestService(t, cluster)
	defer dependencyServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted, err := service.AcceptCreate(ctx, workerCreateRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	service.StartWithOptions(ctx, WorkerOptions{Concurrency: 1, PollInterval: time.Millisecond, LeaseDuration: time.Second, MaximumRetries: 3, RetryBaseDelay: 5 * time.Millisecond})
	waitForCondition(t, 3*time.Second, func() bool {
		operation, ok := service.GetOperation(accepted.OperationID)
		return ok && operation.Status == OperationSucceeded
	})
	if calls := cluster.createCalls.Load(); calls != 2 {
		t.Fatalf("create calls = %d, want 2", calls)
	}
}

func TestWorkerFailsPermanentErrorWithoutRetry(t *testing.T) {
	cluster := &workerProbeCluster{permanent: true}
	service, dependencyServer := newWorkerTestService(t, cluster)
	defer dependencyServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted, err := service.AcceptCreate(ctx, workerCreateRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	service.StartWithOptions(ctx, WorkerOptions{Concurrency: 1, PollInterval: time.Millisecond, LeaseDuration: time.Second, MaximumRetries: 3, RetryBaseDelay: time.Millisecond})
	waitForCondition(t, 3*time.Second, func() bool {
		operation, ok := service.GetOperation(accepted.OperationID)
		return ok && operation.Status == OperationFailed
	})
	if calls := cluster.createCalls.Load(); calls != 1 {
		t.Fatalf("create calls = %d, want 1", calls)
	}
}

func TestWorkerRenewsLeaseDuringLongOperation(t *testing.T) {
	release := make(chan struct{})
	cluster := &workerProbeCluster{release: release}
	service, dependencyServer := newWorkerTestService(t, cluster)
	defer dependencyServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted, err := service.AcceptCreate(ctx, workerCreateRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	service.StartWithOptions(ctx, WorkerOptions{
		Concurrency: 2, PollInterval: time.Millisecond, LeaseDuration: 50 * time.Millisecond,
		MaximumRetries: 3, RetryBaseDelay: time.Millisecond,
	})
	waitForCondition(t, time.Second, func() bool { return cluster.current.Load() == 1 })
	time.Sleep(120 * time.Millisecond)
	close(release)
	waitForCondition(t, time.Second, func() bool {
		operation, ok := service.GetOperation(accepted.OperationID)
		return ok && operation.Status == OperationSucceeded
	})
	time.Sleep(20 * time.Millisecond)
	if calls := cluster.createCalls.Load(); calls != 1 {
		t.Fatalf("create calls = %d, want exactly 1 while lease is renewed", calls)
	}
}

func newWorkerTestService(t *testing.T, cluster clusterAdapter) (*Service, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mock/v1/scheduler/reservations/{reservation_id}", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(Reservation{ReservationID: request.PathValue("reservation_id"), ClusterID: "cluster-1", Valid: true, CPUMillicores: 100, MemoryMiB: 64, EphemeralStorageMiB: 64})
	})
	mux.HandleFunc("GET /mock/v1/catalog/challenges/{challenge_id}", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(Challenge{ChallengeID: request.PathValue("challenge_id"), Image: "example.invalid/challenge@sha256:" + fmt.Sprintf("%064d", 1), ContainerPort: 8080, RuntimeClass: "runc"})
	})
	mux.HandleFunc("POST /", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	server := httptest.NewServer(mux)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newServiceWithStore(server.URL, logger, time.Hour, cluster, newMemoryStore()), server
}

func workerCreateRequest(index int) CreateRequest {
	return CreateRequest{
		RequestID: fmt.Sprintf("request-%d", index), InstanceID: fmt.Sprintf("instance-%d", index),
		TeamID: int64(index), ChallengeID: fmt.Sprintf("challenge-%d", index), ClusterID: "cluster-1",
		ReservationID: fmt.Sprintf("reservation-%d", index), CreatedBy: "test", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not satisfied before timeout")
}
