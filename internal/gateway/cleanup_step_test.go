package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

type cleanupDeleteFunc func(context.Context) error

func (f cleanupDeleteFunc) DeleteWorkload(ctx context.Context, _ provisioner.DeleteWorkloadCommand, _ runtimebinding.Binding) error {
	return f(ctx)
}

func TestGatewayCleanupStepYieldsWorkerWithoutReportingCleanupComplete(t *testing.T) {
	backend := &KubernetesBackend{Delete: cleanupDeleteFunc(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})}
	started := time.Now()
	err := backend.DeleteWorkloadStep(context.Background(), provisioner.DeleteWorkloadCommand{}, runtimebinding.Binding{})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 4*time.Second {
		t.Fatalf("incomplete deletion must yield the worker with an error: elapsed=%s err=%v", time.Since(started), err)
	}
	var pending *operations.ProgressPendingError
	if !errors.As(err, &pending) {
		t.Fatal("normal cleanup progress inherited failure backoff")
	}
}

func TestCleanupStepDoesNotClassifyRemoteFaultAsNormalProgress(t *testing.T) {
	failure := errors.New("remote API forbidden")
	backend := &KubernetesBackend{Delete: cleanupDeleteFunc(func(context.Context) error { return failure })}
	err := backend.DeleteWorkloadStep(context.Background(), provisioner.DeleteWorkloadCommand{}, runtimebinding.Binding{})
	var pending *operations.ProgressPendingError
	if !errors.Is(err, failure) || errors.As(err, &pending) {
		t.Fatal("remote fault became a fast progress retry")
	}
}

func TestOrdinaryDeleteRetainsCallerTimeoutAndGatewayStepHonorsCancellation(t *testing.T) {
	backend := &KubernetesBackend{Delete: cleanupDeleteFunc(func(ctx context.Context) error {
		if _, bounded := ctx.Deadline(); bounded {
			t.Fatal("ordinary delete acquired the Gateway step deadline")
		}
		return nil
	})}
	if err := backend.DeleteWorkload(context.Background(), provisioner.DeleteWorkloadCommand{}, runtimebinding.Binding{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backend.Delete = cleanupDeleteFunc(func(ctx context.Context) error { return ctx.Err() })
	if err := backend.DeleteWorkloadStep(ctx, provisioner.DeleteWorkloadCommand{}, runtimebinding.Binding{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation was lost: %v", err)
	}
}

type pendingStepBackend struct {
	fakeBackend
	steps int
	done  bool
}

func (b *pendingStepBackend) DeleteWorkloadStep(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error {
	b.steps++
	if !b.done {
		return context.DeadlineExceeded
	}
	return nil
}

func TestPendingGatewayDeletionRetainsJournalAcrossWorkerYieldAndRestart(t *testing.T) {
	r := Record{Command: provisioner.CreateWorkloadCommand{InstanceID: "step-instance", TargetID: "target", TeamID: "team", RuntimeType: provisioner.RuntimeTypeKubernetes}, Result: provisioner.CreateWorkloadResult{NamespaceUID: "namespace-uid", RuntimeWorkloadID: "target/namespace/workload"}, Phase: PhaseRouteDeleted}
	journal := &memoryJournal{records: map[string]Record{r.Command.InstanceID: r}}
	backend := &pendingStepBackend{}
	remote := &fakeRoutes{}
	adapter := NewAdapter(backend, remote, journal)
	command := provisioner.DeleteWorkloadCommand{InstanceID: r.Command.InstanceID}
	if err := adapter.DeleteWorkload(context.Background(), command, recoveryBinding(r)); err == nil {
		t.Fatal("incomplete namespace cleanup was reported as success")
	}
	current, _ := journal.Get(context.Background(), r.Command.InstanceID)
	if current.Phase != PhaseRouteDeleted || backend.steps != 1 || backend.deletes != 0 || remote.deletes != 0 {
		t.Fatal("worker yield lost durable cleanup intent or repeated route deletion")
	}
	backend.done = true
	adapter = NewAdapter(backend, remote, journal)
	if err := adapter.DeleteWorkload(context.Background(), command, recoveryBinding(r)); err != nil {
		t.Fatal(err)
	}
	current, _ = journal.Get(context.Background(), r.Command.InstanceID)
	if current.Phase != PhaseDeleted || backend.steps != 2 || backend.deletes != 0 {
		t.Fatal("restarted worker did not confirm cleanup through the step adapter")
	}
}
