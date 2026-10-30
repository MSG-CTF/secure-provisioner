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
		return operations.NewProgressPendingError("NAMESPACE_DELETE_PENDING", ctx.Err())
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

func TestCleanupStepDoesNotClassifyStalledAPIAsNormalProgress(t *testing.T) {
	backend := &KubernetesBackend{Delete: cleanupDeleteFunc(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})}
	err := backend.DeleteWorkloadStep(context.Background(), provisioner.DeleteWorkloadCommand{}, runtimebinding.Binding{})
	var pending *operations.ProgressPendingError
	if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &pending) {
		t.Fatal("stalled API became a fast progress retry")
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

type quiesceWaitBackend struct {
	fakeBackend
	waitErr error
}

func (b *quiesceWaitBackend) Quiesce(context.Context, Record) error {
	b.quiesces++
	return b.waitErr
}

func TestRestartAfterRouteDeletionWaitsForPodsWithoutRepeatingRouteDelete(t *testing.T) {
	for _, normal := range []bool{true, false} {
		t.Run(map[bool]string{true: "terminating pods", false: "API fault"}[normal], func(t *testing.T) {
			r := Record{Command: provisioner.CreateWorkloadCommand{InstanceID: "quiesce-instance", TargetID: "target", TeamID: "team", RuntimeType: provisioner.RuntimeTypeKubernetes}, Result: provisioner.CreateWorkloadResult{NamespaceUID: "namespace-uid", RuntimeWorkloadID: "target/namespace/workload"}, Phase: PhaseDeletePending}
			journal := &memoryJournal{records: map[string]Record{r.Command.InstanceID: r}}
			backend := &quiesceWaitBackend{waitErr: errors.New("namespace API unavailable")}
			if normal {
				backend.waitErr = operations.NewProgressPendingError("GATEWAY_WORKLOAD_STOP_PENDING", nil)
			}
			remote := &fakeRoutes{}
			command := provisioner.DeleteWorkloadCommand{InstanceID: r.Command.InstanceID}
			for attempt := 0; attempt < 2; attempt++ {
				adapter := NewAdapter(backend, remote, journal)
				err := adapter.DeleteWorkload(context.Background(), command, recoveryBinding(r))
				var pending *operations.ProgressPendingError
				if err == nil || errors.As(err, &pending) != normal {
					t.Fatalf("pending classification changed across restart: %v", err)
				}
				current, _ := journal.Get(context.Background(), r.Command.InstanceID)
				if current.Phase != PhaseRouteDeleted || backend.deletes != 0 || remote.deletes != 1 {
					t.Fatal("namespace deleted before pod termination or route deletion repeated")
				}
			}
			backend.waitErr = nil
			if err := NewAdapter(backend, remote, journal).DeleteWorkload(context.Background(), command, recoveryBinding(r)); err != nil {
				t.Fatal(err)
			}
			current, _ := journal.Get(context.Background(), r.Command.InstanceID)
			if current.Phase != PhaseDeleted || backend.deletes != 1 || remote.deletes != 1 {
				t.Fatal("completed quiesce did not continue the existing cleanup")
			}
		})
	}
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
