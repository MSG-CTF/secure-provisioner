package runtimepg

import (
	"context"
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/gateway"
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
	"github.com/google/uuid"
	"sync"
	"testing"
	"time"
)

type lifecycleRoutes struct {
	mu            sync.Mutex
	puts, deletes int
	deleted       bool
	destination   gateway.Destination
}

func (r *lifecycleRoutes) Put(ctx context.Context, id string, d gateway.Destination) (gateway.Route, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.puts++
	if r.puts > 1 && r.destination != d {
		return gateway.Route{}, errors.New("destination changed")
	}
	r.destination = d
	if r.puts == 1 {
		return gateway.Route{}, &gateway.APIError{Code: "GATEWAY_UNAVAILABLE"}
	}
	return gateway.Route{InstanceID: id, Hostname: "abc.gate.msgctf.kr", Port: 443, TLS: true, Protocol: "tcp", CreatedAt: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)}, nil
}
func (r *lifecycleRoutes) Delete(context.Context, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deletes++
	if r.deletes == 1 {
		return &gateway.APIError{Code: "GATEWAY_BUSY"}
	}
	r.deleted = true
	return nil
}

type lifecycleBackend struct {
	mu               sync.Mutex
	creates, deletes int
	remote           *lifecycleRoutes
	port             int
}

func (b *lifecycleBackend) Enabled(string) bool { return true }
func (b *lifecycleBackend) CreateWorkloadForOperation(ctx context.Context, c provisioner.CreateWorkloadCommand, op string) (provisioner.CreateWorkloadResult, error) {
	b.mu.Lock()
	b.creates++
	b.mu.Unlock()
	namespace, _ := k3s.NamespaceForInstance(c.InstanceID)
	return provisioner.CreateWorkloadResult{RuntimeWorkloadID: k3s.RuntimeWorkloadID(c.TargetID, namespace), NamespaceUID: "uid-" + c.InstanceID, Endpoints: []provisioner.WorkloadEndpoint{{ContainerName: c.Containers[0].Name, Port: c.Containers[0].Ports[0], Protocol: "TCP"}}}, nil
}
func (b *lifecycleBackend) Destination(context.Context, provisioner.CreateWorkloadCommand, provisioner.CreateWorkloadResult) (gateway.Destination, string, error) {
	return gateway.Destination{TargetIP: "8.8.8.8", TargetPort: b.port, Protocol: "tcp"}, "service-uid", nil
}
func (b *lifecycleBackend) Verify(context.Context, gateway.Record) error          { return nil }
func (b *lifecycleBackend) VerifyPortClaim(context.Context, gateway.Record) error { return nil }
func (b *lifecycleBackend) Quiesce(context.Context, gateway.Record) error         { return nil }
func (b *lifecycleBackend) CleanupFailedCreate(context.Context, provisioner.CreateWorkloadCommand, provisioner.CreateCleanup) error {
	return errors.New("unexpected pre-intent cleanup")
}
func (b *lifecycleBackend) DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error {
	b.remote.mu.Lock()
	deleted := b.remote.deleted
	b.remote.mu.Unlock()
	if !deleted {
		return errors.New("port released before Gateway tombstone")
	}
	b.mu.Lock()
	b.deletes++
	b.mu.Unlock()
	return nil
}

type lifecycleStatus struct{}

func (lifecycleStatus) Get(context.Context, runtimebinding.Binding) (k3s.RuntimeStatus, error) {
	return k3s.RuntimeStatus{Phase: "READY"}, nil
}

type failBindingSave struct{ runtimebinding.Store }

func (f failBindingSave) SaveCreated(runtimebinding.Binding) (runtimebinding.Binding, bool, error) {
	return runtimebinding.Binding{}, false, errors.New("injected Binding save failure")
}

func TestGatewayPostgresWorkerLostResponseAndBindingFailureCleanup(t *testing.T) {
	for index, failSave := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost response then delete", true: "binding save rollback"}[failSave], func(t *testing.T) {
			db := openTestDatabase(t)
			remote := &lifecycleRoutes{}
			backend := &lifecycleBackend{remote: remote, port: 31200 + index}
			adapter := gateway.NewAdapter(backend, remote, db.GatewayJournal())
			var bindings runtimebinding.Store = db.Bindings()
			if failSave {
				bindings = failBindingSave{bindings}
			}
			service, err := runtimeops.NewService(adapter, lifecycleStatus{}, adapter, bindings, db.Operations(), isolation.NewStaticResolver(), runtimeops.Config{MaxAttempts: 1, CleanupTimeout: time.Second, DeleteCoordinator: db.DeleteCoordinator(), Worker: operations.WorkerConfig{Concurrency: 1, WorkerID: "gateway-integration", PollInterval: time.Millisecond, LeaseDuration: 200 * time.Millisecond, RenewInterval: 50 * time.Millisecond, Backoff: func(int) time.Duration { return time.Millisecond }}})
			if err != nil {
				t.Fatal(err)
			}
			command := validResolvedPwnCommand(t)
			command.RequestID = uuid.NewString()
			command.InstanceID = uuid.NewString()
			create, _, err := service.EnqueueCreate(command)
			if err != nil {
				t.Fatal(err)
			}
			if remote.puts != 0 {
				t.Fatal("Gateway IO during admission")
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- service.Run(ctx) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			terminal := func(id string) operations.Operation {
				deadline := time.Now().Add(4 * time.Second)
				for time.Now().Before(deadline) {
					op, e := service.GetOperation(id)
					if e != nil {
						t.Fatal(e)
					}
					if op.Status == operations.OperationStatusSucceeded || op.Status == operations.OperationStatusFailed {
						return op
					}
					time.Sleep(time.Millisecond)
				}
				t.Fatal("operation did not complete")
				return operations.Operation{}
			}
			final := terminal(create.ID)
			if failSave {
				if final.Status != operations.OperationStatusFailed || !final.Result.CreateCleanupCompleted {
					t.Fatal(final)
				}
			} else {
				if final.Status != operations.OperationStatusSucceeded || final.Result.Create == nil || !final.Result.Create.Endpoints[0].TLS {
					t.Fatal(final)
				}
				binding, e := bindings.Get(command.InstanceID)
				if e != nil || !binding.Endpoints[0].TLS || binding.Endpoints[0].ServerName != "abc.gate.msgctf.kr" {
					t.Fatal(binding, e)
				}
				deleted, _, e := service.EnqueueDelete(provisioner.DeleteWorkloadCommand{RequestID: uuid.NewString(), InstanceID: command.InstanceID, TeamID: command.TeamID, RuntimeType: command.RuntimeType, TargetID: command.TargetID, RuntimeWorkloadID: binding.RuntimeWorkloadID})
				if e != nil {
					t.Fatal(e)
				}
				if op := terminal(deleted.ID); op.Status != operations.OperationStatusSucceeded || !op.Result.DeleteCompleted {
					t.Fatal(op)
				}
			}
			backend.mu.Lock()
			creates, deletes := backend.creates, backend.deletes
			backend.mu.Unlock()
			remote.mu.Lock()
			puts, routeDeletes := remote.puts, remote.deletes
			remote.mu.Unlock()
			if creates != 1 || deletes != 1 || puts != 2 || routeDeletes < 2 {
				t.Fatal(creates, deletes, puts, routeDeletes)
			}
			record, e := db.GatewayJournal().Get(context.Background(), command.InstanceID)
			if e != nil || record.Phase != gateway.PhaseDeleted {
				t.Fatal(record, e)
			}
		})
	}
}
