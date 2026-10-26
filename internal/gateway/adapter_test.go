package gateway

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

type memoryJournal struct {
	mu        sync.Mutex
	records   map[string]Record
	failPhase Phase
}
type memorySession struct {
	s  *memoryJournal
	id string
}

func (s *memoryJournal) WithLock(ctx context.Context, id string, f func(Session) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return f(memorySession{s, id})
}
func (s memorySession) Load() (Record, error) {
	r, ok := s.s.records[s.id]
	if !ok {
		return r, ErrNotFound
	}
	return r, nil
}
func (s memorySession) Save(r Record) error {
	if r.Phase == s.s.failPhase && r.Phase != "" {
		s.s.failPhase = ""
		return errors.New("injected phase commit interruption")
	}
	if s.s.records == nil {
		s.s.records = map[string]Record{}
	}
	s.s.records[s.id] = r
	return nil
}
func (s *memoryJournal) Get(ctx context.Context, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return (memorySession{s, id}).Load()
}
func (s *memoryJournal) HasPendingCleanup(context.Context, string) (bool, error) { return false, nil }

type fakeRoutes struct {
	puts          int
	deletes       int
	lost          bool
	deleteFailure bool
	last          Destination
	conflict      bool
}

func (f *fakeRoutes) Put(ctx context.Context, id string, d Destination) (Route, error) {
	f.puts++
	if f.puts > 1 && f.last != d {
		return Route{}, errors.New("changed tuple")
	}
	f.last = d
	if f.conflict {
		return Route{}, &APIError{Code: "GATEWAY_TARGET_IN_USE", Status: 409, Permanent: true}
	}
	if f.lost && f.puts == 1 {
		return Route{}, &APIError{Code: "GATEWAY_UNAVAILABLE"}
	}
	return Route{InstanceID: id, Hostname: "abc.gate.msgctf.kr", Port: 443, TLS: true, Protocol: d.Protocol, CreatedAt: time.Now()}, nil
}
func (f *fakeRoutes) Delete(context.Context, string) error {
	f.deletes++
	if f.deleteFailure {
		return &APIError{Code: "GATEWAY_BUSY"}
	}
	return nil
}

type fakeBackend struct {
	creates, deletes, quiesces int
	result                     provisioner.CreateWorkloadResult
	err                        error
}

func (f *fakeBackend) CreateWorkloadForOperation(context.Context, provisioner.CreateWorkloadCommand, string) (provisioner.CreateWorkloadResult, error) {
	f.creates++
	return f.result, f.err
}
func (f *fakeBackend) DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error {
	f.deletes++
	return nil
}
func (f *fakeBackend) CleanupFailedCreate(context.Context, provisioner.CreateWorkloadCommand, provisioner.CreateCleanup) error {
	return nil
}
func (f *fakeBackend) Destination(context.Context, provisioner.CreateWorkloadCommand, provisioner.CreateWorkloadResult) (Destination, string, error) {
	return Destination{TargetIP: "8.8.8.8", TargetPort: 31042, Protocol: "tcp"}, "service-uid", nil
}
func (f *fakeBackend) Verify(context.Context, Record) error          { return nil }
func (f *fakeBackend) VerifyPortClaim(context.Context, Record) error { return nil }
func (f *fakeBackend) Quiesce(context.Context, Record) error         { f.quiesces++; return nil }
func (f *fakeBackend) Enabled(string) bool                           { return true }

func TestAdapterReplaysImmutablePUTAfterLostResponseAndRestart(t *testing.T) {
	ctx := context.Background()
	backend := &fakeBackend{result: provisioner.CreateWorkloadResult{RuntimeWorkloadID: "target/ns/id", NamespaceUID: "ns-uid", Endpoints: []provisioner.WorkloadEndpoint{{ContainerName: "web", Port: 8080, Protocol: "TCP"}}}}
	journal := &memoryJournal{}
	remote := &fakeRoutes{lost: true}
	a := NewAdapter(backend, remote, journal)
	cmd := provisioner.CreateWorkloadCommand{InstanceID: "instance-1", TargetID: "target", RuntimeType: provisioner.RuntimeTypeKubernetes, Containers: []provisioner.WorkloadContainer{{Name: "web", Ports: []int{8080}, Expose: true}, {Name: "db", Ports: []int{5432}}}}
	if _, err := a.CreateWorkloadForOperation(ctx, cmd, "op1"); err == nil {
		t.Fatal("lost response accepted")
	}
	a = NewAdapter(backend, remote, journal)
	result, err := a.CreateWorkloadForOperation(ctx, cmd, "op1")
	if err != nil {
		t.Fatal(err)
	}
	if backend.creates != 1 || remote.puts != 2 {
		t.Fatal(backend.creates, remote.puts)
	}
	ep := result.Endpoints[0]
	if ep.ServiceURL != "tls://abc.gate.msgctf.kr:443" || !ep.TLS || ep.ServerName != ep.Hostname || ep.ConnectionPort != 443 || ep.Port != 8080 {
		t.Fatalf("%+v", ep)
	}
	replay, err := a.CreateWorkloadForOperation(ctx, cmd, "op1")
	if err != nil || !reflect.DeepEqual(result, replay) {
		t.Fatal(replay, err)
	}
}

func TestAdapterDoesNotReleaseServiceBeforeDELETE204(t *testing.T) {
	ctx := context.Background()
	journal := &memoryJournal{records: map[string]Record{"instance-1": {Command: provisioner.CreateWorkloadCommand{InstanceID: "instance-1", TargetID: "target"}, Result: provisioner.CreateWorkloadResult{NamespaceUID: "ns-uid", RuntimeWorkloadID: "target/ns/id"}, Phase: PhaseApplied}}}
	remote := &fakeRoutes{deleteFailure: true}
	backend := &fakeBackend{}
	a := NewAdapter(backend, remote, journal)
	binding := runtimebinding.Binding{InstanceID: "instance-1", TargetID: "target", NamespaceUID: "ns-uid", RuntimeWorkloadID: "target/ns/id"}
	if err := a.DeleteWorkload(ctx, provisioner.DeleteWorkloadCommand{InstanceID: "instance-1"}, binding); err == nil {
		t.Fatal("delete failure accepted")
	}
	if backend.deletes != 0 || backend.quiesces != 1 {
		t.Fatal("workload/Service released", backend.deletes)
	}
	record, _ := journal.Get(ctx, "instance-1")
	if record.Phase != PhaseDeletePending {
		t.Fatal(record.Phase)
	}
	remote.deleteFailure = false
	if err := a.DeleteWorkload(ctx, provisioner.DeleteWorkloadCommand{InstanceID: "instance-1"}, binding); err != nil {
		t.Fatal(err)
	}
	if backend.deletes != 1 {
		t.Fatal(backend.deletes)
	}
	if _, err := a.CreateWorkloadForOperation(ctx, record.Command, "op1"); err == nil {
		t.Fatal("tombstone resurrected")
	}
}

func TestGatewayAdmissionCountsAllPublicPorts(t *testing.T) {
	a := NewAdapter(&fakeBackend{}, &fakeRoutes{}, &memoryJournal{})
	for _, ports := range [][]int{{8080}, {8080, 9000}, {}} {
		cmd := provisioner.CreateWorkloadCommand{RuntimeType: provisioner.RuntimeTypeKubernetes, Containers: []provisioner.WorkloadContainer{{Ports: ports, Expose: true}, {Ports: []int{5432}}}}
		err := a.ValidateCreateCommand(cmd)
		if (err == nil) != (len(ports) == 1) {
			t.Fatal(ports, err)
		}
	}
}

func TestGatewayPreservesBackendRuntimeFailureAndCleanupProof(t *testing.T) {
	_, runtimeFailure := k3s.NewAdapter(nil, k3s.AdapterConfig{})
	wrapped := provisioner.WithCreateCleanupCompleted(runtimeFailure)
	backend := &fakeBackend{err: wrapped}
	remote := &fakeRoutes{}
	adapter := NewAdapter(backend, remote, &memoryJournal{})
	command := provisioner.CreateWorkloadCommand{InstanceID: "instance-1", RuntimeType: provisioner.RuntimeTypeKubernetes, Containers: []provisioner.WorkloadContainer{{Ports: []int{8080}, Expose: true}}}
	_, err := adapter.CreateWorkloadForOperation(context.Background(), command, "operation-1")
	if err != wrapped {
		t.Fatalf("backend classification/proof replaced: %v", err)
	}
	var classified *k3s.RuntimeError
	if !errors.As(err, &classified) || classified.Retryable() || classified.Code() != "CONFIG_INVALID" {
		t.Fatal(err)
	}
	var proof interface{ CreateCleanupCompleted() bool }
	if !errors.As(err, &proof) || !proof.CreateCleanupCompleted() || remote.puts != 0 {
		t.Fatal("cleanup proof lost", err)
	}
}

func TestGatewayForeignRouteConflictHoldsPortAcrossRestartAndCleanup(t *testing.T) {
	ctx := context.Background()
	backend := &fakeBackend{result: provisioner.CreateWorkloadResult{RuntimeWorkloadID: "target/ns/id", NamespaceUID: "ns-uid", Endpoints: []provisioner.WorkloadEndpoint{{ContainerName: "web", Port: 8080, Protocol: "TCP"}}}}
	journal := &memoryJournal{}
	remote := &fakeRoutes{conflict: true}
	adapter := NewAdapter(backend, remote, journal)
	command := provisioner.CreateWorkloadCommand{InstanceID: "instance-1", TargetID: "target", RuntimeType: provisioner.RuntimeTypeKubernetes, Containers: []provisioner.WorkloadContainer{{Name: "web", Ports: []int{8080}, Expose: true}}}
	if _, err := adapter.CreateWorkloadForOperation(ctx, command, "op1"); err == nil {
		t.Fatal("foreign route conflict accepted")
	}
	record, _ := journal.Get(ctx, command.InstanceID)
	if record.Phase != PhaseConflictHold || backend.quiesces != 1 || backend.deletes != 0 || remote.deletes != 0 {
		t.Fatal("conflict released/referenced workload", record.Phase, backend, remote)
	}
	adapter = NewAdapter(backend, remote, journal)
	binding := recoveryBinding(record)
	if err := adapter.DeleteWorkload(ctx, provisioner.DeleteWorkloadCommand{InstanceID: command.InstanceID}, binding); err == nil {
		t.Fatal("DELETE bypassed foreign route hold")
	}
	if backend.deletes != 0 || remote.deletes != 0 {
		t.Fatal("current ID DELETE cannot remove foreign route")
	}
	// Simulate operator resolving the foreign route, followed by a process/DB
	// interruption after the positive same-tuple PUT but before phase commit.
	remote.conflict = false
	journal.failPhase = PhaseDeletePending
	if err := adapter.DeleteWorkload(ctx, provisioner.DeleteWorkloadCommand{InstanceID: command.InstanceID}, binding); err == nil {
		t.Fatal("injected interrupted commit accepted")
	}
	if backend.deletes != 0 || remote.deletes != 0 {
		t.Fatal("port released without durable proof")
	}
	adapter = NewAdapter(backend, remote, journal)
	if err := adapter.DeleteWorkload(ctx, provisioner.DeleteWorkloadCommand{InstanceID: command.InstanceID}, binding); err != nil {
		t.Fatal(err)
	}
	if backend.deletes != 1 || remote.deletes != 1 || backend.creates != 1 {
		t.Fatal(backend, remote)
	}
	record, _ = journal.Get(ctx, command.InstanceID)
	if record.Phase != PhaseDeleted {
		t.Fatal(record.Phase)
	}
}
