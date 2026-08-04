package runtimeops

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

func TestServiceEnqueuesCreateIdempotently(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	create := &recordingCreate{result: provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		NamespaceUID:      "namespace-uid-01",
		ServiceURL:        "https://gateway.example.invalid/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001",
	}}
	service := newTestService(t, create, &recordingStatus{}, &recordingDelete{}, bindings)
	command := createCommand()

	first, created, err := service.EnqueueCreate(command)
	if err != nil || !created {
		t.Fatalf("first EnqueueCreate() = (%#v, %t, %v)", first, created, err)
	}
	second, created, err := service.EnqueueCreate(command)
	if err != nil || created {
		t.Fatalf("second EnqueueCreate() = (%#v, %t, %v)", second, created, err)
	}
	if first.ID != second.ID || first.Status != operations.OperationStatusQueued {
		t.Fatalf("operations = %#v, %#v", first, second)
	}
	if create.calls != 0 {
		t.Fatalf("create calls before worker = %d", create.calls)
	}
}

func TestEnqueueCreateResolvesPolicyBeforePersistingOperation(t *testing.T) {
	resolver := &recordingResolver{resolved: validResolvedPolicy()}
	service := newTestServiceWithResolver(t, resolver, operations.NewMemoryStore(func() (string, error) { return "operation-policy", nil }))

	command := createCommand()
	command.ResourceLimits.MemoryMiB = 999
	operation, created, err := service.EnqueueCreate(command)
	if err != nil || !created {
		t.Fatalf("EnqueueCreate() = (%#v, %t, %v)", operation, created, err)
	}
	if resolver.calls != 1 || resolver.request.ChallengeID != "web-chall1" {
		t.Fatalf("resolver calls = %d; request = %#v", resolver.calls, resolver.request)
	}
	if operation.CreateCommand == nil || operation.CreateCommand.Policy.IsolationRef.Name != "STANDARD" ||
		!operation.CreateCommand.Policy.Baseline.RunAsNonRoot || operation.CreateCommand.ResourceLimits.MemoryMiB != 128 {
		t.Fatalf("operation = %#v", operation)
	}
}

func TestEnqueueCreateRejectsPolicyBeforePersistingOperation(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "operation-policy", nil })
	resolver := &recordingResolver{err: isolation.ErrPolicyRejected}
	service := newTestServiceWithResolver(t, resolver, store)

	_, _, err := service.EnqueueCreate(createCommand())
	if !errors.Is(err, isolation.ErrPolicyRejected) {
		t.Fatalf("EnqueueCreate() error = %v, want ErrPolicyRejected", err)
	}
	if _, err := store.GetByRequestID(createCommand().RequestID); !errors.Is(err, operations.ErrOperationNotFound) {
		t.Fatalf("operation store error = %v, want ErrOperationNotFound", err)
	}
}

func TestServiceCreateWorkloadResolvesZeroBaselineBeforeAdapter(t *testing.T) {
	resolver := &recordingResolver{resolved: validResolvedPolicy()}
	create := &recordingCreate{result: provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		NamespaceUID:      "namespace-uid-01",
	}}
	service := newTestServiceWithCreateAndResolver(
		t,
		create,
		resolver,
		operations.NewMemoryStore(func() (string, error) { return "operation-direct", nil }),
	)
	command := createCommand()
	command.Policy = isolation.ResolvedPolicy{}
	command.ResourceLimits.MemoryMiB = 999

	if _, err := service.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 || create.calls != 1 || !create.command.Policy.Baseline.RunAsNonRoot ||
		create.command.ResourceLimits.MemoryMiB != 128 {
		t.Fatalf("resolver calls = %d; create calls = %d; command = %#v", resolver.calls, create.calls, create.command)
	}
}

func TestServiceCreateWorkloadRejectsPolicyBeforeAdapter(t *testing.T) {
	resolver := &recordingResolver{err: isolation.ErrPolicyRejected}
	create := &recordingCreate{}
	service := newTestServiceWithCreateAndResolver(
		t,
		create,
		resolver,
		operations.NewMemoryStore(func() (string, error) { return "operation-direct", nil }),
	)

	_, err := service.CreateWorkload(context.Background(), createCommand())
	if !errors.Is(err, isolation.ErrPolicyRejected) || create.calls != 0 {
		t.Fatalf("CreateWorkload() error = %v; adapter calls = %d", err, create.calls)
	}
}

func TestCreateOperationStoresAppliedIsolationPolicy(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	create := &recordingCreate{result: provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		NamespaceUID:      "namespace-uid-01",
	}}
	service := newTestService(t, create, &recordingStatus{}, &recordingDelete{}, bindings)
	command := createPolicyCommand()

	result, err := service.CreateWorkload(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := bindings.Get(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	wantPolicy := validResolvedPolicyFor(command.PolicyRequest)
	if binding.NamespaceUID != create.result.NamespaceUID ||
		binding.ChallengeID != "web-chall2" || binding.ChallengeVersion != "2026.08.1" ||
		binding.IsolationProfile != "STANDARD@v1" || binding.ResourceProfile != "SMALL_MULTI@v1" ||
		!reflect.DeepEqual(binding.ContainerRequirements, wantPolicy.Containers) ||
		!reflect.DeepEqual(binding.InternalConnections, wantPolicy.InternalConnections) ||
		binding.OutboundMode != isolation.OutboundNone || binding.ResourceLimits != wantPolicy.ResourceLimits {
		t.Fatalf("binding = %#v; result = %#v", binding, result)
	}
}

func TestDirectCreateFailureDoesNotRecordBinding(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	create := &recordingCreate{err: errors.New("create failed")}
	deleteAdapter := &recordingDelete{}
	service := newTestService(t, create, &recordingStatus{}, deleteAdapter, bindings)

	if _, err := service.CreateWorkload(context.Background(), createPolicyCommand()); err == nil {
		t.Fatal("CreateWorkload() error = nil")
	}
	if deleteAdapter.calls != 0 {
		t.Fatalf("cleanup calls after adapter failure = %d", deleteAdapter.calls)
	}
	if _, err := bindings.Get(createPolicyCommand().InstanceID); !errors.Is(err, runtimebinding.ErrNotFound) {
		t.Fatalf("binding Get() error = %v", err)
	}
}

func TestDirectCreateCleansUpWithIndependentContextWhenBindingSaveFails(t *testing.T) {
	store := &failingSaveBindingStore{
		Store: runtimebinding.NewMemoryStore(),
		err:   runtimebinding.ErrConflict,
	}
	create := &recordingCreate{result: provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		NamespaceUID:      "namespace-uid-01",
	}}
	deleteAdapter := &recordingDelete{}
	service := newTestService(t, create, &recordingStatus{}, deleteAdapter, store)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.CreateWorkload(ctx, createCommand())
	if !errors.Is(err, runtimebinding.ErrConflict) {
		t.Fatalf("CreateWorkload() error = %v, want binding save cause", err)
	}
	if code, retryable := operations.ClassifyExecutionError(err); code != "RUNTIME_BINDING_SAVE_FAILED" || retryable {
		t.Fatalf("classification = %q, %v", code, retryable)
	}
	if create.calls != 1 || deleteAdapter.calls != 1 {
		t.Fatalf("create calls = %d; cleanup calls = %d", create.calls, deleteAdapter.calls)
	}
	if deleteAdapter.contextErr != nil || !deleteAdapter.contextHasDeadline {
		t.Fatalf("cleanup context error = %v; has deadline = %t", deleteAdapter.contextErr, deleteAdapter.contextHasDeadline)
	}
	if deleteAdapter.command.Reason != provisioner.DeleteReasonCreateFailedCleanup ||
		deleteAdapter.command.RuntimeWorkloadID != create.result.RuntimeWorkloadID ||
		deleteAdapter.binding.Namespace != "ctf-018f3f1e21b87a91a30b63b3400fd001" ||
		deleteAdapter.binding.NamespaceUID != create.result.NamespaceUID {
		t.Fatalf("cleanup command = %#v; binding = %#v", deleteAdapter.command, deleteAdapter.binding)
	}
	if _, getErr := store.Store.Get(createCommand().InstanceID); !errors.Is(getErr, runtimebinding.ErrNotFound) {
		t.Fatalf("binding after cleanup Get() error = %v", getErr)
	}
}

func TestDirectCreatePreservesBindingSaveAndCleanupFailures(t *testing.T) {
	saveCause := runtimebinding.ErrConflict
	cleanupCause := errors.New("namespace cleanup failed")
	store := &failingSaveBindingStore{Store: runtimebinding.NewMemoryStore(), err: saveCause}
	create := &recordingCreate{result: provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		NamespaceUID:      "namespace-uid-01",
	}}
	deleteAdapter := &recordingDelete{err: retryableTestError{cause: cleanupCause}}
	service := newTestService(t, create, &recordingStatus{}, deleteAdapter, store)

	_, err := service.CreateWorkload(context.Background(), createCommand())
	if !errors.Is(err, saveCause) || !errors.Is(err, cleanupCause) {
		t.Fatalf("CreateWorkload() error chain = %v", err)
	}
	if code, retryable := operations.ClassifyExecutionError(err); code != "ROLLBACK_FAILED" || !retryable {
		t.Fatalf("classification = %q, %v", code, retryable)
	}
	if deleteAdapter.calls != 1 {
		t.Fatalf("cleanup calls = %d", deleteAdapter.calls)
	}
	if _, getErr := store.Store.Get(createCommand().InstanceID); !errors.Is(getErr, runtimebinding.ErrNotFound) {
		t.Fatalf("binding after failed cleanup Get() error = %v", getErr)
	}
}

func TestServiceProcessesCreateAndRecordsBinding(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	create := &recordingCreate{result: provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		NamespaceUID:      "namespace-uid-01",
		ServiceURL:        "https://gateway.example.invalid/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001",
	}}
	service := newTestService(t, create, &recordingStatus{}, &recordingDelete{}, bindings)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerDone := make(chan error, 1)
	go func() { workerDone <- service.Run(ctx) }()

	operation, created, err := service.EnqueueCreate(createCommand())
	if err != nil || !created {
		t.Fatalf("EnqueueCreate() = (%#v, %t, %v)", operation, created, err)
	}
	operation = waitForOperationStatus(t, service, operation.ID, operations.OperationStatusSucceeded)
	if operation.Result.Create == nil || !reflect.DeepEqual(*operation.Result.Create, create.result) {
		t.Fatalf("operation result = %#v", operation.Result)
	}
	binding, err := bindings.Get(createCommand().InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if binding.TargetID != createCommand().TargetID || binding.TeamID != createCommand().TeamID ||
		binding.Namespace != "ctf-018f3f1e21b87a91a30b63b3400fd001" ||
		binding.NamespaceUID != create.result.NamespaceUID ||
		binding.RuntimeWorkloadID != create.result.RuntimeWorkloadID ||
		binding.ChallengeID != "web-chall1" || binding.ChallengeVersion != "2026.08.1" ||
		binding.IsolationProfile != "STANDARD@v1" || binding.ResourceProfile != "SMALL_SINGLE@v1" ||
		!reflect.DeepEqual(binding.ContainerRequirements, validResolvedPolicy().Containers) ||
		binding.OutboundMode != isolation.OutboundNone {
		t.Fatalf("binding = %#v", binding)
	}
	stopWorker(t, cancel, workerDone)
}

func TestServiceCreateFailureDoesNotRecordBinding(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	create := &recordingCreate{err: errors.New("create failed")}
	service := newTestService(t, create, &recordingStatus{}, &recordingDelete{}, bindings)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerDone := make(chan error, 1)
	go func() { workerDone <- service.Run(ctx) }()

	operation, _, err := service.EnqueueCreate(createCommand())
	if err != nil {
		t.Fatal(err)
	}
	operation = waitForOperationStatus(t, service, operation.ID, operations.OperationStatusFailed)
	if operation.LastErrorCode != "EXECUTION_FAILED" {
		t.Fatalf("operation = %#v", operation)
	}
	if _, err := bindings.Get(createCommand().InstanceID); !errors.Is(err, runtimebinding.ErrNotFound) {
		t.Fatalf("binding Get() error = %v", err)
	}
	stopWorker(t, cancel, workerDone)
}

func TestServiceCleansUpNamespaceWhenBindingSaveFails(t *testing.T) {
	store := &failingSaveBindingStore{
		Store: runtimebinding.NewMemoryStore(),
		err:   runtimebinding.ErrConflict,
	}
	create := &recordingCreate{result: provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		NamespaceUID:      "namespace-uid-01",
		ServiceURL:        "https://gateway.example.invalid/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001",
	}}
	deleteAdapter := &recordingDelete{}
	service := newTestService(t, create, &recordingStatus{}, deleteAdapter, store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerDone := make(chan error, 1)
	go func() { workerDone <- service.Run(ctx) }()

	operation, _, err := service.EnqueueCreate(createCommand())
	if err != nil {
		t.Fatal(err)
	}
	operation = waitForOperationStatus(t, service, operation.ID, operations.OperationStatusFailed)
	if operation.LastErrorCode != "RUNTIME_BINDING_SAVE_FAILED" {
		t.Fatalf("operation = %#v", operation)
	}
	if deleteAdapter.calls != 1 {
		t.Fatalf("cleanup delete calls = %d", deleteAdapter.calls)
	}
	if deleteAdapter.command.Reason != provisioner.DeleteReasonCreateFailedCleanup ||
		deleteAdapter.command.RuntimeWorkloadID != create.result.RuntimeWorkloadID ||
		deleteAdapter.binding.Namespace != "ctf-018f3f1e21b87a91a30b63b3400fd001" ||
		deleteAdapter.binding.NamespaceUID != create.result.NamespaceUID {
		t.Fatalf("cleanup command = %#v, binding = %#v", deleteAdapter.command, deleteAdapter.binding)
	}
	if _, err := store.Store.Get(createCommand().InstanceID); !errors.Is(err, runtimebinding.ErrNotFound) {
		t.Fatalf("binding after rollback Get() error = %v", err)
	}
	stopWorker(t, cancel, workerDone)
}

func TestServiceReadsStatusFromStoredTarget(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	binding := savedBinding(t, bindings)
	source := &recordingStatus{result: k3s.RuntimeStatus{InstanceID: binding.InstanceID, TargetID: binding.TargetID, Phase: "READY"}}
	service := newTestService(t, &recordingCreate{}, source, &recordingDelete{}, bindings)

	status, err := service.GetRuntimeStatus(context.Background(), binding.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != "READY" || !reflect.DeepEqual(source.binding, binding) {
		t.Fatalf("status = %#v, source binding = %#v", status, source.binding)
	}
}

func TestServiceRejectsDeleteCommandThatConflictsWithBinding(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	binding := savedBinding(t, bindings)
	deleteAdapter := &recordingDelete{}
	service := newTestService(t, &recordingCreate{}, &recordingStatus{}, deleteAdapter, bindings)
	command := deleteCommand(binding)
	command.TargetID = "gcp-dev"

	if _, _, err := service.EnqueueDelete(command); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("EnqueueDelete() error = %v", err)
	}
	if deleteAdapter.calls != 0 {
		t.Fatalf("delete calls = %d", deleteAdapter.calls)
	}
}

func TestServiceProcessesDeleteAndMarksBindingDeleted(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	binding := savedBinding(t, bindings)
	deleteAdapter := &recordingDelete{}
	service := newTestService(t, &recordingCreate{}, &recordingStatus{}, deleteAdapter, bindings)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerDone := make(chan error, 1)
	go func() { workerDone <- service.Run(ctx) }()

	operation, created, err := service.EnqueueDelete(deleteCommand(binding))
	if err != nil || !created {
		t.Fatalf("EnqueueDelete() = (%#v, %t, %v)", operation, created, err)
	}
	operation = waitForOperationStatus(t, service, operation.ID, operations.OperationStatusSucceeded)
	deleted, err := bindings.Get(binding.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.State != runtimebinding.StateDeleted || deleteAdapter.calls != 1 {
		t.Fatalf("deleted binding = %#v, calls = %d", deleted, deleteAdapter.calls)
	}

	replayed, created, err := service.EnqueueDelete(deleteCommand(binding))
	if err != nil || created || replayed.ID != operation.ID ||
		replayed.Status != operations.OperationStatusSucceeded {
		t.Fatalf("replayed EnqueueDelete() = (%#v, %t, %v)", replayed, created, err)
	}
	if deleteAdapter.calls != 1 {
		t.Fatalf("delete calls after replay = %d", deleteAdapter.calls)
	}

	stopWorker(t, cancel, workerDone)
}

func TestServiceRestoresCreatedBindingWhenDeleteQueueFails(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	binding := savedBinding(t, bindings)
	store := &failingDeleteOperationStore{
		Store: operations.NewMemoryStore(nil),
		err:   errors.New("queue unavailable"),
	}
	service := newTestServiceWithOperationStore(t, &recordingCreate{}, &recordingStatus{}, &recordingDelete{}, bindings, store)

	if _, _, err := service.EnqueueDelete(deleteCommand(binding)); err == nil {
		t.Fatal("EnqueueDelete() error = nil")
	}
	restored, err := bindings.Get(binding.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.State != runtimebinding.StateCreated {
		t.Fatalf("binding state = %s", restored.State)
	}
}

func TestServiceRejectsDeleteRequestIDConflictWithoutChangingBinding(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	binding := savedBinding(t, bindings)
	store := operations.NewMemoryStore(func() (string, error) { return "operation-create", nil })
	conflictingCreate := createCommand()
	conflictingCreate.RequestID = deleteCommand(binding).RequestID
	if _, _, err := store.EnqueueCreate(conflictingCreate, 2); err != nil {
		t.Fatal(err)
	}
	service := newTestServiceWithOperationStore(t, &recordingCreate{}, &recordingStatus{}, &recordingDelete{}, bindings, store)

	if _, _, err := service.EnqueueDelete(deleteCommand(binding)); !errors.Is(err, operations.ErrIdempotencyConflict) {
		t.Fatalf("EnqueueDelete() error = %v", err)
	}
	unchanged, err := bindings.Get(binding.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.State != runtimebinding.StateCreated {
		t.Fatalf("binding state = %s", unchanged.State)
	}
}

func waitForOperationStatus(t *testing.T, service *Service, operationID string, want operations.OperationStatus) operations.Operation {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		operation, err := service.GetOperation(operationID)
		if err != nil {
			t.Fatal(err)
		}
		if operation.Status == want {
			return operation
		}
		if operation.Status == operations.OperationStatusFailed && want != operations.OperationStatusFailed {
			t.Fatalf("operation failed: %#v", operation)
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation did not reach %s: %#v", want, operation)
		}
		time.Sleep(time.Millisecond)
	}
}

func stopWorker(t *testing.T, cancel context.CancelFunc, workerDone <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-workerDone:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func newTestService(
	t *testing.T,
	create CreateAdapter,
	status StatusSource,
	deleteAdapter DeleteAdapter,
	bindings runtimebinding.Store,
) *Service {
	t.Helper()
	return newTestServiceWithOperationStore(
		t,
		create,
		status,
		deleteAdapter,
		bindings,
		operations.NewMemoryStore(func() (string, error) { return "operation-01", nil }),
	)
}

func newTestServiceWithOperationStore(
	t *testing.T,
	create CreateAdapter,
	status StatusSource,
	deleteAdapter DeleteAdapter,
	bindings runtimebinding.Store,
	operationStore operations.Store,
) *Service {
	t.Helper()
	service, err := NewService(
		create,
		status,
		deleteAdapter,
		bindings,
		operationStore,
		isolation.NewStaticResolver(),
		Config{
			MaxAttempts: 2,
			Worker: operations.WorkerConfig{
				Concurrency: 1,
				Backoff:     func(int) time.Duration { return 0 },
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC) }
	return service
}

func newTestServiceWithResolver(t *testing.T, resolver isolation.Resolver, operationStore operations.Store) *Service {
	t.Helper()
	return newTestServiceWithCreateAndResolver(t, &recordingCreate{}, resolver, operationStore)
}

func newTestServiceWithCreateAndResolver(
	t *testing.T,
	create CreateAdapter,
	resolver isolation.Resolver,
	operationStore operations.Store,
) *Service {
	t.Helper()
	service, err := NewService(
		create,
		&recordingStatus{},
		&recordingDelete{},
		runtimebinding.NewMemoryStore(),
		operationStore,
		resolver,
		Config{
			MaxAttempts: 2,
			Worker: operations.WorkerConfig{
				Concurrency: 1,
				Backoff:     func(int) time.Duration { return 0 },
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type recordingResolver struct {
	calls    int
	request  isolation.Request
	resolved isolation.ResolvedPolicy
	err      error
}

func (r *recordingResolver) Resolve(request isolation.Request) (isolation.ResolvedPolicy, error) {
	r.calls++
	r.request = request
	return r.resolved, r.err
}

type recordingCreate struct {
	calls   int
	result  provisioner.CreateWorkloadResult
	err     error
	command provisioner.CreateWorkloadCommand
}

func (a *recordingCreate) CreateWorkload(_ context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	a.calls++
	a.command = command
	return a.result, a.err
}

type recordingStatus struct {
	result  k3s.RuntimeStatus
	err     error
	binding runtimebinding.Binding
}

func (s *recordingStatus) Get(_ context.Context, binding runtimebinding.Binding) (k3s.RuntimeStatus, error) {
	s.binding = binding
	return s.result, s.err
}

type recordingDelete struct {
	calls              int
	command            provisioner.DeleteWorkloadCommand
	binding            runtimebinding.Binding
	err                error
	contextErr         error
	contextHasDeadline bool
}

func (a *recordingDelete) DeleteWorkload(ctx context.Context, command provisioner.DeleteWorkloadCommand, binding runtimebinding.Binding) error {
	a.calls++
	a.command = command
	a.binding = binding
	a.contextErr = ctx.Err()
	_, a.contextHasDeadline = ctx.Deadline()
	return a.err
}

type failingSaveBindingStore struct {
	runtimebinding.Store
	err error
}

func (s *failingSaveBindingStore) SaveCreated(runtimebinding.Binding) (runtimebinding.Binding, bool, error) {
	return runtimebinding.Binding{}, false, s.err
}

type retryableTestError struct {
	cause error
}

func (e retryableTestError) Error() string {
	return e.cause.Error()
}

func (e retryableTestError) Unwrap() error {
	return e.cause
}

func (retryableTestError) Retryable() bool {
	return true
}

type failingDeleteOperationStore struct {
	operations.Store
	err error
}

func (s *failingDeleteOperationStore) EnqueueDelete(provisioner.DeleteWorkloadCommand, int) (operations.Operation, bool, error) {
	return operations.Operation{}, false, s.err
}

func createCommand() provisioner.CreateWorkloadCommand {
	return provisioner.CreateWorkloadCommand{
		RequestID:    "create-request-01",
		InstanceID:   "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:       18,
		ChallengeRef: provisioner.ChallengeRef{ChallengeID: "web-chall1", Version: "2026.08.1"},
		RuntimeType:  provisioner.RuntimeTypeKubernetes,
		TargetID:     "aws-dev",
		Containers: []provisioner.WorkloadContainer{{
			Name:   "challenge",
			Image:  "registry.example.invalid/challenge@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ports:  []int{8080},
			Expose: true,
		}},
		ResourceLimits: provisioner.ResourceLimits{
			CPUMillicores:       100,
			MemoryMiB:           128,
			EphemeralStorageMiB: 128,
		},
		PolicyRequest: isolation.Request{
			ChallengeID:  "web-chall1",
			IsolationRef: isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
			ResourceRef:  isolation.ProfileRef{Name: "SMALL_SINGLE", Version: "v1"},
			Containers: []isolation.ContainerRequirement{{
				Name: "challenge", Ports: []int{8080}, RunAsUser: 10001,
			}},
			OutboundMode:   isolation.OutboundNone,
			ResourceLimits: isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
		},
	}
}

func validResolvedPolicy() isolation.ResolvedPolicy {
	return validResolvedPolicyFor(createCommand().PolicyRequest)
}

func validResolvedPolicyFor(request isolation.Request) isolation.ResolvedPolicy {
	policy, err := isolation.NewStaticResolver().Resolve(request)
	if err != nil {
		panic(err)
	}
	return policy
}

func createPolicyCommand() provisioner.CreateWorkloadCommand {
	command := createCommand()
	command.ChallengeRef = provisioner.ChallengeRef{ChallengeID: "web-chall2", Version: "2026.08.1"}
	command.Containers = []provisioner.WorkloadContainer{
		{Name: "web", Image: "registry.example.invalid/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ports: []int{8000}, Expose: true},
		{Name: "api", Image: "registry.example.invalid/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Ports: []int{8080}},
	}
	command.PolicyRequest = isolation.Request{
		ChallengeID:  "web-chall2",
		IsolationRef: isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
		ResourceRef:  isolation.ProfileRef{Name: "SMALL_MULTI", Version: "v1"},
		Containers: []isolation.ContainerRequirement{
			{Name: "web", Ports: []int{8000}, RunAsUser: 101, WritablePaths: []isolation.WritablePath{{Path: "/tmp", SizeMiB: 64}}},
			{Name: "api", Ports: []int{8080}, RunAsUser: 10001},
		},
		InternalConnections: []isolation.InternalConnection{{
			SourceContainer: "web", DestinationContainer: "api", Protocol: isolation.ProtocolTCP, Port: 8080,
		}},
		OutboundMode: isolation.OutboundNone,
		ResourceLimits: isolation.ResourceLimits{
			CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256,
		},
	}
	command.ResourceLimits = provisioner.ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256}
	return command
}

func savedBinding(t *testing.T, store runtimebinding.Store) runtimebinding.Binding {
	t.Helper()
	binding := runtimebinding.Binding{
		InstanceID:        createCommand().InstanceID,
		TeamID:            18,
		TargetID:          "aws-dev",
		Namespace:         "ctf-018f3f1e21b87a91a30b63b3400fd001",
		NamespaceUID:      "namespace-uid-01",
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		State:             runtimebinding.StateCreated,
		CreatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	}
	if _, _, err := store.SaveCreated(binding); err != nil {
		t.Fatal(err)
	}
	return binding
}

func deleteCommand(binding runtimebinding.Binding) provisioner.DeleteWorkloadCommand {
	return provisioner.DeleteWorkloadCommand{
		RequestID:         "delete-request-01",
		InstanceID:        binding.InstanceID,
		TeamID:            binding.TeamID,
		RuntimeType:       provisioner.RuntimeTypeKubernetes,
		TargetID:          binding.TargetID,
		RuntimeWorkloadID: binding.RuntimeWorkloadID,
		Reason:            provisioner.DeleteReasonUserRequested,
	}
}
