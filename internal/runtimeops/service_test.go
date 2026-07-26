package runtimeops

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

func TestServiceRecordsBindingAfterSuccessfulCreate(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	create := &recordingCreate{result: provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		ServiceURL:        "https://gateway.example.invalid/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001",
	}}
	service := newTestService(t, create, &recordingStatus{}, &recordingDelete{}, bindings)
	command := createCommand()

	result, err := service.CreateWorkload(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result != create.result {
		t.Fatalf("result = %#v", result)
	}
	binding, err := bindings.Get(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if binding.TargetID != command.TargetID || binding.TeamID != command.TeamID ||
		binding.Namespace != "ctf-018f3f1e21b87a91a30b63b3400fd001" ||
		binding.RuntimeWorkloadID != result.RuntimeWorkloadID {
		t.Fatalf("binding = %#v", binding)
	}
}

func TestServiceDoesNotRecordBindingAfterFailedCreate(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	create := &recordingCreate{err: errors.New("create failed")}
	service := newTestService(t, create, &recordingStatus{}, &recordingDelete{}, bindings)

	if _, err := service.CreateWorkload(context.Background(), createCommand()); err == nil {
		t.Fatal("CreateWorkload() error = nil")
	}
	if _, err := bindings.Get(createCommand().InstanceID); !errors.Is(err, runtimebinding.ErrNotFound) {
		t.Fatalf("binding Get() error = %v", err)
	}
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
	if status.Phase != "READY" || source.binding != binding {
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
	deadline := time.Now().Add(2 * time.Second)
	for {
		operation, err = service.GetOperation(operation.ID)
		if err != nil {
			t.Fatal(err)
		}
		if operation.Status == operations.OperationStatusSucceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation did not succeed: %#v", operation)
		}
		time.Sleep(time.Millisecond)
	}
	deleted, err := bindings.Get(binding.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.State != runtimebinding.StateDeleted || deleteAdapter.calls != 1 {
		t.Fatalf("deleted binding = %#v, calls = %d", deleted, deleteAdapter.calls)
	}

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
	service, err := NewService(
		create,
		status,
		deleteAdapter,
		bindings,
		operations.NewMemoryStore(func() (string, error) { return "operation-01", nil }),
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

type recordingCreate struct {
	result  provisioner.CreateWorkloadResult
	err     error
	command provisioner.CreateWorkloadCommand
}

func (a *recordingCreate) CreateWorkload(_ context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
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
	calls   int
	command provisioner.DeleteWorkloadCommand
	binding runtimebinding.Binding
	err     error
}

func (a *recordingDelete) DeleteWorkload(_ context.Context, command provisioner.DeleteWorkloadCommand, binding runtimebinding.Binding) error {
	a.calls++
	a.command = command
	a.binding = binding
	return a.err
}

func createCommand() provisioner.CreateWorkloadCommand {
	return provisioner.CreateWorkloadCommand{
		RequestID:     "create-request-01",
		InstanceID:    "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:        18,
		RuntimeType:   provisioner.RuntimeTypeKubernetes,
		TargetID:      "aws-dev",
		Image:         "registry.example.invalid/challenge@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ContainerPort: 8080,
		ResourceLimits: provisioner.ResourceLimits{
			CPUMillicores:       500,
			MemoryMiB:           512,
			EphemeralStorageMiB: 1024,
		},
	}
}

func savedBinding(t *testing.T, store runtimebinding.Store) runtimebinding.Binding {
	t.Helper()
	binding := runtimebinding.Binding{
		InstanceID:        createCommand().InstanceID,
		TeamID:            18,
		TargetID:          "aws-dev",
		Namespace:         "ctf-018f3f1e21b87a91a30b63b3400fd001",
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
