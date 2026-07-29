package k3s

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

func TestExecutorRoutesCreateOperationToSelectedTarget(t *testing.T) {
	command := provisioner.CreateWorkloadCommand{RequestID: "req-1", TargetID: "aws-dev"}
	want := provisioner.CreateWorkloadResult{RuntimeWorkloadID: "aws-dev/instance-1", ServiceURL: "https://instance-1.aws-dev.example"}
	adapter := &recordingCreateAdapter{result: want}
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}

	result, err := executor.Execute(context.Background(), operations.Operation{
		Type:          operations.OperationTypeCreate,
		CreateCommand: &command,
	})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.calls != 1 || !reflect.DeepEqual(adapter.command, command) {
		t.Fatalf("adapter calls = %d, command = %#v", adapter.calls, adapter.command)
	}
	if result.Create == nil || *result.Create != want || result.DeleteCompleted {
		t.Fatalf("result = %#v", result)
	}
}

func TestExecutorRejectsDeleteWithoutCallingKubernetes(t *testing.T) {
	adapter := &recordingCreateAdapter{}
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}

	_, err = executor.Execute(context.Background(), operations.Operation{Type: operations.OperationTypeDelete})
	if code, retryable := operations.ClassifyExecutionError(err); code != "UNSUPPORTED_OPERATION" || retryable {
		t.Fatalf("classification = %q, %v", code, retryable)
	}
	if adapter.calls != 0 {
		t.Fatalf("adapter calls = %d, want 0", adapter.calls)
	}
}

func TestExecutorRoutesDeleteUsingStoredBinding(t *testing.T) {
	binding, _ := deleteFixture()
	store := runtimebinding.NewMemoryStore()
	if _, _, err := store.SaveCreated(binding); err != nil {
		t.Fatal(err)
	}
	createAdapter := &recordingCreateAdapter{}
	deleteAdapter := &recordingDeleteAdapter{}
	executor, err := NewExecutorWithDelete(createAdapter, deleteAdapter, store)
	if err != nil {
		t.Fatal(err)
	}
	command := deleteCommand(binding)

	result, err := executor.Execute(context.Background(), operations.Operation{
		Type:          operations.OperationTypeDelete,
		DeleteCommand: &command,
	})
	if err != nil {
		t.Fatal(err)
	}
	if deleteAdapter.calls != 1 || deleteAdapter.command != command || deleteAdapter.binding != binding {
		t.Fatalf("delete call = %#v", deleteAdapter)
	}
	if !result.DeleteCompleted || result.Create != nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestExecutorMapsRuntimeErrorToStableExecutionError(t *testing.T) {
	cause := errors.New("https://private.cluster.example kubeconfig=/secret")
	adapter := &recordingCreateAdapter{err: newRuntimeError("K3S_UNAVAILABLE", true, cause)}
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	command := provisioner.CreateWorkloadCommand{RequestID: "req-1", TargetID: "aws-dev"}

	_, err = executor.Execute(context.Background(), operations.Operation{Type: operations.OperationTypeCreate, CreateCommand: &command})
	if code, retryable := operations.ClassifyExecutionError(err); code != "K3S_UNAVAILABLE" || !retryable {
		t.Fatalf("classification = %q, %v", code, retryable)
	}
	if err.Error() != "K3S_UNAVAILABLE" || !errors.Is(err, cause) {
		t.Fatalf("error = %v", err)
	}
}

func TestExecutorRejectsUnknownOperationAndMissingCreatePayload(t *testing.T) {
	adapter := &recordingCreateAdapter{}
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}

	for _, operation := range []operations.Operation{
		{Type: operations.OperationTypeCreate},
		{Type: operations.OperationType("ARCHIVE")},
	} {
		_, err := executor.Execute(context.Background(), operation)
		if code, retryable := operations.ClassifyExecutionError(err); code != "UNSUPPORTED_OPERATION" || retryable {
			t.Fatalf("operation %#v classification = %q, %v", operation, code, retryable)
		}
	}
	if adapter.calls != 0 {
		t.Fatalf("adapter calls = %d, want 0", adapter.calls)
	}
}

func TestExecutorMapsUnclassifiedAdapterErrorToNonRetryableExecutionFailure(t *testing.T) {
	adapter := &recordingCreateAdapter{err: errors.New("connection detail")}
	executor, err := NewExecutor(adapter)
	if err != nil {
		t.Fatal(err)
	}
	command := provisioner.CreateWorkloadCommand{RequestID: "req-1", TargetID: "aws-dev"}

	_, err = executor.Execute(context.Background(), operations.Operation{Type: operations.OperationTypeCreate, CreateCommand: &command})
	if code, retryable := operations.ClassifyExecutionError(err); code != "EXECUTION_FAILED" || retryable {
		t.Fatalf("classification = %q, %v", code, retryable)
	}
	if err.Error() != "EXECUTION_FAILED" {
		t.Fatalf("error = %q", err)
	}
}

func TestNewExecutorRejectsNilAdapter(t *testing.T) {
	if _, err := NewExecutor(nil); err == nil {
		t.Fatal("NewExecutor(nil) error = nil")
	}
}

type recordingCreateAdapter struct {
	calls   int
	command provisioner.CreateWorkloadCommand
	result  provisioner.CreateWorkloadResult
	err     error
}

type recordingDeleteAdapter struct {
	calls   int
	command provisioner.DeleteWorkloadCommand
	binding runtimebinding.Binding
	err     error
}

func (a *recordingDeleteAdapter) DeleteWorkload(_ context.Context, command provisioner.DeleteWorkloadCommand, binding runtimebinding.Binding) error {
	a.calls++
	a.command = command
	a.binding = binding
	return a.err
}

func (a *recordingCreateAdapter) CreateWorkload(_ context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	a.calls++
	a.command = command
	return a.result, a.err
}
