package operations

import (
	"errors"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestNewCreateOperation(t *testing.T) {
	command := provisioner.CreateWorkloadCommand{
		RequestID:     "req-1",
		InstanceID:    "inst-1",
		RuntimeType:   provisioner.RuntimeTypeKubernetes,
		TargetID:      "aws-dev",
		Image:         "nginx:1.27",
		ContainerPort: 80,
	}

	operation, err := NewCreateOperation("op-1", command, 3)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Type != OperationTypeCreate || operation.Status != OperationStatusQueued || operation.Attempt != 0 || operation.MaxAttempts != 3 {
		t.Fatalf("unexpected operation: %#v", operation)
	}
	if operation.CreateCommand == nil || operation.DeleteCommand != nil {
		t.Fatalf("unexpected payload: %#v", operation)
	}
	if operation.RequestID != command.RequestID || *operation.CreateCommand != command {
		t.Fatalf("unexpected copied command: %#v", operation)
	}
}

func TestNewDeleteOperation(t *testing.T) {
	command := provisioner.DeleteWorkloadCommand{
		RequestID:         "req-2",
		InstanceID:        "inst-2",
		RuntimeType:       provisioner.RuntimeTypeKubernetes,
		TargetID:          "aws-dev",
		RuntimeWorkloadID: "ns/workload",
		Reason:            provisioner.DeleteReasonUserRequested,
	}

	operation, err := NewDeleteOperation("op-2", command, 2)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Type != OperationTypeDelete || operation.Status != OperationStatusQueued || operation.Attempt != 0 || operation.MaxAttempts != 2 {
		t.Fatalf("unexpected operation: %#v", operation)
	}
	if operation.DeleteCommand == nil || operation.CreateCommand != nil {
		t.Fatalf("unexpected payload: %#v", operation)
	}
	if operation.RequestID != command.RequestID || *operation.DeleteCommand != command {
		t.Fatalf("unexpected copied command: %#v", operation)
	}
}

func TestNewOperationRejectsEmptyIDRequestIDAndInvalidMaxAttempts(t *testing.T) {
	validCommand := provisioner.CreateWorkloadCommand{RequestID: "req-1"}
	testCases := []struct {
		name        string
		id          string
		command     provisioner.CreateWorkloadCommand
		maxAttempts int
	}{
		{name: "empty operation ID", command: validCommand, maxAttempts: 1},
		{name: "empty request ID", id: "op-1", maxAttempts: 1},
		{name: "invalid max attempts", id: "op-1", command: validCommand},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewCreateOperation(testCase.id, testCase.command, testCase.maxAttempts)
			if !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestSameRequestRequiresMatchingTypeRequestIDAndFullCommand(t *testing.T) {
	createCommand := provisioner.CreateWorkloadCommand{
		RequestID: "req-1", InstanceID: "inst-1", TeamID: 7,
		RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: "aws-dev", Image: "nginx:1.27", ContainerPort: 80,
		ResourceLimits: provisioner.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 256},
	}
	matching, err := NewCreateOperation("op-1", createCommand, 1)
	if err != nil {
		t.Fatal(err)
	}
	otherMatching, err := NewCreateOperation("op-2", createCommand, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !matching.SameRequest(otherMatching) {
		t.Fatal("expected identical create requests to match")
	}

	differentCommand := createCommand
	differentCommand.ResourceLimits.MemoryMiB = 256
	otherDifferentCommand, err := NewCreateOperation("op-3", differentCommand, 1)
	if err != nil {
		t.Fatal(err)
	}
	if matching.SameRequest(otherDifferentCommand) {
		t.Fatal("expected different command to not match")
	}

	deleteOperation, err := NewDeleteOperation("op-4", provisioner.DeleteWorkloadCommand{RequestID: "req-1"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if matching.SameRequest(deleteOperation) {
		t.Fatal("expected different operation types to not match")
	}
}
