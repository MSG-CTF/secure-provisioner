package operations

import (
	"errors"
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestNewCreateOperation(t *testing.T) {
	command := provisioner.CreateWorkloadCommand{
		RequestID:   "req-1",
		InstanceID:  "inst-1",
		RuntimeType: provisioner.RuntimeTypeKubernetes,
		TargetID:    "aws-dev",
		Containers: []provisioner.WorkloadContainer{{
			Name: "challenge", Image: "nginx:1.27", Ports: []int{80}, Expose: true,
		}},
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
	if operation.RequestID != command.RequestID || !reflect.DeepEqual(*operation.CreateCommand, command) {
		t.Fatalf("unexpected copied command: %#v", operation)
	}
}

func TestCreateOperationCopiesPolicyAndIncludesItInIdempotency(t *testing.T) {
	command := provisioner.CreateWorkloadCommand{
		RequestID: "req-policy",
		PolicyRequest: isolation.Request{
			IsolationRef:       isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
			WorkloadProfileRef: isolation.ProfileRef{Name: "WEB", Version: "v1"},
			Containers: []isolation.ContainerRequirement{{
				Name: "web", Ports: []int{8080}, Expose: true, RunAsUser: 101,
				WritablePaths: []isolation.WritablePath{{Path: "/tmp", SizeMiB: 64}},
			}},
			InternalConnections: []isolation.InternalConnection{{
				SourceContainer: "web", DestinationContainer: "web", Protocol: isolation.ProtocolTCP, Port: 8080,
			}},
		},
		Policy: isolation.ResolvedPolicy{
			IsolationRef:        isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
			WorkloadProfileRef:  isolation.ProfileRef{Name: "WEB", Version: "v1"},
			EndpointProtocol:    isolation.EndpointProtocolHTTP,
			ExposureRequirement: isolation.ExposureAnySupported,
			Containers: []isolation.ContainerRequirement{{
				Name: "web", Ports: []int{8080}, Expose: true, RunAsUser: 101,
				WritablePaths: []isolation.WritablePath{{Path: "/tmp", SizeMiB: 64}},
			}},
			InternalConnections: []isolation.InternalConnection{{
				SourceContainer: "web", DestinationContainer: "web", Protocol: isolation.ProtocolTCP, Port: 8080,
			}},
		},
	}
	operation, err := NewCreateOperation("op-policy", command, 2)
	if err != nil {
		t.Fatal(err)
	}

	command.PolicyRequest.Containers[0].Ports[0] = 9090
	command.Policy.Containers[0].Ports[0] = 9090
	command.Policy.Containers[0].WritablePaths[0].Path = "/cache"
	command.Policy.InternalConnections[0].Port = 9090
	if operation.CreateCommand.PolicyRequest.Containers[0].Ports[0] != 8080 ||
		operation.CreateCommand.Policy.Containers[0].Ports[0] != 8080 ||
		operation.CreateCommand.Policy.Containers[0].WritablePaths[0].Path != "/tmp" ||
		operation.CreateCommand.Policy.InternalConnections[0].Port != 8080 {
		t.Fatalf("operation leaked policy aliases: %#v", operation.CreateCommand)
	}

	matching, err := NewCreateOperation("op-policy-2", *operation.CreateCommand, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !operation.SameRequest(matching) {
		t.Fatal("identical policies should be idempotent")
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*provisioner.CreateWorkloadCommand)
	}{
		{name: "container ports", mutate: func(command *provisioner.CreateWorkloadCommand) {
			command.Policy.Containers[0].Ports[0] = 9090
		}},
		{name: "writable paths", mutate: func(command *provisioner.CreateWorkloadCommand) {
			command.Policy.Containers[0].WritablePaths[0].SizeMiB = 32
		}},
		{name: "internal connections", mutate: func(command *provisioner.CreateWorkloadCommand) {
			command.Policy.InternalConnections[0].Port = 9090
		}},
		{name: "workload profile", mutate: func(command *provisioner.CreateWorkloadCommand) {
			command.Policy.WorkloadProfileRef = isolation.ProfileRef{Name: "PWN", Version: "v1"}
		}},
		{name: "endpoint protocol", mutate: func(command *provisioner.CreateWorkloadCommand) {
			command.Policy.EndpointProtocol = isolation.EndpointProtocolTCP
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			different := copyCreateCommand(*matching.CreateCommand)
			testCase.mutate(&different)
			differentOperation, err := NewCreateOperation("op-policy-3", different, 2)
			if err != nil {
				t.Fatal(err)
			}
			if operation.SameRequest(differentOperation) {
				t.Fatal("different resolved policies must conflict")
			}
		})
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
		RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: "aws-dev",
		Containers: []provisioner.WorkloadContainer{{
			Name: "challenge", Image: "nginx:1.27", Ports: []int{80}, Expose: true,
		}},
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
