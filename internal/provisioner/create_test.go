package provisioner

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCreateWorkloadRequestToCommandPreservesSchedulerFields(t *testing.T) {
	request := validCreateWorkloadRequest()

	if err := ValidateCreateWorkloadRequest(request); err != nil {
		t.Fatalf("ValidateCreateWorkloadRequest() error = %v", err)
	}

	command := request.ToCommand()
	if command.RequestID != request.RequestID || command.InstanceID != request.InstanceID {
		t.Fatalf("identity fields were not preserved: %#v", command)
	}
	if command.TeamID != request.TeamID || command.RuntimeType != RuntimeType(request.Target.RuntimeType) || command.TargetID != request.Target.TargetID {
		t.Fatalf("target fields were not preserved: %#v", command)
	}
	if command.Image != request.Workload.Image || command.ContainerPort != request.Workload.ContainerPort {
		t.Fatalf("workload fields were not preserved: %#v", command)
	}
	if command.ResourceLimits != request.Workload.ResourceLimits {
		t.Fatalf("resource limits were not preserved: %#v", command.ResourceLimits)
	}
}

func TestValidateCreateWorkloadRequestRejectsInvalidSchedulerFields(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*CreateWorkloadRequest)
	}{
		{name: "request id", field: "request_id", mutate: func(request *CreateWorkloadRequest) { request.RequestID = " " }},
		{name: "instance id", field: "instance_id", mutate: func(request *CreateWorkloadRequest) { request.InstanceID = "not-a-uuid" }},
		{name: "team id", field: "team_id", mutate: func(request *CreateWorkloadRequest) { request.TeamID = 0 }},
		{name: "runtime type", field: "runtime_type", mutate: func(request *CreateWorkloadRequest) { request.Target.RuntimeType = "DOCKER" }},
		{name: "target id", field: "target_id", mutate: func(request *CreateWorkloadRequest) { request.Target.TargetID = "" }},
		{name: "image", field: "image", mutate: func(request *CreateWorkloadRequest) { request.Workload.Image = " " }},
		{name: "container port low", field: "container_port", mutate: func(request *CreateWorkloadRequest) { request.Workload.ContainerPort = 0 }},
		{name: "container port high", field: "container_port", mutate: func(request *CreateWorkloadRequest) { request.Workload.ContainerPort = 65536 }},
		{name: "cpu", field: "cpu_millicores", mutate: func(request *CreateWorkloadRequest) { request.Workload.ResourceLimits.CPUMillicores = 0 }},
		{name: "memory", field: "memory_mib", mutate: func(request *CreateWorkloadRequest) { request.Workload.ResourceLimits.MemoryMiB = -1 }},
		{name: "storage", field: "ephemeral_storage_mib", mutate: func(request *CreateWorkloadRequest) { request.Workload.ResourceLimits.EphemeralStorageMiB = 0 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validCreateWorkloadRequest()
			test.mutate(&request)

			err := ValidateCreateWorkloadRequest(request)
			if err == nil {
				t.Fatal("ValidateCreateWorkloadRequest() error = nil")
			}
			if !strings.Contains(err.Error(), test.field) {
				t.Fatalf("error %q does not identify %q", err, test.field)
			}
		})
	}
}

func validCreateWorkloadRequest() CreateWorkloadRequest {
	return CreateWorkloadRequest{
		RequestID:  "req-01",
		InstanceID: "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:     1,
		Target: RuntimeTarget{
			RuntimeType: string(RuntimeTypeKubernetes),
			TargetID:    "cluster-main",
		},
		Workload: RuntimeWorkload{
			Image:         "registry.msgctf.local/challenges/web-01@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ContainerPort: 8080,
			ResourceLimits: ResourceLimits{
				CPUMillicores:       500,
				MemoryMiB:           512,
				EphemeralStorageMiB: 1024,
			},
		},
	}
}

func TestUnavailableCreateWorkloadUseCaseReportsRuntimeUnavailable(t *testing.T) {
	_, err := (UnavailableCreateWorkloadUseCase{}).CreateWorkload(context.Background(), validCreateWorkloadRequest().ToCommand())
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("CreateWorkload() error = %v, want ErrRuntimeUnavailable", err)
	}
}
