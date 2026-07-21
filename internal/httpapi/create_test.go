package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestCreateWorkloadRequestDecodesAndConvertsAllSchedulerFields(t *testing.T) {
	var request CreateWorkloadRequest
	if err := json.Unmarshal([]byte(validCreateRequestJSON()), &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	if command.RuntimeType != provisioner.RuntimeTypeKubernetes || command.TargetID != "cluster-main" {
		t.Fatalf("target = %#v", command)
	}
	if command.RequestID != "req-01" || command.TeamID != 1 || command.ContainerPort != 8080 {
		t.Fatalf("command = %#v", command)
	}
	if command.ResourceLimits.CPUMillicores != 500 || command.ResourceLimits.MemoryMiB != 512 || command.ResourceLimits.EphemeralStorageMiB != 1024 {
		t.Fatalf("resource limits = %#v", command.ResourceLimits)
	}
}

func TestCreateWorkloadRequestRejectsUnknownRuntimeType(t *testing.T) {
	request := validCreateWorkloadRequest()
	request.Target.RuntimeType = RuntimeType("DOCKER")
	if err := request.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
}

func validCreateWorkloadRequest() CreateWorkloadRequest {
	return CreateWorkloadRequest{
		RequestID:  "req-01",
		InstanceID: "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:     1,
		Target: RuntimeTarget{
			RuntimeType: RuntimeTypeKubernetes,
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

func validCreateRequestJSON() string {
	return `{
		"request_id":"req-01",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":1,
		"target":{"runtime_type":"KUBERNETES","target_id":"cluster-main"},
		"workload":{
			"image":"registry.msgctf.local/challenges/web-01@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"container_port":8080,
			"resource_limits":{"cpu_millicores":500,"memory_mib":512,"ephemeral_storage_mib":1024}
		}
	}`
}
