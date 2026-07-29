package httpapi

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestCreateWorkloadRequestDecodesMultipleContainers(t *testing.T) {
	var request CreateWorkloadRequest
	err := json.Unmarshal([]byte(`{
		"request_id":"req-multi",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":18,
		"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},
		"workload":{
			"containers":[
				{"name":"web","image":"ghcr.io/msg-ctf/challenges/oob-test/web:latest","ports":[8080],"expose":true},
				{"name":"internal","image":"ghcr.io/msg-ctf/challenges/oob-test/web:latest","ports":[8080,9090],"expose":false}
			],
			"resource_limits":{"cpu_millicores":501,"memory_mib":513,"ephemeral_storage_mib":1025}
		}
	}`), &request)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}

	command := request.ToCommand()
	if len(command.Containers) != 2 {
		t.Fatalf("containers = %#v", command.Containers)
	}
	if command.Containers[1].Name != "internal" ||
		!reflect.DeepEqual(command.Containers[1].Ports, []int{8080, 9090}) ||
		command.Containers[1].Expose {
		t.Fatalf("second container = %#v", command.Containers[1])
	}
}

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

func TestCreateWorkloadRequestRejectsInvalidContainerSet(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*CreateWorkloadRequest)
	}{
		{
			name: "legacy and containers together",
			mutate: func(request *CreateWorkloadRequest) {
				request.Workload.Image = "legacy:latest"
				request.Workload.ContainerPort = 80
			},
		},
		{
			name: "duplicate names",
			mutate: func(request *CreateWorkloadRequest) {
				request.Workload.Containers[1].Name = request.Workload.Containers[0].Name
			},
		},
		{
			name: "invalid DNS name",
			mutate: func(request *CreateWorkloadRequest) {
				request.Workload.Containers[0].Name = "Not_Valid"
			},
		},
		{
			name: "empty image",
			mutate: func(request *CreateWorkloadRequest) {
				request.Workload.Containers[0].Image = " "
			},
		},
		{
			name: "empty ports",
			mutate: func(request *CreateWorkloadRequest) {
				request.Workload.Containers[0].Ports = nil
			},
		},
		{
			name: "invalid port",
			mutate: func(request *CreateWorkloadRequest) {
				request.Workload.Containers[0].Ports = []int{65536}
			},
		},
		{
			name: "duplicate port",
			mutate: func(request *CreateWorkloadRequest) {
				request.Workload.Containers[0].Ports = []int{8080, 8080}
			},
		},
		{
			name: "no exposed container",
			mutate: func(request *CreateWorkloadRequest) {
				request.Workload.Containers[0].Expose = false
			},
		},
		{
			name: "aggregate resource smaller than container count",
			mutate: func(request *CreateWorkloadRequest) {
				request.Workload.ResourceLimits.CPUMillicores = 1
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := validMultiCreateWorkloadRequest()
			testCase.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func validMultiCreateWorkloadRequest() CreateWorkloadRequest {
	return CreateWorkloadRequest{
		RequestID:  "req-multi",
		InstanceID: "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:     18,
		Target: RuntimeTarget{
			RuntimeType: RuntimeTypeKubernetes,
			TargetID:    "aws-dev",
		},
		Workload: RuntimeWorkload{
			Containers: []RuntimeContainer{
				{
					Name:   "web",
					Image:  "ghcr.io/msg-ctf/challenges/oob-test/web:latest",
					Ports:  []int{8080},
					Expose: true,
				},
				{
					Name:   "internal",
					Image:  "ghcr.io/msg-ctf/challenges/oob-test/web:latest",
					Ports:  []int{8080, 9090},
					Expose: false,
				},
			},
			ResourceLimits: ResourceLimits{
				CPUMillicores:       501,
				MemoryMiB:           513,
				EphemeralStorageMiB: 1025,
			},
		},
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
