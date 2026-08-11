package httpapi

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"sigs.k8s.io/yaml"
)

func TestCreateWorkloadRequestDecodesMultipleContainers(t *testing.T) {
	var request CreateWorkloadRequest
	err := json.Unmarshal([]byte(`{
		"request_id":"req-multi",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":18,
		"challenge_ref":{"challenge_id":"web-chall2","version":"2026.08.1"},
		"isolation_ref":{"name":"STANDARD","version":"v1"},
		"resource_profile_ref":{"name":"SMALL_MULTI","version":"v1"},
		"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},
		"workload":{
			"containers":[
				{"name":"web","image":"ghcr.io/msg-ctf/challenges/oob-test/web:latest","ports":[8080],"expose":true,"run_as_user":10001},
				{"name":"internal","image":"ghcr.io/msg-ctf/challenges/oob-test/web:latest","ports":[8080,9090],"expose":false,"run_as_user":10001}
			],
			"outbound_mode":"NONE",
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
	if command.RequestID != "req-01" || command.TeamID != 1 ||
		len(command.Containers) != 1 || command.Containers[0].Name != "challenge" ||
		!reflect.DeepEqual(command.Containers[0].Ports, []int{8080}) {
		t.Fatalf("command = %#v", command)
	}
	if command.ResourceLimits.CPUMillicores != 500 || command.ResourceLimits.MemoryMiB != 512 || command.ResourceLimits.EphemeralStorageMiB != 1024 {
		t.Fatalf("resource limits = %#v", command.ResourceLimits)
	}
}

func TestCreateWorkloadRequestConvertsApprovedIsolationRequirements(t *testing.T) {
	request := validMultiCreateWorkloadRequest()
	request.ChallengeRef = ChallengeRef{ChallengeID: "web-chall2", Version: "2026.08.1"}
	request.IsolationRef = ProfileRef{Name: "STANDARD", Version: "v1"}
	request.ResourceProfileRef = ProfileRef{Name: "SMALL_MULTI", Version: "v1"}
	request.Workload.Containers[0].RunAsUser = 101
	request.Workload.Containers[0].WritablePaths = []WritablePath{{Path: "/tmp", SizeMiB: 64}}
	request.Workload.Containers[1].Name = "api"
	request.Workload.Containers[1].RunAsUser = 10001
	request.Workload.InternalConnections = []InternalConnection{{
		SourceContainer: "web", DestinationContainer: "api", Protocol: "TCP", Port: 8080,
	}}
	request.Workload.OutboundMode = "NONE"
	request.Workload.ResourceLimits = ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256}

	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	if command.ChallengeRef.ChallengeID != "web-chall2" || command.PolicyRequest.IsolationRef.Name != "STANDARD" {
		t.Fatalf("command = %#v", command)
	}
	if command.Policy.IsolationRef.Name != "STANDARD" ||
		command.PolicyRequest.Containers[0].RunAsUser != 101 ||
		!reflect.DeepEqual(command.PolicyRequest.Containers[0].WritablePaths, command.Policy.Containers[0].WritablePaths) ||
		len(command.PolicyRequest.InternalConnections) != 1 ||
		command.PolicyRequest.InternalConnections[0].DestinationContainer != "api" {
		t.Fatalf("policy request = %#v; policy = %#v", command.PolicyRequest, command.Policy)
	}
}

func TestCreateWorkloadRequestRejectsInvalidIsolation(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*CreateWorkloadRequest)
	}{
		{name: "missing challenge", mutate: func(request *CreateWorkloadRequest) { request.ChallengeRef.ChallengeID = "" }},
		{name: "missing isolation profile", mutate: func(request *CreateWorkloadRequest) { request.IsolationRef.Name = "" }},
		{name: "root UID", mutate: func(request *CreateWorkloadRequest) { request.Workload.Containers[0].RunAsUser = 0 }},
		{name: "relative writable path", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].WritablePaths = []WritablePath{{Path: "tmp", SizeMiB: 8}}
		}},
		{name: "unknown source", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.InternalConnections[0].SourceContainer = "worker"
		}},
		{name: "unknown destination port", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.InternalConnections[0].Port = 7070
		}},
		{name: "unsupported protocol", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.InternalConnections[0].Protocol = "UDP"
		}},
		{name: "unknown outbound mode", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.OutboundMode = "PRIVATE_NETWORK"
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := validIsolationCreateWorkloadRequest()
			testCase.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestCreateWorkloadRequestRejectsUnknownRuntimeType(t *testing.T) {
	request := validCreateWorkloadRequest()
	request.Target.RuntimeType = RuntimeType("DOCKER")
	if err := request.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
}

func TestCreateWorkloadRequestDefaultsLegacyMultiContainerPolicy(t *testing.T) {
	var request CreateWorkloadRequest
	if err := json.Unmarshal([]byte(`{
		"request_id":"req-legacy-multi",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":18,
		"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},
		"workload":{
			"containers":[
				{"name":"web","image":"web:latest","ports":[8080],"expose":true},
				{"name":"api","image":"api:latest","ports":[8080]}
			],
			"resource_limits":{"cpu_millicores":501,"memory_mib":513,"ephemeral_storage_mib":1025}
		}
	}`), &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}

	command := request.ToCommand()
	if command.PolicyRequest.ResourceRef != (isolation.ProfileRef{Name: "SMALL_MULTI", Version: "v1"}) ||
		command.PolicyRequest.Containers[0].RunAsUser != 10001 ||
		command.PolicyRequest.Containers[1].RunAsUser != 10001 ||
		command.PolicyRequest.ResourceLimits != (isolation.ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256}) {
		t.Fatalf("legacy multi command = %#v", command)
	}
}

func TestCreateWorkloadRequestAcceptsNullableOptionalPolicyRequirements(t *testing.T) {
	var request CreateWorkloadRequest
	if err := json.Unmarshal([]byte(`{
		"request_id":"req-nullable-policy",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":18,
		"challenge_ref":{"challenge_id":"web-chall2","version":"2026.08.1"},
		"isolation_ref":{"name":"STANDARD","version":"v1"},
		"resource_profile_ref":{"name":"SMALL_MULTI","version":"v1"},
		"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},
		"workload":{
			"containers":[
				{"name":"web","image":"web:latest","ports":[8080],"expose":true,"run_as_user":101,"writable_paths":null},
				{"name":"api","image":"api:latest","ports":[8080],"expose":null,"run_as_user":10001}
			],
			"internal_connections":null,
			"outbound_mode":"NONE",
			"resource_limits":{"cpu_millicores":200,"memory_mib":256,"ephemeral_storage_mib":256}
		}
	}`), &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	if command.Containers[1].Expose || command.PolicyRequest.Containers[1].RunAsUser != 10001 ||
		len(command.PolicyRequest.Containers[0].WritablePaths) != 0 || len(command.PolicyRequest.InternalConnections) != 0 {
		t.Fatalf("command = %#v", command)
	}
}

func TestDocumentedCreateRequestExamplesDecodeAndValidate(t *testing.T) {
	specification, err := os.ReadFile("../../docs/api/secure-provisioner.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]struct {
			Post struct {
				RequestBody struct {
					Content map[string]struct {
						Examples map[string]struct {
							Value any `json:"value"`
						} `json:"examples"`
					} `json:"content"`
				} `json:"requestBody"`
			} `json:"post"`
		} `json:"paths"`
	}
	if err := yaml.Unmarshal(specification, &document); err != nil {
		t.Fatal(err)
	}
	examples := document.Paths["/internal/v1/instances"].Post.RequestBody.Content["application/json"].Examples
	for _, name := range []string{"MultiContainer", "LegacyMultiContainer", "ExplicitNullableRequirements"} {
		example, found := examples[name]
		if !found {
			t.Fatalf("OpenAPI create example %q not found", name)
		}
		encoded, err := json.Marshal(example.Value)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		var request CreateWorkloadRequest
		if err := json.Unmarshal(encoded, &request); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if err := request.Validate(); err != nil {
			t.Fatalf("validate %s: %v", name, err)
		}
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
		ChallengeRef: ChallengeRef{
			ChallengeID: "web-chall2",
			Version:     "2026.08.1",
		},
		IsolationRef:       ProfileRef{Name: "STANDARD", Version: "v1"},
		ResourceProfileRef: ProfileRef{Name: "SMALL_MULTI", Version: "v1"},
		Target: RuntimeTarget{
			RuntimeType: RuntimeTypeKubernetes,
			TargetID:    "aws-dev",
		},
		Workload: RuntimeWorkload{
			Containers: []RuntimeContainer{
				{
					Name:      "web",
					Image:     "ghcr.io/msg-ctf/challenges/oob-test/web:latest",
					Ports:     []int{8080},
					Expose:    true,
					RunAsUser: 10001,
				},
				{
					Name:      "internal",
					Image:     "ghcr.io/msg-ctf/challenges/oob-test/web:latest",
					Ports:     []int{8080, 9090},
					Expose:    false,
					RunAsUser: 10001,
				},
			},
			OutboundMode: "NONE",
			ResourceLimits: ResourceLimits{
				CPUMillicores:       501,
				MemoryMiB:           513,
				EphemeralStorageMiB: 1025,
			},
		},
	}
}

func validIsolationCreateWorkloadRequest() CreateWorkloadRequest {
	request := validMultiCreateWorkloadRequest()
	request.ChallengeRef = ChallengeRef{ChallengeID: "web-chall2", Version: "2026.08.1"}
	request.IsolationRef = ProfileRef{Name: "STANDARD", Version: "v1"}
	request.ResourceProfileRef = ProfileRef{Name: "SMALL_MULTI", Version: "v1"}
	request.Workload.Containers[0].RunAsUser = 101
	request.Workload.Containers[0].WritablePaths = []WritablePath{{Path: "/tmp", SizeMiB: 64}}
	request.Workload.Containers[1].Name = "api"
	request.Workload.Containers[1].RunAsUser = 10001
	request.Workload.InternalConnections = []InternalConnection{{
		SourceContainer: "web", DestinationContainer: "api", Protocol: "TCP", Port: 8080,
	}}
	request.Workload.OutboundMode = "NONE"
	request.Workload.ResourceLimits = ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256}
	return request
}

func validCreateWorkloadRequest() CreateWorkloadRequest {
	return CreateWorkloadRequest{
		RequestID:  "req-01",
		InstanceID: "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:     1,
		ChallengeRef: ChallengeRef{
			ChallengeID: "web-chall1",
			Version:     "2026.08.1",
		},
		IsolationRef:       ProfileRef{Name: "STANDARD", Version: "v1"},
		ResourceProfileRef: ProfileRef{Name: "SMALL_SINGLE", Version: "v1"},
		Target: RuntimeTarget{
			RuntimeType: RuntimeTypeKubernetes,
			TargetID:    "cluster-main",
		},
		Workload: RuntimeWorkload{
			Image:         "registry.msgctf.local/challenges/web-01@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ContainerPort: 8080,
			OutboundMode:  "NONE",
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
		"challenge_ref":{"challenge_id":"web-chall1","version":"2026.08.1"},
		"isolation_ref":{"name":"STANDARD","version":"v1"},
		"resource_profile_ref":{"name":"SMALL_SINGLE","version":"v1"},
		"target":{"runtime_type":"KUBERNETES","target_id":"cluster-main"},
		"workload":{
			"image":"registry.msgctf.local/challenges/web-01@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"container_port":8080,
			"outbound_mode":"NONE",
			"resource_limits":{"cpu_millicores":500,"memory_mib":512,"ephemeral_storage_mib":1024}
		}
	}`
}
