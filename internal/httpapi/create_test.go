package httpapi

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"sigs.k8s.io/yaml"
)

func TestCreateWorkloadRequestDecodesSimplifiedMultiContainerContract(t *testing.T) {
	var request CreateWorkloadRequest
	if err := json.Unmarshal([]byte(validCreateRequestJSON()), &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}

	command := request.ToCommand()
	if command.RuntimeType != provisioner.RuntimeTypeKubernetes || command.TargetID != "aws-dev" ||
		command.RequestID != "req-multi" || command.TeamID != "00000000-0000-4000-8000-000000000018" {
		t.Fatalf("command = %#v", command)
	}
	if len(command.Containers) != 2 || command.Containers[1].Name != "api" ||
		!reflect.DeepEqual(command.Containers[1].Ports, []int{9000}) || command.Containers[1].Expose {
		t.Fatalf("containers = %#v", command.Containers)
	}
	if command.PolicyRequest.WorkloadProfile != isolation.WorkloadProfileWeb ||
		command.PolicyRequest.ResourceLimits != (isolation.ResourceLimits{CPUMillicores: 500, MemoryMiB: 512, EphemeralStorageMiB: 1024}) ||
		command.Policy.OutboundMode != isolation.OutboundNone ||
		command.Policy.IsolationRef != (isolation.ProfileRef{Name: "STANDARD", Version: "v2"}) ||
		command.Policy.WorkloadProfileRef != (isolation.ProfileRef{Name: "WEB", Version: "v1"}) {
		t.Fatalf("policy request = %#v; unresolved policy = %#v", command.PolicyRequest, command.Policy)
	}

}

func TestCreateWorkloadRequestMapsExactIsolationProfiles(t *testing.T) {
	for _, testCase := range []struct {
		wire string
		want isolation.WorkloadProfile
	}{
		{wire: "WEB", want: isolation.WorkloadProfileWeb},
		{wire: "PWN", want: isolation.WorkloadProfilePwn},
	} {
		t.Run(testCase.wire, func(t *testing.T) {
			request := validCreateWorkloadRequest()
			request.IsolationProfile = testCase.wire
			if testCase.want == isolation.WorkloadProfilePwn {
				request.Workload.Containers = []RuntimeContainer{{
					Name: "challenge", Image: "pwn@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Ports: []int{31337}, Expose: true, RunAsUser: 10001,
				}}
			}
			if err := request.Validate(); err != nil {
				t.Fatal(err)
			}
			if got := request.ToCommand().PolicyRequest.WorkloadProfile; got != testCase.want {
				t.Fatalf("workload profile = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestCreateWorkloadRequestRejectsMissingOrUnknownIsolationProfile(t *testing.T) {
	for _, profile := range []string{"", "web", "KERNEL"} {
		t.Run(profile, func(t *testing.T) {
			request := validCreateWorkloadRequest()
			request.IsolationProfile = profile
			if err := request.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestCreateWorkloadRequestRejectsNonCanonicalTeamID(t *testing.T) {
	for _, teamID := range []provisioner.TeamID{
		"",
		"18",
		"not-a-uuid",
		"00000000-0000-0000-0000-000000000000",
		"00000000-0000-4000-8000-0000000000AA",
	} {
		t.Run(string(teamID), func(t *testing.T) {
			request := validCreateWorkloadRequest()
			request.TeamID = teamID
			if err := request.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestCreateWorkloadRequestRejectsRemovedPolicyFields(t *testing.T) {
	for _, testCase := range []struct {
		name string
		body string
	}{
		{name: "challenge ref", body: strings.Replace(validCreateRequestJSON(), `"team_id":"00000000-0000-4000-8000-000000000018",`, `"team_id":"00000000-0000-4000-8000-000000000018","challenge_ref":{"challenge_id":"old","version":"v1"},`, 1)},
		{name: "isolation ref", body: strings.Replace(validCreateRequestJSON(), `"team_id":"00000000-0000-4000-8000-000000000018",`, `"team_id":"00000000-0000-4000-8000-000000000018","isolation_ref":{"name":"STANDARD","version":"v1"},`, 1)},
		{name: "workload profile ref", body: strings.Replace(validCreateRequestJSON(), `"team_id":"00000000-0000-4000-8000-000000000018",`, `"team_id":"00000000-0000-4000-8000-000000000018","workload_profile_ref":{"name":"WEB","version":"v1"},`, 1)},
		{name: "resource profile ref", body: strings.Replace(validCreateRequestJSON(), `"team_id":"00000000-0000-4000-8000-000000000018",`, `"team_id":"00000000-0000-4000-8000-000000000018","resource_profile_ref":{"name":"SMALL_MULTI","version":"v1"},`, 1)},
		{name: "outbound mode", body: strings.Replace(validCreateRequestJSON(), `"workload":{`, `"workload":{"outbound_mode":"NONE",`, 1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var request CreateWorkloadRequest
			if err := json.Unmarshal([]byte(testCase.body), &request); err == nil {
				t.Fatal("Unmarshal() error = nil")
			}
		})
	}
}

func TestCreateWorkloadRequestKeepsDeprecatedSingleContainerInput(t *testing.T) {
	request := CreateWorkloadRequest{
		RequestID: "req-single", InstanceID: "018f3f1e-21b8-7a91-a30b-63b3400fd001", TeamID: "00000000-0000-4000-8000-000000000018",
		IsolationProfile: "WEB",
		Target:           RuntimeTarget{RuntimeType: RuntimeTypeKubernetes, TargetID: "aws-dev"},
		Workload: RuntimeWorkload{
			Image: "web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ContainerPort: 8080,
			ResourceLimits: ResourceLimits{CPUMillicores: 333, MemoryMiB: 444, EphemeralStorageMiB: 555},
		},
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	if len(command.Containers) != 1 || command.Containers[0].Name != "challenge" ||
		!command.Containers[0].Expose || command.PolicyRequest.Containers[0].RunAsUser != 10001 ||
		command.ResourceLimits != (provisioner.ResourceLimits{CPUMillicores: 333, MemoryMiB: 444, EphemeralStorageMiB: 555}) {
		t.Fatalf("command = %#v", command)
	}
}

func TestCreateWorkloadRequestAcceptsNullableOptionalIsolationRequirements(t *testing.T) {
	var request CreateWorkloadRequest
	if err := json.Unmarshal([]byte(`{
		"request_id":"req-nullable-policy",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":"00000000-0000-4000-8000-000000000018",
		"isolation_profile":"WEB",
		"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},
		"workload":{
			"containers":[
				{"name":"web","image":"web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ports":[8080],"expose":true,"run_as_user":101,"writable_paths":null},
				{"name":"api","image":"api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","ports":[9000],"expose":null,"run_as_user":10001}
			],
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

func TestCreateWorkloadRequestRejectsInvalidIsolationRequirements(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*CreateWorkloadRequest)
	}{
		{name: "root UID", mutate: func(request *CreateWorkloadRequest) { request.Workload.Containers[0].RunAsUser = 0 }},
		{name: "relative writable path", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].WritablePaths = []WritablePath{{Path: "tmp", SizeMiB: 8}}
		}},

		{name: "reserved writable path", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].WritablePaths = []WritablePath{{Path: "/proc/self", SizeMiB: 8}}
		}},
		{name: "writable paths exceed ephemeral storage", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].WritablePaths = []WritablePath{
				{Path: "/tmp/a", SizeMiB: 800},
				{Path: "/tmp/b", SizeMiB: 800},
			}
		}},
		{name: "Pwn exposes multiple containers", mutate: func(request *CreateWorkloadRequest) {
			request.IsolationProfile = "PWN"
			request.Workload.Containers[0].WritablePaths = nil
			request.Workload.Containers[0].Ports = []int{31337}
			request.Workload.Containers[1].Expose = true
			request.Workload.Containers[1].Ports = []int{31338}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := validCreateWorkloadRequest()
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

func TestCreateWorkloadRequestRejectsInvalidContainerSet(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*CreateWorkloadRequest)
	}{
		{name: "legacy and containers together", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Image = "legacy:latest"
			request.Workload.ContainerPort = 80
		}},
		{name: "duplicate names", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[1].Name = request.Workload.Containers[0].Name
		}},
		{name: "invalid DNS name", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].Name = "Not_Valid"
		}},
		{name: "empty image", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].Image = " "
		}},
		{name: "empty ports", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].Ports = nil
		}},
		{name: "invalid port", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].Ports = []int{65536}
		}},
		{name: "duplicate port", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].Ports = []int{8080, 8080}
		}},
		{name: "no exposed container", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].Expose = false
		}},
		{name: "aggregate resource smaller than container count", mutate: func(request *CreateWorkloadRequest) {
			request.Workload.ResourceLimits.CPUMillicores = 1
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := validCreateWorkloadRequest()
			testCase.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestCreateWorkloadRequestRequiresImmutableSHA256Images(t *testing.T) {
	for _, test := range []struct {
		name  string
		image string
		valid bool
	}{
		{name: "digest", image: "ghcr.io/msg-ctf/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", valid: true},
		{name: "latest", image: "ghcr.io/msg-ctf/web:latest"},
		{name: "tag only", image: "ghcr.io/msg-ctf/web:v1"},
		{name: "uppercase digest", image: "ghcr.io/msg-ctf/web@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{name: "short digest", image: "ghcr.io/msg-ctf/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validCreateWorkloadRequest()
			request.Workload.Containers[0].Image = test.image
			err := request.Validate()
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && err == nil {
				t.Fatal("mutable image accepted")
			}
		})
	}
}

func TestCreateWorkloadRequestRejectsDuplicateJSONKeysAtEveryObjectLevel(t *testing.T) {
	for _, body := range []string{
		strings.Replace(validCreateRequestJSON(), `"workload":{`, `"workload":null,"workload":{`, 1),
		strings.Replace(validCreateRequestJSON(), `"isolation_profile":"WEB"`, `"isolation_profile":"WEB","ISOLATION_PROFILE":"WEB"`, 1),
		strings.Replace(validCreateRequestJSON(), `"ports":[8080]`, `"ports":[8080],"ports":[8080]`, 1),
		strings.Replace(validCreateRequestJSON(), `"memory_mib":512`, `"memory_mib":512,"MEMORY_MIB":512`, 1),
	} {
		var request CreateWorkloadRequest
		if err := json.Unmarshal([]byte(body), &request); err == nil {
			t.Fatal("Unmarshal() error = nil")
		}
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
	for _, name := range []string{"MultiContainer", "Pwn", "DeprecatedSingleContainer", "ExplicitNullableRequirements"} {
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

func TestMaintainedMultiContainerRequestExampleDecodesAndValidates(t *testing.T) {
	encoded, err := os.ReadFile("../../examples/requests/create-multi-container.json")
	if err != nil {
		t.Fatal(err)
	}
	var request CreateWorkloadRequest
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatalf("decode maintained request example: %v", err)
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("validate maintained request example: %v", err)
	}
}

func TestCanonicalMVPRequestFixturesDecodeAndValidate(t *testing.T) {
	for _, name := range []string{"create-web-digest.json", "create-pwn-digest.json", "create-web-mixed-ports.json"} {
		encoded, err := os.ReadFile("../../examples/requests/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var request CreateWorkloadRequest
		if err := json.Unmarshal(encoded, &request); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if err := request.Validate(); err != nil {
			t.Fatalf("validate %s: %v", name, err)
		}
		if request.IsolationProfile != "WEB" && request.IsolationProfile != "PWN" {
			t.Fatalf("profile = %q", request.IsolationProfile)
		}
		if !strings.Contains(request.Workload.Containers[0].Image, "@sha256:") {
			t.Fatalf("%s image is not digest pinned", name)
		}
	}
	encoded, err := os.ReadFile("../../examples/requests/delete-ttl.json")
	if err != nil {
		t.Fatal(err)
	}
	var request DeleteWorkloadRequest
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	if request.Reason != DeleteReasonTTLExpired {
		t.Fatalf("delete_reason = %q", request.Reason)
	}
}

func validMultiCreateWorkloadRequest() CreateWorkloadRequest {
	return validCreateWorkloadRequest()
}

func validIsolationCreateWorkloadRequest() CreateWorkloadRequest {
	return validCreateWorkloadRequest()
}

func validCreateWorkloadRequest() CreateWorkloadRequest {
	return CreateWorkloadRequest{
		RequestID: "req-multi", InstanceID: "018f3f1e-21b8-7a91-a30b-63b3400fd001", TeamID: "00000000-0000-4000-8000-000000000018",
		IsolationProfile: "WEB",
		Target:           RuntimeTarget{RuntimeType: RuntimeTypeKubernetes, TargetID: "aws-dev"},
		Workload: RuntimeWorkload{
			Containers: []RuntimeContainer{
				{Name: "web", Image: "web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ports: []int{8080}, Expose: true, RunAsUser: 101, WritablePaths: []WritablePath{{Path: "/tmp/web", SizeMiB: 64}}},
				{Name: "api", Image: "api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Ports: []int{9000}, RunAsUser: 10001},
			},
			ResourceLimits: ResourceLimits{CPUMillicores: 500, MemoryMiB: 512, EphemeralStorageMiB: 1024},
		},
	}
}

func validCreateRequestJSON() string {
	return `{
		"request_id":"req-multi",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":"00000000-0000-4000-8000-000000000018",
		"isolation_profile":"WEB",
		"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},
		"workload":{
			"containers":[
				{"name":"web","image":"web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ports":[8080],"expose":true,"run_as_user":101,"writable_paths":[{"path":"/tmp/web","size_mib":64}]},
				{"name":"api","image":"api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","ports":[9000],"expose":false,"run_as_user":10001}
			],
			"resource_limits":{"cpu_millicores":500,"memory_mib":512,"ephemeral_storage_mib":1024}
		}
	}`
}
