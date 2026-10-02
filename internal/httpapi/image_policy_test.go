package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

const gradePolicyImage = "ghcr.io/msg-ctf/challenges/web-grade-tampering/web@sha256:9ffbf4761b09e0d182e444bb8793343cdc9633b72692aa516b777cf9c750956d"

const testImagePolicies = `{
  "schema_version": 1,
  "managed_repositories": ["ghcr.io/msg-ctf/challenges/web-grade-tampering/web"],
  "images": [{
    "image": "` + gradePolicyImage + `",
    "container": "web",
    "isolation_profile": "WEB",
    "status": "create_enabled",
    "run_as_user": 10001,
    "ports": [8080],
    "exposed_ports": [8080],
    "writable_paths": [
      {"path": "/tmp", "size_mib": 32},
      {"path": "/app/instance", "size_mib": 32}
    ]
  }]
}`

func TestImagePolicyListsOnlyEnabledFlagRequirements(t *testing.T) {
	withFlag := strings.Replace(testImagePolicies, `"status": "create_enabled",`, `"status": "create_enabled", "requires_flag": true,`, 1)
	catalog, err := ParseImagePolicies([]byte(withFlag))
	if err != nil {
		t.Fatal(err)
	}
	images := catalog.RequiredFlagImages()
	if len(images) != 1 || images[0] != gradePolicyImage || !catalog.AllowsFlag(gradePolicyImage) ||
		catalog.AllowsFlag("registry.example.invalid/unknown@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("FLAG requirements = %v", images)
	}
}

func TestImagePolicyOverridesKnownDigestBeforeValidation(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(testImagePolicies))
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{{
		Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true,
		RunAsUser: 10001, WritablePaths: []WritablePath{{Path: "/tmp", SizeMiB: 64}},
	}}
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	container := request.Workload.Containers[0]
	if container.Expose || len(container.ExposedPorts) != 1 || container.ExposedPorts[0] != 8080 {
		t.Fatalf("public ports were not pinned: %+v", container)
	}
	if len(container.WritablePaths) != 2 || container.WritablePaths[0].SizeMiB != 32 || container.WritablePaths[1].Path != "/app/instance" {
		t.Fatalf("writable paths were not pinned: %+v", container.WritablePaths)
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("overridden request is invalid: %v", err)
	}
}

func TestImagePolicyRejectsUnreviewedDigestAndWrongContainer(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(testImagePolicies))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, image, container string
	}{
		{"new digest", strings.Replace(gradePolicyImage, "9ffbf", "affbf", 1), "web"},
		{"wrong container", gradePolicyImage, "other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validCreateWorkloadRequest()
			request.Workload.Containers = []RuntimeContainer{{Name: test.container, Image: test.image, Ports: []int{8080}, Expose: true, RunAsUser: 10001}}
			if err := catalog.Apply(&request); err == nil {
				t.Fatal("unreviewed image policy was accepted")
			}
		})
	}
}

func TestImagePolicyLeavesUnmanagedImagesUnchanged(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(testImagePolicies))
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateWorkloadRequest()
	before := request.Workload.Containers[0].WritablePaths[0]
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	if got := request.Workload.Containers[0].WritablePaths[0]; got != before {
		t.Fatalf("unmanaged image changed: %+v", got)
	}
}

func TestImagePolicyRejectsUnreviewedCompanionContainer(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(testImagePolicies))
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{
		{Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true, RunAsUser: 10001},
		{Name: "sidecar", Image: "ghcr.io/msg-ctf/other@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ports: []int{9000}, RunAsUser: 10001},
	}
	if err := catalog.Apply(&request); err == nil {
		t.Fatal("unreviewed companion was accepted with managed challenge image")
	}
}

func TestImagePolicyRejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(testImagePolicies, `"schema_version": 1,`, `"schema_version": 1, "privileged": true,`, 1),
		strings.Replace(testImagePolicies, `"schema_version": 1,`, `"schema_version": 1, "schema_version": 1,`, 1),
	} {
		if _, err := ParseImagePolicies([]byte(raw)); err == nil {
			t.Fatal("invalid policy file accepted")
		}
	}
}

func TestImagePolicyRejectsDuplicateImagesAndReservedPaths(t *testing.T) {
	var config imagePolicyFile
	if err := json.Unmarshal([]byte(testImagePolicies), &config); err != nil {
		t.Fatal(err)
	}
	config.Images = append(config.Images, config.Images[0])
	duplicate, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseImagePolicies(duplicate); err == nil {
		t.Fatal("duplicate image accepted")
	}
	config.Images = config.Images[:1]
	config.Images[0].WritablePaths[1].Path = "/var/run/secrets/kubernetes.io"
	reserved, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseImagePolicies(reserved); err == nil {
		t.Fatal("reserved writable path accepted")
	}
}

func TestCreateHandlerAppliesImagePolicyToQueuedCommand(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(testImagePolicies))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &recordingRuntimeUseCase{operation: operations.Operation{
		ID: "operation-image-policy", RequestID: "req-multi", Type: operations.OperationTypeCreate,
		Status: operations.OperationStatusQueued, MaxAttempts: 3,
	}, created: true}
	handler := withTestServiceAuthentication(NewHandlerWithRuntimePolicies(&recordingCreateUseCase{}, runtime, ServiceAuthConfig{CurrentToken: testCurrentServiceToken}, catalog))
	requestBody := validCreateWorkloadRequest()
	requestBody.Workload.Containers = []RuntimeContainer{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true, RunAsUser: 10001, WritablePaths: []WritablePath{{Path: "/tmp", SizeMiB: 64}}}}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(string(encoded)))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if runtime.createCalls != 1 || runtime.createCommand.PolicyRequest.Containers[0].WritablePaths[1].Path != "/app/instance" {
		t.Fatalf("queued command lacks reviewed writable paths: %+v", runtime.createCommand)
	}
	if publicPorts := runtime.createCommand.Containers[0].PublicPorts(); len(publicPorts) != 1 || publicPorts[0] != 8080 {
		t.Fatalf("queued command public ports = %v", publicPorts)
	}
}

func TestCreateHandlerRejectsManagedImageWithoutPolicy(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(testImagePolicies))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &recordingRuntimeUseCase{}
	handler := withTestServiceAuthentication(NewHandlerWithRuntimePolicies(&recordingCreateUseCase{}, runtime, ServiceAuthConfig{CurrentToken: testCurrentServiceToken}, catalog))
	requestBody := validCreateWorkloadRequest()
	requestBody.Workload.Containers = []RuntimeContainer{{Name: "web", Image: strings.Replace(gradePolicyImage, "9ffbf", "affbf", 1), Ports: []int{8080}, Expose: true, RunAsUser: 10001}}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(string(encoded)))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity || runtime.createCalls != 0 {
		t.Fatalf("status = %d, create calls = %d", response.Code, runtime.createCalls)
	}
}

func TestPublishedWebImagePoliciesKeepUnverifiedChallengesBlocked(t *testing.T) {
	catalog, err := LoadImagePolicies("../../config/web-image-policies.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		image string
		ready bool
	}{
		{gradePolicyImage, true},
		{"ghcr.io/msg-ctf/challenges/web-daily-point/web@sha256:98c98088662fd5ff538ae9e163fb4a68ad73580e0f4f703624b0650d4a2b499a", true},
		{"ghcr.io/msg-ctf/challenges/web-open-house/web@sha256:6a3ab6373bdee16229dfda362d41dd10bd59ede5b05249557d332a3d5d22b8bd", true},
		{"ghcr.io/msg-ctf/challenges/web-logout-please/service@sha256:c4407d4218a5f4261152e60c45813af2d1fa4e16917b4aea2e7241600a8ab702", false},
		{"ghcr.io/msg-ctf/challenges/web-notebook/db@sha256:7a40ab203a9f16d06269a4506f1f99b770e2991bb0d5c4ee072fddaea722cea0", false},
	} {
		policy, found := catalog.images[test.image]
		if !found || (policy.Status == "create_enabled") != test.ready {
			t.Fatalf("image policy for %q = %+v, found = %v", test.image, policy, found)
		}
	}
	if _, managed := catalog.managed["ghcr.io/msg-ctf/challenges/web-afterimage/indexer"]; !managed {
		t.Fatal("unpublished AFTERIMAGE image repository is not fail-closed")
	}
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{{
		Name: "service", Image: "ghcr.io/msg-ctf/challenges/web-logout-please/service@sha256:c4407d4218a5f4261152e60c45813af2d1fa4e16917b4aea2e7241600a8ab702",
		Ports: []int{8080, 9090}, Expose: true, RunAsUser: 10001,
	}}
	if err := catalog.Apply(&request); err == nil {
		t.Fatal("unverified Logout Please image was accepted")
	}
}
