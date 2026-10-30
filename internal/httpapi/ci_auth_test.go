package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

const (
	testCISmokeToken = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	testCITeamID     = "f33df6f0-52ee-4e63-b409-3df4d0a4b314"
)

func ciSmokeAuthConfig(t *testing.T) ServiceAuthConfig {
	t.Helper()
	var config ServiceAuthConfig
	if err := json.Unmarshal([]byte(`{"CurrentToken":"`+testCurrentServiceToken+`","CISmokeToken":"`+testCISmokeToken+`","CISmokeTeamID":"`+testCITeamID+`","CISmokeTargetID":"aws-dev"}`), &config); err != nil {
		t.Fatal(err)
	}
	return config
}

func ciSmokeCatalog(t *testing.T) *ImagePolicyCatalog {
	t.Helper()
	policy := strings.Replace(testImagePolicies, `"status": "create_enabled",`, `"status": "create_enabled", "ci_smoke_enabled": true,`, 1)
	catalog, err := ParseImagePolicies([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func ciSmokeCreateRequest(t *testing.T) []byte {
	t.Helper()
	request := validCreateWorkloadRequest()
	request.TeamID = provisioner.TeamID(testCITeamID)
	request.Workload.Containers = []RuntimeContainer{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true, RunAsUser: 10001}}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func ciSmokeCall(handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer "+testCISmokeToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestCISmokeTokenCreatesOnlyApprovedImageForDedicatedTeamAndTarget(t *testing.T) {
	runtime := &recordingRuntimeUseCase{operation: operations.Operation{ID: "ci-create", RequestID: "req-multi", Type: operations.OperationTypeCreate, Status: operations.OperationStatusQueued, MaxAttempts: 3}, created: true}
	handler := NewHandlerWithRuntimePolicies(&recordingCreateUseCase{}, runtime, ciSmokeAuthConfig(t), ciSmokeCatalog(t))
	allowed := ciSmokeCall(handler, http.MethodPost, "/internal/v1/instances", ciSmokeCreateRequest(t))
	if allowed.Code != http.StatusAccepted || runtime.createCalls != 1 {
		t.Fatalf("approved CI create: status=%d calls=%d body=%s", allowed.Code, runtime.createCalls, allowed.Body.String())
	}
	for _, test := range []struct {
		name   string
		mutate func(*CreateWorkloadRequest)
	}{
		{"other team", func(request *CreateWorkloadRequest) { request.TeamID = "00000000-0000-4000-8000-000000000099" }},
		{"other target", func(request *CreateWorkloadRequest) { request.Target.TargetID = "other-target" }},
		{"unapproved image", func(request *CreateWorkloadRequest) {
			request.Workload.Containers[0].Image = strings.Replace(gradePolicyImage, "9ffbf", "affbf", 1)
		}},
		{"oversized resources", func(request *CreateWorkloadRequest) {
			request.Workload.ResourceLimits = ResourceLimits{CPUMillicores: 1000, MemoryMiB: 1024, EphemeralStorageMiB: 2048}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var request CreateWorkloadRequest
			if err := json.Unmarshal(ciSmokeCreateRequest(t), &request); err != nil {
				t.Fatal(err)
			}
			test.mutate(&request)
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			response := ciSmokeCall(handler, http.MethodPost, "/internal/v1/instances", encoded)
			if response.Code != http.StatusForbidden || runtime.createCalls != 1 {
				t.Fatalf("restricted CI create: status=%d calls=%d body=%s", response.Code, runtime.createCalls, response.Body.String())
			}
		})
	}
}

func TestCISmokeTokenCannotReadOtherTeamStatusOrOperation(t *testing.T) {
	runtime := &recordingRuntimeUseCase{}
	if err := json.Unmarshal([]byte(`{"InstanceID":"018f3f1e-21b8-7a91-a30b-63b3400fd001","TeamID":"00000000-0000-4000-8000-000000000099","TargetID":"aws-dev","Phase":"READY"}`), &runtime.status); err != nil {
		t.Fatal(err)
	}
	runtime.operation = operations.Operation{ID: "foreign", Type: operations.OperationTypeCreate, Status: operations.OperationStatusSucceeded, CreateCommand: &provisioner.CreateWorkloadCommand{TeamID: "00000000-0000-4000-8000-000000000099", TargetID: "aws-dev"}}
	handler := NewHandlerWithRuntimePolicies(&recordingCreateUseCase{}, runtime, ciSmokeAuthConfig(t), ciSmokeCatalog(t))
	for _, path := range []string{"/internal/v1/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001/runtime-status", "/internal/v1/operations/foreign"} {
		response := ciSmokeCall(handler, http.MethodGet, path, nil)
		if response.Code != http.StatusForbidden {
			t.Fatalf("CI GET %s: status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestCISmokeTokenCannotDeleteOtherTeamInstance(t *testing.T) {
	runtime := &recordingRuntimeUseCase{}
	handler := NewHandlerWithRuntimePolicies(&recordingCreateUseCase{}, runtime, ciSmokeAuthConfig(t), ciSmokeCatalog(t))
	response := ciSmokeCall(handler, http.MethodDelete, "/internal/v1/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001", []byte(validDeleteRequestJSON()))
	if response.Code != http.StatusForbidden || runtime.deleteCalls != 0 {
		t.Fatalf("CI foreign delete: status=%d calls=%d body=%s", response.Code, runtime.deleteCalls, response.Body.String())
	}
}
