package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestCreateInstanceAcceptsSchedulerContract(t *testing.T) {
	runtime := &recordingRuntimeUseCase{
		operation: operations.Operation{
			ID:          "operation-create-01",
			RequestID:   "req-01",
			Type:        operations.OperationTypeCreate,
			Status:      operations.OperationStatusQueued,
			MaxAttempts: 3,
		},
		created: true,
	}
	handler := NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusAccepted, response.Body.String())
	}
	if runtime.createCalls != 1 {
		t.Fatalf("EnqueueCreate() calls = %d, want 1", runtime.createCalls)
	}
	wantCommand := validCreateWorkloadRequest().ToCommand()
	if !reflect.DeepEqual(runtime.createCommand, wantCommand) {
		t.Fatalf("command = %#v, want %#v", runtime.createCommand, wantCommand)
	}
	if got := response.Header().Get("Location"); got != "/internal/v1/operations/operation-create-01" {
		t.Fatalf("Location = %q", got)
	}
	if got := response.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q", got)
	}
	var result OperationResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.OperationID != "operation-create-01" || result.RequestID != "req-01" ||
		result.Type != "CREATE" || result.Status != "QUEUED" || result.Created == nil || !*result.Created {
		t.Fatalf("result = %#v", result)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}
}

func TestCreateInstanceDirectPathResolvesPolicyBeforeCreate(t *testing.T) {
	useCase := &recordingCreateUseCase{}
	requestBody, err := json.Marshal(validIsolationCreateWorkloadRequest())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(string(requestBody)))
	request.Header.Set("Content-Type", "application/json")

	NewHandler(useCase).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	if useCase.calls != 1 || !useCase.command.Policy.Baseline.RunAsNonRoot ||
		!useCase.command.Policy.Baseline.ReadOnlyRootFilesystem ||
		useCase.command.ResourceLimits.MemoryMiB != 256 {
		t.Fatalf("calls = %d; command = %#v", useCase.calls, useCase.command)
	}
}

func TestCreateInstanceDirectPathMapsPolicyRejectionTo422(t *testing.T) {
	useCase := &recordingCreateUseCase{}
	createRequest := validIsolationCreateWorkloadRequest()
	createRequest.Workload.OutboundMode = "PUBLIC_INTERNET"
	requestBody, err := json.Marshal(createRequest)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(string(requestBody)))
	request.Header.Set("Content-Type", "application/json")

	NewHandler(useCase).ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity || useCase.calls != 0 {
		t.Fatalf("status = %d; calls = %d; body = %s", response.Code, useCase.calls, response.Body.String())
	}
	assertErrorCode(t, response, "ISOLATION_POLICY_REJECTED")
}

func TestCreateInstanceAcceptsLegacyWireContractWithSafePolicyDefaults(t *testing.T) {
	runtime := &recordingRuntimeUseCase{
		operation: operations.Operation{ID: "operation-legacy", RequestID: "req-legacy", Type: operations.OperationTypeCreate, Status: operations.OperationStatusQueued},
		created:   true,
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(`{
		"request_id":"req-legacy",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":1,
		"target":{"runtime_type":"KUBERNETES","target_id":"cluster-main"},
		"workload":{
			"image":"registry.msgctf.local/challenges/web-01@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"container_port":8080,
			"resource_limits":{"cpu_millicores":500,"memory_mib":512,"ephemeral_storage_mib":1024}
		}
	}`))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusAccepted || runtime.createCalls != 1 {
		t.Fatalf("status = %d; calls = %d; body = %s", response.Code, runtime.createCalls, response.Body.String())
	}
	command := runtime.createCommand
	if command.ChallengeRef != (provisioner.ChallengeRef{ChallengeID: "legacy", Version: "v1"}) ||
		command.PolicyRequest.IsolationRef != (isolation.ProfileRef{Name: "STANDARD", Version: "v1"}) ||
		command.PolicyRequest.ResourceRef != (isolation.ProfileRef{Name: "SMALL_SINGLE", Version: "v1"}) ||
		command.PolicyRequest.OutboundMode != isolation.OutboundNone ||
		command.PolicyRequest.Containers[0].RunAsUser != 10001 ||
		command.ResourceLimits != (provisioner.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128}) {
		t.Fatalf("legacy command = %#v", command)
	}
}

func TestCreateInstanceRejectsExplicitEmptyLegacyPolicyFields(t *testing.T) {
	legacySingle := legacyWireRequestJSON()
	legacyMulti := legacyMultiWireRequestJSON()
	testCases := []struct {
		name string
		body string
	}{
		{
			name: "empty isolation ref",
			body: strings.Replace(legacySingle, `"team_id":1,`, `"team_id":1,"isolation_ref":{},`, 1),
		},
		{
			name: "null isolation ref",
			body: strings.Replace(legacySingle, `"team_id":1,`, `"team_id":1,"isolation_ref":null,`, 1),
		},
		{
			name: "noncanonical empty isolation ref",
			body: strings.Replace(legacySingle, `"team_id":1,`, `"team_id":1,"ISOLATION_REF":{},`, 1),
		},
		{
			name: "empty outbound mode",
			body: strings.Replace(legacySingle, `"workload":{`, `"workload":{"outbound_mode":"",`, 1),
		},
		{
			name: "noncanonical workload with empty outbound mode",
			body: strings.Replace(legacySingle, `"workload":{`, `"WORKLOAD":{"outbound_mode":"",`, 1),
		},
		{
			name: "zero run as user",
			body: strings.Replace(legacyMulti, `"expose":true`, `"expose":true,"run_as_user":0`, 1),
		},
		{
			name: "empty writable paths",
			body: strings.Replace(legacyMulti, `"expose":true`, `"expose":true,"writable_paths":[]`, 1),
		},
		{
			name: "empty internal connections",
			body: strings.Replace(legacySingle, `"workload":{`, `"workload":{"internal_connections":[],`, 1),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			runtime := &recordingRuntimeUseCase{}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(testCase.body))
			request.Header.Set("Content-Type", "application/json")

			NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || runtime.createCalls != 0 {
				t.Fatalf("status = %d; calls = %d; body = %s", response.Code, runtime.createCalls, response.Body.String())
			}
			assertErrorCode(t, response, "INVALID_REQUEST")
		})
	}
}

func TestCreateInstanceStillRejectsRawContainerSecuritySettings(t *testing.T) {
	body := strings.Replace(
		legacyMultiWireRequestJSON(),
		`"expose":true`,
		`"expose":true,"security_context":{"privileged":true}`,
		1,
	)
	runtime := &recordingRuntimeUseCase{}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || runtime.createCalls != 0 {
		t.Fatalf("status = %d; calls = %d; body = %s", response.Code, runtime.createCalls, response.Body.String())
	}
	assertErrorCode(t, response, "INVALID_REQUEST")
}

func TestCreateInstanceRejectsDuplicateJSONKeysAtEveryObjectLevel(t *testing.T) {
	legacySingle := legacyWireRequestJSON()
	legacyMulti := legacyMultiWireRequestJSON()
	testCases := []struct {
		name string
		body string
	}{
		{
			name: "exact duplicate parent",
			body: strings.Replace(legacySingle, `"workload":{`, `"workload":null,"workload":{`, 1),
		},
		{
			name: "case variant duplicate parent",
			body: strings.Replace(legacySingle, `"workload":{`, `"WORKLOAD":null,"workload":{`, 1),
		},
		{
			name: "duplicate policy child",
			body: strings.Replace(
				validCreateRequestJSON(),
				`"isolation_ref":{"name":"STANDARD","version":"v1"}`,
				`"isolation_ref":{"name":"STANDARD","name":"STANDARD","version":"v1"}`,
				1,
			),
		},
		{
			name: "duplicate container field",
			body: strings.Replace(legacyMulti, `"ports":[8080]`, `"ports":[8080],"ports":[8080]`, 1),
		},
		{
			name: "case variant duplicate resource field",
			body: strings.Replace(legacySingle, `"memory_mib":512`, `"memory_mib":512,"MEMORY_MIB":512`, 1),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			runtime := &recordingRuntimeUseCase{}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(testCase.body))
			request.Header.Set("Content-Type", "application/json")

			NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || runtime.createCalls != 0 {
				t.Fatalf("status = %d; calls = %d; body = %s", response.Code, runtime.createCalls, response.Body.String())
			}
			assertErrorCode(t, response, "INVALID_REQUEST")
		})
	}
}

func TestCreateInstanceIncludesFalseCreatedForIdempotentReplay(t *testing.T) {
	runtime := &recordingRuntimeUseCase{
		operation: operations.Operation{
			ID:          "operation-create-01",
			RequestID:   "req-01",
			Type:        operations.OperationTypeCreate,
			Status:      operations.OperationStatusRunning,
			Attempt:     1,
			MaxAttempts: 3,
		},
		created: false,
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	var payload OperationResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Created == nil || *payload.Created {
		t.Fatalf("created = %#v", payload.Created)
	}
}

func TestCreateInstanceRejectsInvalidJSONContracts(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "legacy camelCase", body: `{"requestId":"req-01","instanceId":"018f3f1e-21b8-7a91-a30b-63b3400fd001"}`},
		{name: "unknown field", body: `{"request_id":"req-01","unexpected":true}`},
		{name: "multiple objects", body: `{}` + "\n" + `{}`},
		{name: "wrong field type", body: `{"request_id":"req-secret-value","instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001","team_id":"secret-team"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			useCase := &recordingCreateUseCase{}
			runtime := &recordingRuntimeUseCase{}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")

			NewHandlerWithRuntime(useCase, runtime).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
			}
			if runtime.createCalls != 0 {
				t.Fatalf("EnqueueCreate() calls = %d, want 0", runtime.createCalls)
			}
			if !strings.Contains(response.Body.String(), "invalid JSON request body") {
				t.Fatalf("response does not use stable decode error: %s", response.Body.String())
			}
			if strings.Contains(response.Body.String(), "CreateWorkloadRequest") || strings.Contains(response.Body.String(), "secret-team") {
				t.Fatalf("response leaked decoder details: %s", response.Body.String())
			}
			assertErrorCode(t, response, "INVALID_REQUEST")
		})
	}
}

func TestCreateInstanceRejectsInvalidResourceValues(t *testing.T) {
	useCase := &recordingCreateUseCase{}
	runtime := &recordingRuntimeUseCase{}
	body := `{
		"request_id":"req-01",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":1,
		"target":{"runtime_type":"KUBERNETES","target_id":"cluster-main"},
		"workload":{
			"image":"registry.example.test/challenge@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"container_port":8080,
			"resource_limits":{"cpu_millicores":0,"memory_mib":512,"ephemeral_storage_mib":1024}
		}
	}`
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")

	NewHandlerWithRuntime(useCase, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if runtime.createCalls != 0 {
		t.Fatalf("EnqueueCreate() calls = %d, want 0", runtime.createCalls)
	}
	assertErrorCode(t, response, "INVALID_REQUEST")
}

func TestCreateInstanceRejectsRequestIDConflict(t *testing.T) {
	useCase := &recordingCreateUseCase{}
	runtime := &recordingRuntimeUseCase{createErr: operations.ErrIdempotencyConflict}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(useCase, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusConflict, response.Body.String())
	}
	assertErrorCode(t, response, "REQUEST_ID_CONFLICT")
}

func TestCreateInstanceMapsQueueFailureWithoutLeakingStoreDetails(t *testing.T) {
	runtime := &recordingRuntimeUseCase{createErr: errors.New("private operation store detail")}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadGateway, response.Body.String())
	}
	assertPublicErrorMessage(t, response, "CREATE_QUEUE_FAILED", "private operation store detail")
}

func TestCreateRejectsIsolationPolicy(t *testing.T) {
	runtime := &recordingRuntimeUseCase{createErr: isolation.ErrPolicyRejected}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnprocessableEntity, response.Body.String())
	}
	assertErrorCode(t, response, "ISOLATION_POLICY_REJECTED")
}

func TestCreateInstanceRequiresJSONContentType(t *testing.T) {
	useCase := &recordingCreateUseCase{}
	runtime := &recordingRuntimeUseCase{}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "text/plain")

	NewHandlerWithRuntime(useCase, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnsupportedMediaType, response.Body.String())
	}
	if runtime.createCalls != 0 {
		t.Fatalf("EnqueueCreate() calls = %d, want 0", runtime.createCalls)
	}
	assertErrorCode(t, response, "UNSUPPORTED_MEDIA_TYPE")
}

type recordingCreateUseCase struct {
	result  provisioner.CreateWorkloadResult
	err     error
	command provisioner.CreateWorkloadCommand
	calls   int
}

func legacyWireRequestJSON() string {
	return `{
		"request_id":"req-legacy",
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

func legacyMultiWireRequestJSON() string {
	return `{
		"request_id":"req-legacy-multi",
		"instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"team_id":18,
		"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},
		"workload":{
			"containers":[
				{"name":"web","image":"web:latest","ports":[8080],"expose":true},
				{"name":"api","image":"api:latest","ports":[8080],"expose":false}
			],
			"resource_limits":{"cpu_millicores":501,"memory_mib":513,"ephemeral_storage_mib":1025}
		}
	}`
}

func (useCase *recordingCreateUseCase) CreateWorkload(_ context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	useCase.calls++
	useCase.command = command
	return useCase.result, useCase.err
}

type apiErrorEnvelope struct {
	Error struct {
		Code    string  `json:"code"`
		Message *string `json:"message"`
	} `json:"error"`
}

func assertErrorCode(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	_ = assertAPIErrorEnvelope(t, response, want)
}

func assertPublicErrorMessage(t *testing.T, response *httptest.ResponseRecorder, wantCode, privateDetail string) {
	t.Helper()
	rawBody := response.Body.String()
	payload := assertAPIErrorEnvelope(t, response, wantCode)
	if payload.Error.Message == nil {
		t.Fatal("error message is missing")
	}
	if strings.TrimSpace(*payload.Error.Message) == "" {
		t.Fatal("error message is empty")
	}
	if strings.Contains(rawBody, privateDetail) {
		t.Fatalf("response leaked private error detail: %s", rawBody)
	}
}

func assertAPIErrorEnvelope(t *testing.T, response *httptest.ResponseRecorder, wantCode string) apiErrorEnvelope {
	t.Helper()
	var payload apiErrorEnvelope
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Error.Code != wantCode {
		t.Fatalf("error code = %q, want %q", payload.Error.Code, wantCode)
	}
	return payload
}
