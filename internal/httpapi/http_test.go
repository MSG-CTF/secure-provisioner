package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	if runtime.createCommand != wantCommand {
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
	assertErrorCode(t, response, "CREATE_QUEUE_FAILED")
	if strings.Contains(response.Body.String(), "private operation store detail") {
		t.Fatalf("response leaked queue error details: %s", response.Body.String())
	}
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

func (useCase *recordingCreateUseCase) CreateWorkload(_ context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	useCase.calls++
	useCase.command = command
	return useCase.result, useCase.err
}

func assertErrorCode(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Error.Code != want {
		t.Fatalf("error code = %q, want %q", payload.Error.Code, want)
	}
}
