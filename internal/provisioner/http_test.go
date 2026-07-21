package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateInstanceAcceptsSchedulerContract(t *testing.T) {
	useCase := &recordingCreateUseCase{
		result: CreateWorkloadResult{
			RuntimeWorkloadID: "cluster-main/ns-team-1/workload-abc",
			ServiceURL:        "https://team-1.example.test",
		},
	}
	handler := NewHandler(useCase)
	body := `{
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

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	if useCase.calls != 1 {
		t.Fatalf("CreateWorkload() calls = %d, want 1", useCase.calls)
	}
	wantCommand := validCreateWorkloadRequest().ToCommand()
	if useCase.command != wantCommand {
		t.Fatalf("command = %#v, want %#v", useCase.command, wantCommand)
	}

	responseBody := append([]byte(nil), response.Body.Bytes()...)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(responseBody, &fields); err != nil {
		t.Fatalf("decode response fields: %v", err)
	}
	if len(fields) != 2 || fields["runtime_workload_id"] == nil || fields["service_url"] == nil {
		t.Fatalf("response fields = %v, want exactly runtime_workload_id and service_url", fields)
	}
	var result CreateWorkloadResult
	if err := json.Unmarshal(responseBody, &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result != useCase.result {
		t.Fatalf("result = %#v, want %#v", result, useCase.result)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}
}

func TestCreateInstanceRejectsInvalidJSONContracts(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "legacy camelCase",
			body: `{"requestId":"req-01","instanceId":"018f3f1e-21b8-7a91-a30b-63b3400fd001"}`,
		},
		{
			name: "unknown field",
			body: `{"request_id":"req-01","unexpected":true}`,
		},
		{
			name: "multiple objects",
			body: `{}` + "\n" + `{}`,
		},
		{
			name: "wrong field type",
			body: `{"request_id":"req-secret-value","instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001","team_id":"secret-team"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			useCase := &recordingCreateUseCase{}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")

			NewHandler(useCase).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
			}
			if useCase.calls != 0 {
				t.Fatalf("CreateWorkload() calls = %d, want 0", useCase.calls)
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

	NewHandler(useCase).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if useCase.calls != 0 {
		t.Fatalf("CreateWorkload() calls = %d, want 0", useCase.calls)
	}
	assertErrorCode(t, response, "INVALID_REQUEST")
}

func TestCreateInstanceHidesUseCaseFailureDetails(t *testing.T) {
	useCase := &recordingCreateUseCase{err: errors.New("kubeconfig contains secret-internal-path")}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandler(useCase).ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadGateway, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "secret-internal-path") {
		t.Fatalf("response leaked internal error: %s", response.Body.String())
	}
	assertErrorCode(t, response, "PROVISIONING_FAILED")
}

func TestCreateInstanceReportsUnavailableRuntime(t *testing.T) {
	useCase := &recordingCreateUseCase{err: ErrRuntimeUnavailable}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandler(useCase).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
	assertErrorCode(t, response, "RUNTIME_UNAVAILABLE")
}

func TestCreateInstanceRequiresJSONContentType(t *testing.T) {
	useCase := &recordingCreateUseCase{}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(validCreateRequestJSON()))
	request.Header.Set("Content-Type", "text/plain")

	NewHandler(useCase).ServeHTTP(response, request)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnsupportedMediaType, response.Body.String())
	}
	if useCase.calls != 0 {
		t.Fatalf("CreateWorkload() calls = %d, want 0", useCase.calls)
	}
	assertErrorCode(t, response, "UNSUPPORTED_MEDIA_TYPE")
}

type recordingCreateUseCase struct {
	result  CreateWorkloadResult
	err     error
	command CreateWorkloadCommand
	calls   int
}

func (useCase *recordingCreateUseCase) CreateWorkload(_ context.Context, command CreateWorkloadCommand) (CreateWorkloadResult, error) {
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
