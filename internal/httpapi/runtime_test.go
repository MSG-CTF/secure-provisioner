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
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
)

const runtimeInstanceID = "018f3f1e-21b8-7a91-a30b-63b3400fd001"

func TestRuntimeStatusReturnsContainerResourcesWithoutClusterSecrets(t *testing.T) {
	startedAt := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	runtime := &recordingRuntimeUseCase{
		status: k3s.RuntimeStatus{
			InstanceID:        runtimeInstanceID,
			TargetID:          "aws-dev",
			RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
			Phase:             "READY",
			EndpointReady:     true,
			MetricsAvailable:  true,
			ObservedAt:        startedAt.Add(time.Minute),
			Node: k3s.NodeRuntimeStatus{
				Ready:       true,
				Capacity:    k3s.ResourceValues{CPUMillicores: 2000, MemoryMiB: 4096, EphemeralStorageMiB: 20480},
				Allocatable: k3s.ResourceValues{CPUMillicores: 1800, MemoryMiB: 3584, EphemeralStorageMiB: 18432},
				Requested:   k3s.ResourceValues{CPUMillicores: 900, MemoryMiB: 1536, EphemeralStorageMiB: 4096},
				Schedulable: k3s.ResourceValues{CPUMillicores: 900, MemoryMiB: 2048, EphemeralStorageMiB: 14336},
				Usage:       &k3s.ResourceUsage{CPUMillicores: 640, MemoryMiB: 1720},
			},
			Containers: []k3s.ContainerRuntimeStatus{{
				PodName:      "challenge-76bf",
				Name:         "challenge",
				State:        "RUNNING",
				Ready:        true,
				RestartCount: 2,
				StartedAt:    &startedAt,
				Requests:     k3s.ResourceValues{CPUMillicores: 100, MemoryMiB: 128},
				Limits:       k3s.ResourceValues{CPUMillicores: 500, MemoryMiB: 512, EphemeralStorageMiB: 1024},
				Usage:        &k3s.ResourceUsage{CPUMillicores: 86, MemoryMiB: 146},
			}},
		},
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/internal/v1/instances/"+runtimeInstanceID+"/runtime-status", nil)

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if runtime.statusInstanceID != runtimeInstanceID {
		t.Fatalf("instance id = %q", runtime.statusInstanceID)
	}
	var payload struct {
		InstanceID       string `json:"instance_id"`
		TargetID         string `json:"target_id"`
		Phase            string `json:"phase"`
		EndpointReady    bool   `json:"endpoint_ready"`
		MetricsAvailable bool   `json:"metrics_available"`
		Node             struct {
			Ready       bool                   `json:"ready"`
			Requested   ResourceValuesResponse `json:"requested"`
			Schedulable ResourceValuesResponse `json:"schedulable"`
			Usage       *ResourceUsageResponse `json:"usage"`
		} `json:"node"`
		Containers []struct {
			Name         string `json:"name"`
			State        string `json:"state"`
			RestartCount int32  `json:"restart_count"`
			Usage        *struct {
				CPUMillicores int64 `json:"cpu_millicores"`
				MemoryMiB     int64 `json:"memory_mib"`
			} `json:"usage"`
		} `json:"containers"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.InstanceID != runtimeInstanceID || payload.TargetID != "aws-dev" || payload.Phase != "READY" ||
		!payload.EndpointReady || !payload.MetricsAvailable || len(payload.Containers) != 1 ||
		payload.Containers[0].RestartCount != 2 || payload.Containers[0].Usage.CPUMillicores != 86 ||
		!payload.Node.Ready || payload.Node.Requested.CPUMillicores != 900 ||
		payload.Node.Schedulable.MemoryMiB != 2048 || payload.Node.Usage.CPUMillicores != 640 {
		t.Fatalf("payload = %#v", payload)
	}
	body := response.Body.String()
	if strings.Contains(body, "kubeconfig") || strings.Contains(body, "api_server") || strings.Contains(body, "certificate") {
		t.Fatalf("response leaked cluster connection details: %s", body)
	}
}

func TestRuntimeStatusMapsMissingBindingToNotFound(t *testing.T) {
	runtime := &recordingRuntimeUseCase{statusErr: runtimebinding.ErrNotFound}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/internal/v1/instances/"+runtimeInstanceID+"/runtime-status", nil)

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertErrorCode(t, response, "INSTANCE_NOT_FOUND")
}

func TestRuntimeStatusMapsStableK3sErrors(t *testing.T) {
	for _, test := range []struct {
		code       string
		wantStatus int
	}{
		{code: "RUNTIME_IDENTITY_MISMATCH", wantStatus: http.StatusConflict},
		{code: "RUNTIME_OWNERSHIP_MISMATCH", wantStatus: http.StatusConflict},
		{code: "TARGET_NOT_FOUND", wantStatus: http.StatusServiceUnavailable},
		{code: "TARGET_TOPOLOGY_INVALID", wantStatus: http.StatusServiceUnavailable},
		{code: "TARGET_TEMPORARILY_UNAVAILABLE", wantStatus: http.StatusBadGateway},
	} {
		t.Run(test.code, func(t *testing.T) {
			runtime := &recordingRuntimeUseCase{statusErr: stableStatusError(test.code)}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/internal/v1/instances/"+runtimeInstanceID+"/runtime-status", nil)

			NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			assertErrorCode(t, response, test.code)
		})
	}
}

func TestDeleteInstanceQueuesBoundRuntimeOperation(t *testing.T) {
	runtime := &recordingRuntimeUseCase{
		operation: operations.Operation{
			ID:          "operation-delete-01",
			RequestID:   "req-delete-01",
			Type:        operations.OperationTypeDelete,
			Status:      operations.OperationStatusQueued,
			Attempt:     0,
			MaxAttempts: 3,
		},
		created: true,
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/internal/v1/instances/"+runtimeInstanceID, strings.NewReader(validDeleteRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	wantCommand := validDeleteWorkloadRequest().ToCommand()
	wantCommand.TargetID = "aws-dev"
	wantCommand.RuntimeWorkloadID = "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge"
	if runtime.deleteCommand != wantCommand {
		t.Fatalf("command = %#v", runtime.deleteCommand)
	}
	var payload OperationResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.OperationID != "operation-delete-01" || payload.Status != "QUEUED" ||
		payload.Created == nil || !*payload.Created {
		t.Fatalf("payload = %#v", payload)
	}
	if payload.RequestID != "req-delete-01" {
		t.Fatalf("request id = %q", payload.RequestID)
	}
	if got := response.Header().Get("Location"); got != "/internal/v1/operations/operation-delete-01" {
		t.Fatalf("Location = %q", got)
	}
	if got := response.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q", got)
	}
}

func TestDeleteInstanceRejectsPathBodyMismatch(t *testing.T) {
	runtime := &recordingRuntimeUseCase{}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/internal/v1/instances/028f3f1e-21b8-7a91-a30b-63b3400fd002", strings.NewReader(validDeleteRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if runtime.deleteCalls != 0 {
		t.Fatalf("delete calls = %d", runtime.deleteCalls)
	}
	assertErrorCode(t, response, "INSTANCE_BINDING_MISMATCH")
}

func TestDeleteInstanceMapsBindingConflictWithoutLeakingDetails(t *testing.T) {
	runtime := &recordingRuntimeUseCase{deleteErr: runtimeops.ErrBindingMismatch}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/internal/v1/instances/"+runtimeInstanceID, strings.NewReader(validDeleteRequestJSON()))
	request.Header.Set("Content-Type", "application/json")

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertErrorCode(t, response, "INSTANCE_BINDING_MISMATCH")
}

func TestDeleteInstanceMapsQueueErrorsWithoutLeakingDetails(t *testing.T) {
	for _, test := range []struct {
		name          string
		err           error
		wantStatus    int
		wantCode      string
		privateDetail string
	}{
		{name: "missing binding", err: runtimebinding.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: "INSTANCE_NOT_FOUND"},
		{name: "binding mismatch", err: runtimeops.ErrBindingMismatch, wantStatus: http.StatusConflict, wantCode: "INSTANCE_BINDING_MISMATCH"},
		{name: "request ID conflict", err: operations.ErrIdempotencyConflict, wantStatus: http.StatusConflict, wantCode: "REQUEST_ID_CONFLICT"},
		{name: "invalid transition", err: runtimebinding.ErrInvalidTransition, wantStatus: http.StatusConflict, wantCode: "INSTANCE_STATE_CONFLICT"},
		{name: "store failure", err: errors.New("private operation store detail"), wantStatus: http.StatusBadGateway, wantCode: "DELETE_QUEUE_FAILED", privateDetail: "private operation store detail"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &recordingRuntimeUseCase{deleteErr: test.err}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodDelete, "/internal/v1/instances/"+runtimeInstanceID, strings.NewReader(validDeleteRequestJSON()))
			request.Header.Set("Content-Type", "application/json")

			NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.privateDetail != "" {
				assertPublicErrorMessage(t, response, test.wantCode, test.privateDetail)
			} else {
				assertErrorCode(t, response, test.wantCode)
			}
		})
	}
}

func TestGetOperationReturnsProgress(t *testing.T) {
	runtime := &recordingRuntimeUseCase{
		operation: operations.Operation{
			ID:            "operation-delete-01",
			Type:          operations.OperationTypeDelete,
			Status:        operations.OperationStatusRetrying,
			Attempt:       1,
			MaxAttempts:   3,
			LastErrorCode: "TARGET_TEMPORARILY_UNAVAILABLE",
		},
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/internal/v1/operations/operation-delete-01", nil)

	NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload OperationResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.OperationID != "operation-delete-01" || payload.Status != "RETRYING" ||
		payload.Attempt != 1 || payload.MaxAttempts != 3 || payload.LastErrorCode != "TARGET_TEMPORARILY_UNAVAILABLE" {
		t.Fatalf("payload = %#v", payload)
	}
	if response.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After = %q", response.Header().Get("Retry-After"))
	}
}

func TestGetOperationReturnsCreateAndDeleteResults(t *testing.T) {
	tests := []struct {
		name      string
		operation operations.Operation
		want      OperationResultResponse
	}{
		{
			name: "create",
			operation: operations.Operation{
				ID:        "operation-create-01",
				RequestID: "req-create-01",
				Type:      operations.OperationTypeCreate,
				Status:    operations.OperationStatusSucceeded,
				Result: operations.OperationResult{Create: &provisioner.CreateWorkloadResult{
					RuntimeWorkloadID: "aws-dev/ns/challenge",
					NamespaceUID:      "namespace-uid-01",
					ServiceURL:        "https://challenge.example.test",
					Endpoints: []provisioner.WorkloadEndpoint{{
						ContainerName: "web",
						Port:          8080,
						ServiceURL:    "https://challenge.example.test",
					}},
				}},
			},
			want: OperationResultResponse{
				RuntimeWorkloadID: "aws-dev/ns/challenge",
				ServiceURL:        "https://challenge.example.test",
				Endpoints: []WorkloadEndpointResponse{{
					ContainerName: "web",
					Port:          8080,
					ServiceURL:    "https://challenge.example.test",
				}},
			},
		},
		{
			name: "delete",
			operation: operations.Operation{
				ID:            "operation-delete-01",
				RequestID:     "req-delete-01",
				Type:          operations.OperationTypeDelete,
				Status:        operations.OperationStatusSucceeded,
				DeleteCommand: &provisioner.DeleteWorkloadCommand{RuntimeWorkloadID: "aws-dev/ns/challenge"},
				Result:        operations.OperationResult{DeleteCompleted: true},
			},
			want: OperationResultResponse{
				RuntimeWorkloadID: "aws-dev/ns/challenge",
				Status:            "SUCCESS",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := &recordingRuntimeUseCase{operation: test.operation}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/internal/v1/operations/"+test.operation.ID, nil)

			NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

			body := response.Body.Bytes()
			if strings.Contains(string(body), "namespace_uid") {
				t.Fatalf("internal Namespace UID leaked in public response: %s", body)
			}
			var payload OperationResponse
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Result == nil || !reflect.DeepEqual(*payload.Result, test.want) {
				t.Fatalf("result = %#v, want %#v", payload.Result, test.want)
			}
			if response.Header().Get("Retry-After") != "" {
				t.Fatalf("terminal Retry-After = %q", response.Header().Get("Retry-After"))
			}
		})
	}
}

func TestGetOperationMapsLookupErrorsWithoutLeakingDetails(t *testing.T) {
	for _, test := range []struct {
		name          string
		err           error
		wantStatus    int
		wantCode      string
		privateDetail string
	}{
		{name: "operation not found", err: operations.ErrOperationNotFound, wantStatus: http.StatusNotFound, wantCode: "OPERATION_NOT_FOUND"},
		{name: "store failure", err: errors.New("private operation store detail"), wantStatus: http.StatusInternalServerError, wantCode: "OPERATION_LOOKUP_FAILED", privateDetail: "private operation store detail"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &recordingRuntimeUseCase{operationErr: test.err}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/internal/v1/operations/operation-01", nil)

			NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.privateDetail != "" {
				assertPublicErrorMessage(t, response, test.wantCode, test.privateDetail)
			} else {
				assertErrorCode(t, response, test.wantCode)
			}
		})
	}
}

func validDeleteRequestJSON() string {
	return `{"request_id":"req-delete-01","instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001","team_id":1,"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},"runtime_workload_id":"aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge","delete_reason":"USER_REQUESTED"}`
}

type recordingRuntimeUseCase struct {
	status           k3s.RuntimeStatus
	statusErr        error
	statusInstanceID string
	operation        operations.Operation
	created          bool
	deleteErr        error
	deleteCommand    provisioner.DeleteWorkloadCommand
	deleteCalls      int
	operationErr     error
	createErr        error
	createCommand    provisioner.CreateWorkloadCommand
	createCalls      int
}

func (useCase *recordingRuntimeUseCase) GetRuntimeStatus(_ context.Context, instanceID string) (k3s.RuntimeStatus, error) {
	useCase.statusInstanceID = instanceID
	return useCase.status, useCase.statusErr
}

func (useCase *recordingRuntimeUseCase) EnqueueDelete(command provisioner.DeleteWorkloadCommand) (operations.Operation, bool, error) {
	useCase.deleteCalls++
	useCase.deleteCommand = command
	return useCase.operation, useCase.created, useCase.deleteErr
}

func (useCase *recordingRuntimeUseCase) EnqueueCreate(command provisioner.CreateWorkloadCommand) (operations.Operation, bool, error) {
	useCase.createCalls++
	useCase.createCommand = command
	return useCase.operation, useCase.created, useCase.createErr
}

func (useCase *recordingRuntimeUseCase) GetOperation(string) (operations.Operation, error) {
	return useCase.operation, useCase.operationErr
}

var _ RuntimeUseCase = (*recordingRuntimeUseCase)(nil)

type stableStatusError string

func (e stableStatusError) Error() string {
	return string(e)
}

func (e stableStatusError) Code() string {
	return string(e)
}
