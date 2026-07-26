package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		Containers       []struct {
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
		payload.Containers[0].RestartCount != 2 || payload.Containers[0].Usage.CPUMillicores != 86 {
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

func TestDeleteInstanceQueuesBoundRuntimeOperation(t *testing.T) {
	runtime := &recordingRuntimeUseCase{
		operation: operations.Operation{
			ID:          "operation-delete-01",
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
	if payload.OperationID != "operation-delete-01" || payload.Status != "QUEUED" || !payload.Created {
		t.Fatalf("payload = %#v", payload)
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
}

func validDeleteRequestJSON() string {
	return `{"request_id":"req-delete-01","instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001","team_id":1,"target":{"runtime_type":"KUBERNETES","target_id":"aws-dev"},"runtime_workload_id":"aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge","reason":"USER_REQUESTED"}`
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

func (useCase *recordingRuntimeUseCase) GetOperation(string) (operations.Operation, error) {
	return useCase.operation, useCase.operationErr
}

var _ RuntimeUseCase = (*recordingRuntimeUseCase)(nil)
