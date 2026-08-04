package httpapi

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
)

type RuntimeUseCase interface {
	EnqueueCreate(provisioner.CreateWorkloadCommand) (operations.Operation, bool, error)
	GetRuntimeStatus(context.Context, string) (k3s.RuntimeStatus, error)
	EnqueueDelete(provisioner.DeleteWorkloadCommand) (operations.Operation, bool, error)
	GetOperation(string) (operations.Operation, error)
}

type RuntimeStatusResponse struct {
	InstanceID        string                    `json:"instance_id"`
	TargetID          string                    `json:"target_id"`
	RuntimeWorkloadID string                    `json:"runtime_workload_id"`
	Phase             string                    `json:"phase"`
	EndpointReady     bool                      `json:"endpoint_ready"`
	MetricsAvailable  bool                      `json:"metrics_available"`
	ObservedAt        time.Time                 `json:"observed_at"`
	Node              NodeStatusResponse        `json:"node"`
	Containers        []ContainerStatusResponse `json:"containers"`
}

type NodeStatusResponse struct {
	Ready          bool                   `json:"ready"`
	MemoryPressure bool                   `json:"memory_pressure"`
	DiskPressure   bool                   `json:"disk_pressure"`
	PIDPressure    bool                   `json:"pid_pressure"`
	Capacity       ResourceValuesResponse `json:"capacity"`
	Allocatable    ResourceValuesResponse `json:"allocatable"`
	Requested      ResourceValuesResponse `json:"requested"`
	Schedulable    ResourceValuesResponse `json:"schedulable"`
	Usage          *ResourceUsageResponse `json:"usage"`
}

type ContainerStatusResponse struct {
	PodName      string                 `json:"pod_name"`
	Name         string                 `json:"name"`
	State        string                 `json:"state"`
	Ready        bool                   `json:"ready"`
	RestartCount int32                  `json:"restart_count"`
	Reason       string                 `json:"reason,omitempty"`
	ExitCode     int32                  `json:"exit_code,omitempty"`
	StartedAt    *time.Time             `json:"started_at,omitempty"`
	FinishedAt   *time.Time             `json:"finished_at,omitempty"`
	Requests     ResourceValuesResponse `json:"requests"`
	Limits       ResourceValuesResponse `json:"limits"`
	Usage        *ResourceUsageResponse `json:"usage"`
}

type ResourceValuesResponse struct {
	CPUMillicores       int64 `json:"cpu_millicores"`
	MemoryMiB           int64 `json:"memory_mib"`
	EphemeralStorageMiB int64 `json:"ephemeral_storage_mib"`
}

type ResourceUsageResponse struct {
	CPUMillicores int64 `json:"cpu_millicores"`
	MemoryMiB     int64 `json:"memory_mib"`
}

type OperationResponse struct {
	OperationID   string                   `json:"operation_id"`
	RequestID     string                   `json:"request_id"`
	Type          string                   `json:"type"`
	Status        string                   `json:"status"`
	Attempt       int                      `json:"attempt"`
	MaxAttempts   int                      `json:"max_attempts"`
	LastErrorCode string                   `json:"last_error_code,omitempty"`
	Created       *bool                    `json:"created,omitempty"`
	Result        *OperationResultResponse `json:"result,omitempty"`
}

type OperationResultResponse struct {
	RuntimeWorkloadID string                     `json:"runtime_workload_id"`
	ServiceURL        string                     `json:"service_url,omitempty"`
	Endpoints         []WorkloadEndpointResponse `json:"endpoints,omitempty"`
	Status            string                     `json:"status,omitempty"`
}

type WorkloadEndpointResponse struct {
	ContainerName string `json:"container_name"`
	Port          int    `json:"port"`
	ServiceURL    string `json:"service_url"`
}

func (api *API) handleRuntimeStatus(writer http.ResponseWriter, request *http.Request) {
	status, err := api.runtime.GetRuntimeStatus(request.Context(), request.PathValue("instance_id"))
	if err != nil {
		if errors.Is(err, runtimebinding.ErrNotFound) {
			writeAPIError(writer, http.StatusNotFound, "INSTANCE_NOT_FOUND", "instance runtime binding was not found")
			return
		}
		if writeRuntimeStatusError(writer, err) {
			return
		}
		writeAPIError(writer, http.StatusBadGateway, "RUNTIME_STATUS_FAILED", "runtime status lookup failed")
		return
	}
	writeJSON(writer, http.StatusOK, newRuntimeStatusResponse(status))
}

func writeRuntimeStatusError(writer http.ResponseWriter, err error) bool {
	var coded interface{ Code() string }
	if !errors.As(err, &coded) {
		return false
	}
	switch coded.Code() {
	case "RUNTIME_IDENTITY_MISMATCH":
		writeAPIError(writer, http.StatusConflict, coded.Code(), "runtime identity does not match the stored binding")
	case "RUNTIME_OWNERSHIP_MISMATCH":
		writeAPIError(writer, http.StatusConflict, coded.Code(), "runtime ownership does not match the stored binding")
	case "TARGET_NOT_FOUND":
		writeAPIError(writer, http.StatusServiceUnavailable, coded.Code(), "runtime target was not found")
	case "TARGET_TOPOLOGY_INVALID":
		writeAPIError(writer, http.StatusServiceUnavailable, coded.Code(), "runtime target must contain exactly one node")
	case "TARGET_TEMPORARILY_UNAVAILABLE", "K3S_UNAVAILABLE":
		writeAPIError(writer, http.StatusBadGateway, coded.Code(), "runtime target is temporarily unavailable")
	default:
		return false
	}
	return true
}

func (api *API) handleDeleteInstance(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
		return
	}

	var deleteRequest DeleteWorkloadRequest
	if err := decodeJSON(request, &deleteRequest); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON request body")
		return
	}
	if err := deleteRequest.Validate(); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if deleteRequest.InstanceID != request.PathValue("instance_id") {
		writeAPIError(writer, http.StatusConflict, "INSTANCE_BINDING_MISMATCH", "request does not match the stored runtime binding")
		return
	}

	operation, created, err := api.runtime.EnqueueDelete(deleteRequest.ToCommand())
	if err != nil {
		writeDeleteError(writer, err)
		return
	}
	writeAcceptedOperation(writer, operation, created)
}

func (api *API) handleGetOperation(writer http.ResponseWriter, request *http.Request) {
	operation, err := api.runtime.GetOperation(request.PathValue("operation_id"))
	if err != nil {
		if errors.Is(err, operations.ErrOperationNotFound) {
			writeAPIError(writer, http.StatusNotFound, "OPERATION_NOT_FOUND", "operation was not found")
			return
		}
		writeAPIError(writer, http.StatusInternalServerError, "OPERATION_LOOKUP_FAILED", "operation lookup failed")
		return
	}
	if operationNeedsPolling(operation.Status) {
		writer.Header().Set("Retry-After", "2")
	}
	writeJSON(writer, http.StatusOK, newOperationResponse(operation))
}

func writeAcceptedOperation(writer http.ResponseWriter, operation operations.Operation, created bool) {
	writer.Header().Set("Location", "/internal/v1/operations/"+url.PathEscape(operation.ID))
	writer.Header().Set("Retry-After", "2")
	response := newOperationResponse(operation)
	response.Created = &created
	writeJSON(writer, http.StatusAccepted, response)
}

func operationNeedsPolling(status operations.OperationStatus) bool {
	switch status {
	case operations.OperationStatusQueued, operations.OperationStatusRunning, operations.OperationStatusRetrying:
		return true
	default:
		return false
	}
}

func writeDeleteError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, runtimebinding.ErrNotFound):
		writeAPIError(writer, http.StatusNotFound, "INSTANCE_NOT_FOUND", "instance runtime binding was not found")
	case errors.Is(err, runtimeops.ErrBindingMismatch):
		writeAPIError(writer, http.StatusConflict, "INSTANCE_BINDING_MISMATCH", "request does not match the stored runtime binding")
	case errors.Is(err, operations.ErrIdempotencyConflict):
		writeAPIError(writer, http.StatusConflict, "REQUEST_ID_CONFLICT", "request_id is already used by another operation")
	case errors.Is(err, runtimebinding.ErrInvalidTransition):
		writeAPIError(writer, http.StatusConflict, "INSTANCE_STATE_CONFLICT", "instance cannot be deleted from its current state")
	default:
		writeAPIError(writer, http.StatusBadGateway, "DELETE_QUEUE_FAILED", "workload deletion could not be queued")
	}
}

func newRuntimeStatusResponse(status k3s.RuntimeStatus) RuntimeStatusResponse {
	response := RuntimeStatusResponse{
		InstanceID:        status.InstanceID,
		TargetID:          status.TargetID,
		RuntimeWorkloadID: status.RuntimeWorkloadID,
		Phase:             status.Phase,
		EndpointReady:     status.EndpointReady,
		MetricsAvailable:  status.MetricsAvailable,
		ObservedAt:        status.ObservedAt,
		Node: NodeStatusResponse{
			Ready:          status.Node.Ready,
			MemoryPressure: status.Node.MemoryPressure,
			DiskPressure:   status.Node.DiskPressure,
			PIDPressure:    status.Node.PIDPressure,
			Capacity:       newResourceValuesResponse(status.Node.Capacity),
			Allocatable:    newResourceValuesResponse(status.Node.Allocatable),
			Requested:      newResourceValuesResponse(status.Node.Requested),
			Schedulable:    newResourceValuesResponse(status.Node.Schedulable),
		},
		Containers: make([]ContainerStatusResponse, 0, len(status.Containers)),
	}
	if status.Node.Usage != nil {
		response.Node.Usage = &ResourceUsageResponse{
			CPUMillicores: status.Node.Usage.CPUMillicores,
			MemoryMiB:     status.Node.Usage.MemoryMiB,
		}
	}
	for _, container := range status.Containers {
		item := ContainerStatusResponse{
			PodName:      container.PodName,
			Name:         container.Name,
			State:        container.State,
			Ready:        container.Ready,
			RestartCount: container.RestartCount,
			Reason:       container.Reason,
			ExitCode:     container.ExitCode,
			StartedAt:    container.StartedAt,
			FinishedAt:   container.FinishedAt,
			Requests:     newResourceValuesResponse(container.Requests),
			Limits:       newResourceValuesResponse(container.Limits),
		}
		if container.Usage != nil {
			item.Usage = &ResourceUsageResponse{
				CPUMillicores: container.Usage.CPUMillicores,
				MemoryMiB:     container.Usage.MemoryMiB,
			}
		}
		response.Containers = append(response.Containers, item)
	}
	return response
}

func newResourceValuesResponse(values k3s.ResourceValues) ResourceValuesResponse {
	return ResourceValuesResponse{
		CPUMillicores:       values.CPUMillicores,
		MemoryMiB:           values.MemoryMiB,
		EphemeralStorageMiB: values.EphemeralStorageMiB,
	}
}

func newOperationResponse(operation operations.Operation) OperationResponse {
	return OperationResponse{
		OperationID:   operation.ID,
		RequestID:     operation.RequestID,
		Type:          string(operation.Type),
		Status:        string(operation.Status),
		Attempt:       operation.Attempt,
		MaxAttempts:   operation.MaxAttempts,
		LastErrorCode: operation.LastErrorCode,
		Result:        newOperationResultResponse(operation),
	}
}

func newOperationResultResponse(operation operations.Operation) *OperationResultResponse {
	if operation.Status != operations.OperationStatusSucceeded {
		return nil
	}
	switch operation.Type {
	case operations.OperationTypeCreate:
		if operation.Result.Create == nil {
			return nil
		}
		response := &OperationResultResponse{
			RuntimeWorkloadID: operation.Result.Create.RuntimeWorkloadID,
			ServiceURL:        operation.Result.Create.ServiceURL,
			Endpoints:         make([]WorkloadEndpointResponse, 0, len(operation.Result.Create.Endpoints)),
		}
		for _, endpoint := range operation.Result.Create.Endpoints {
			response.Endpoints = append(response.Endpoints, newWorkloadEndpointResponse(endpoint))
		}
		return response
	case operations.OperationTypeDelete:
		if !operation.Result.DeleteCompleted || operation.DeleteCommand == nil {
			return nil
		}
		return &OperationResultResponse{
			RuntimeWorkloadID: operation.DeleteCommand.RuntimeWorkloadID,
			Status:            "SUCCESS",
		}
	default:
		return nil
	}
}

func newWorkloadEndpointResponse(endpoint provisioner.WorkloadEndpoint) WorkloadEndpointResponse {
	return WorkloadEndpointResponse{
		ContainerName: endpoint.ContainerName,
		Port:          endpoint.Port,
		ServiceURL:    endpoint.ServiceURL,
	}
}
