package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type API struct {
	createWorkload provisioner.CreateWorkloadUseCase
	runtime        RuntimeUseCase
}

func NewHandler(createWorkload provisioner.CreateWorkloadUseCase) http.Handler {
	return newHandler(createWorkload, nil)
}

func NewHandlerWithRuntime(createWorkload provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase) http.Handler {
	return newHandler(createWorkload, runtime)
}

func newHandler(createWorkload provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase) http.Handler {
	api := &API{createWorkload: createWorkload, runtime: runtime}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/instances", api.handleCreateInstance)
	if runtime != nil {
		mux.HandleFunc("GET /internal/v1/instances/{instance_id}/runtime-status", api.handleRuntimeStatus)
		mux.HandleFunc("DELETE /internal/v1/instances/{instance_id}", api.handleDeleteInstance)
		mux.HandleFunc("GET /internal/v1/operations/{operation_id}", api.handleGetOperation)
	}
	return requestSizeLimit(mux)
}

func (api *API) handleCreateInstance(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
		return
	}

	var createRequest CreateWorkloadRequest
	if err := decodeJSON(request, &createRequest); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON request body")
		return
	}
	if err := createRequest.Validate(); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if api.runtime != nil {
		operation, created, err := api.runtime.EnqueueCreate(createRequest.ToCommand())
		if err != nil {
			if errors.Is(err, isolation.ErrPolicyRejected) {
				writeAPIError(writer, http.StatusUnprocessableEntity, "ISOLATION_POLICY_REJECTED", "isolation policy was rejected")
				return
			}
			if errors.Is(err, operations.ErrIdempotencyConflict) {
				writeAPIError(writer, http.StatusConflict, "REQUEST_ID_CONFLICT", "request_id is already used by another operation")
				return
			}
			writeAPIError(writer, http.StatusBadGateway, "CREATE_QUEUE_FAILED", "workload creation could not be queued")
			return
		}
		writeAcceptedOperation(writer, operation, created)
		return
	}

	result, err := api.createWorkload.CreateWorkload(request.Context(), createRequest.ToCommand())
	if err != nil {
		if errors.Is(err, provisioner.ErrRuntimeUnavailable) {
			writeAPIError(writer, http.StatusServiceUnavailable, "RUNTIME_UNAVAILABLE", "runtime adapter is unavailable")
			return
		}
		writeAPIError(writer, http.StatusBadGateway, "PROVISIONING_FAILED", "workload creation failed")
		return
	}

	writeJSON(writer, http.StatusCreated, NewCreateWorkloadResponse(result))
}

func decodeJSON(request *http.Request, destination any) error {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func writeAPIError(writer http.ResponseWriter, status int, code string, message string) {
	writeJSON(writer, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func requestSizeLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
		next.ServeHTTP(writer, request)
	})
}
