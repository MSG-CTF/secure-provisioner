package provisioner

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type API struct {
	service *Service
}

func NewHandler(service *Service) http.Handler {
	api := &API{service: service}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", api.handleDashboard)
	mux.HandleFunc("GET /health/live", api.handleLive)
	mux.HandleFunc("GET /health/ready", api.handleReady)
	mux.HandleFunc("POST /internal/v1/instances", api.handleCreateInstance)
	mux.HandleFunc("GET /internal/v1/instances/{instanceId}", api.handleGetInstance)
	mux.HandleFunc("DELETE /internal/v1/instances/{instanceId}", api.handleDeleteInstance)
	mux.HandleFunc("GET /internal/v1/operations/{operationId}", api.handleGetOperation)
	mux.HandleFunc("GET /internal/v1/debug/resources/{instanceId}", api.handleGetRuntimeResources)

	return requestSizeLimit(mux)
}

func (api *API) handleLive(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (api *API) handleReady(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (api *API) handleCreateInstance(writer http.ResponseWriter, request *http.Request) {
	var createRequest CreateRequest
	if err := decodeJSON(request, &createRequest); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	accepted, err := api.service.AcceptCreate(request.Context(), createRequest)
	if err != nil {
		if errors.Is(err, ErrInstanceIDInUse) {
			writeAPIError(writer, http.StatusConflict, "INSTANCE_ID_IN_USE", "instance_id is already in use")
			return
		}
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	writeJSON(writer, http.StatusAccepted, accepted)
}

func (api *API) handleGetInstance(writer http.ResponseWriter, request *http.Request) {
	instance, err := api.service.GetInstance(request.PathValue("instanceId"))
	if err != nil {
		writeAPIError(writer, http.StatusNotFound, "INSTANCE_NOT_FOUND", "instance was not found")
		return
	}

	writeJSON(writer, http.StatusOK, instance)
}

func (api *API) handleDeleteInstance(writer http.ResponseWriter, request *http.Request) {
	var deleteRequest DeleteRequest
	if err := decodeJSON(request, &deleteRequest); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	accepted, err := api.service.AcceptDelete(request.Context(), deleteRequest.RequestID, request.PathValue("instanceId"))
	if err != nil {
		if errors.Is(err, ErrInstanceNotFound) {
			writeAPIError(writer, http.StatusNotFound, "INSTANCE_NOT_FOUND", "instance was not found")
			return
		}
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	writeJSON(writer, http.StatusAccepted, accepted)
}

func (api *API) handleGetOperation(writer http.ResponseWriter, request *http.Request) {
	operation, exists := api.service.GetOperation(request.PathValue("operationId"))
	if !exists {
		writeAPIError(writer, http.StatusNotFound, "OPERATION_NOT_FOUND", "operation was not found")
		return
	}

	writeJSON(writer, http.StatusOK, operation)
}

func (api *API) handleGetRuntimeResources(writer http.ResponseWriter, request *http.Request) {
	resources, exists := api.service.GetRuntimeResources(request.PathValue("instanceId"))
	if !exists {
		writeAPIError(writer, http.StatusNotFound, "RUNTIME_RESOURCES_NOT_FOUND", "fake runtime resources were not found")
		return
	}

	writeJSON(writer, http.StatusOK, resources)
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
