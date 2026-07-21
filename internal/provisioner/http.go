package provisioner

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type API struct {
	createWorkload CreateWorkloadUseCase
}

func NewHandler(createWorkload CreateWorkloadUseCase) http.Handler {
	api := &API{createWorkload: createWorkload}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/instances", api.handleCreateInstance)
	return requestSizeLimit(mux)
}

func (api *API) handleCreateInstance(writer http.ResponseWriter, request *http.Request) {
	var createRequest CreateWorkloadRequest
	if err := decodeJSON(request, &createRequest); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := ValidateCreateWorkloadRequest(createRequest); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	result, err := api.createWorkload.CreateWorkload(request.Context(), createRequest.ToCommand())
	if err != nil {
		if errors.Is(err, ErrRuntimeUnavailable) {
			writeAPIError(writer, http.StatusServiceUnavailable, "RUNTIME_UNAVAILABLE", "runtime adapter is unavailable")
			return
		}
		writeAPIError(writer, http.StatusBadGateway, "PROVISIONING_FAILED", "workload creation failed")
		return
	}

	writeJSON(writer, http.StatusCreated, result)
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
