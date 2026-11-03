package httpapi

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

const windowsSubmitPattern = "POST /internal/v1/windows-vms/{resource_target_id}/executions"

type WindowsUseCase interface {
	Submit(context.Context, string, string, []byte) (windowsruntime.Record, bool, error)
	Get(context.Context, string) (windowsruntime.Record, error)
	MaxPayload() int
}
type handlerOptions struct {
	VMPolicy func(*CreateWorkloadRequest) error
	Windows  WindowsUseCase
	Checker  CheckerUseCase
}

func NewHandlerWithWindows(create provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase, auth ServiceAuthConfig, policies *ImagePolicyCatalog, readiness ReadinessConfig, vmPolicy func(*CreateWorkloadRequest) error, windows WindowsUseCase, checker ...CheckerUseCase) http.Handler {
	options := handlerOptions{VMPolicy: vmPolicy, Windows: windows}
	if len(checker) > 0 {
		options.Checker = checker[0]
	}
	return newHandler(create, runtime, auth, policies, &readiness, options)
}

type windowsExecutionResponse struct {
	ID            string                  `json:"execution_id"`
	TargetID      string                  `json:"resource_target_id"`
	Phase         string                  `json:"phase"`
	Outcome       *windowsruntime.Outcome `json:"outcome,omitempty"`
	ErrorCode     string                  `json:"error_code,omitempty"`
	BrokerPending bool                    `json:"broker_pending"`
	CreatedAt     time.Time               `json:"created_at"`
	UpdatedAt     time.Time               `json:"updated_at"`
}

func windowsResponse(r windowsruntime.Record) windowsExecutionResponse {
	return windowsExecutionResponse{r.ID, r.TargetID, r.Phase, r.Outcome, r.ErrorCode, r.BrokerPending, r.CreatedAt, r.UpdatedAt}
}
func (api *API) handleWindowsSubmit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if isCISmokeRequest(r) {
		writeAPIError(w, 403, "FORBIDDEN", "CI smoke token cannot submit executables")
		return
	}
	target := r.PathValue("resource_target_id")
	keys := r.Header.Values("X-Request-ID")
	if !windowsruntime.ValidID(target) || len(keys) != 1 || !windowsruntime.ValidID(keys[0]) {
		writeAPIError(w, 400, "INVALID_REQUEST", "valid VM and request UUIDs are required")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/octet-stream" || r.Header.Get("Content-Encoding") != "" {
		writeAPIError(w, 415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/octet-stream")
		return
	}
	max := int64(api.windows.MaxPayload())
	if r.ContentLength > max {
		writeAPIError(w, 413, "PAYLOAD_TOO_LARGE", "executable exceeds upload limit")
		return
	}
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			writeAPIError(w, 413, "PAYLOAD_TOO_LARGE", "executable exceeds upload limit")
		} else {
			writeAPIError(w, 400, "INVALID_REQUEST", "unable to read executable")
		}
		return
	}
	record, _, err := api.windows.Submit(r.Context(), keys[0], target, payload)
	if err != nil {
		switch {
		case errors.Is(err, windowsruntime.ErrConflict):
			writeAPIError(w, 409, "REQUEST_ID_CONFLICT", "request ID was used for a different execution")
		case errors.Is(err, windowsruntime.ErrInvalidSubmission):
			writeAPIError(w, 400, "INVALID_EXECUTABLE", "a bounded Windows executable is required")
		default:
			writeAPIError(w, 503, "WINDOWS_QUEUE_UNAVAILABLE", "execution could not be queued")
		}
		return
	}
	w.Header().Set("Location", "/internal/v1/windows-executions/"+record.ID)
	w.Header().Set("Retry-After", "1")
	writeJSON(w, 202, windowsResponse(record))
}
func (api *API) handleWindowsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if isCISmokeRequest(r) {
		writeAPIError(w, 403, "FORBIDDEN", "CI smoke token cannot inspect executions")
		return
	}
	id := r.PathValue("execution_id")
	if !windowsruntime.ValidID(id) {
		writeAPIError(w, 400, "INVALID_REQUEST", "valid execution UUID is required")
		return
	}
	record, err := api.windows.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, windowsruntime.ErrNotFound) {
			writeAPIError(w, 404, "WINDOWS_EXECUTION_NOT_FOUND", "execution not found")
		} else {
			writeAPIError(w, 503, "WINDOWS_STORE_UNAVAILABLE", "execution could not be read")
		}
		return
	}
	writeJSON(w, 200, windowsResponse(record))
}
