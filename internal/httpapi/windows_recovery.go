package httpapi

import (
	"context"
	"errors"
	"mime"
	"net/http"

	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

type windowsRecoveryUseCase interface {
	ConfirmRecovery(context.Context, string, string, string) (windowsruntime.RecoveryReceipt, error)
}

func (api *API) handleWindowsRecovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		writeAPIError(w, 415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
		return
	}
	var body struct {
		ExecutionID string `json:"execution_id"`
		EventID     string `json:"event_id"`
		VMState     string `json:"vm_state"`
	}
	targetID := r.PathValue("resource_target_id")
	if decodeJSON(r, &body) != nil || !windowsruntime.ValidID(targetID) ||
		!windowsruntime.ValidID(body.ExecutionID) || !windowsruntime.ValidID(body.EventID) || body.VMState != "READY" {
		writeAPIError(w, 400, "INVALID_REQUEST", "valid recovery event and UUIDs are required")
		return
	}
	receiver := api.windows.(windowsRecoveryUseCase)
	receipt, err := receiver.ConfirmRecovery(r.Context(), targetID, body.ExecutionID, body.EventID)
	if err != nil {
		switch {
		case errors.Is(err, windowsruntime.ErrNotFound):
			writeAPIError(w, 404, "WINDOWS_EXECUTION_NOT_FOUND", "execution not found")
		case errors.Is(err, windowsruntime.ErrConflict):
			writeAPIError(w, 409, "WINDOWS_RECOVERY_CONFLICT", "recovery event conflicts with execution")
		case errors.Is(err, windowsruntime.ErrRecoveryNotReady):
			writeAPIError(w, 409, "WINDOWS_EXECUTION_NOT_FINISHED", "Broker execution has not finished")
		default:
			writeAPIError(w, 503, "WINDOWS_RECOVERY_UNAVAILABLE", "recovery event could not be saved")
		}
		return
	}
	writeJSON(w, 200, map[string]any{"code": "SUCCESS", "data": receipt})
}
