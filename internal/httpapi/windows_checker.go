package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

type CheckerUseCase interface {
	SubmitForBackend(context.Context, string, windowsruntime.CheckerRequest, string) (windowsruntime.Record, bool, error)
	GetForBackend(context.Context, string, string) (windowsruntime.Record, error)
}

type checkerResponse struct {
	Code string         `json:"code"`
	Data checkerJobData `json:"data"`
}
type checkerJobData struct {
	SubmissionID  string `json:"submission_id"`
	AssignmentID  string `json:"assignment_id"`
	CheckerJobID  string `json:"checker_job_id"`
	QueueState    string `json:"queue_state,omitempty"`
	QueuePosition *int   `json:"queue_position,omitempty"`
}

func checkerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("X-Submission-Token")
	if len(values) != 1 || len(values[0]) < 20 || len(values[0]) > 4096 || strings.ContainsAny(values[0], " \t\r\n\x00") {
		return "", false
	}
	return values[0], true
}

func (api *API) handleCheckerSubmit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if isCISmokeRequest(r) {
		writeAPIError(w, 403, "FORBIDDEN", "CI smoke token cannot submit checker jobs")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	token, ok := checkerToken(r)
	if err != nil || media != "application/json" || !ok {
		writeAPIError(w, 400, "INVALID_REQUEST", "checker request headers are invalid")
		return
	}
	raw, readErr := io.ReadAll(r.Body)
	var fields map[string]json.RawMessage
	if readErr != nil || json.Unmarshal(raw, &fields) != nil {
		writeAPIError(w, 400, "INVALID_REQUEST", "checker request is invalid")
		return
	}
	decoded := r.Clone(r.Context())
	decoded.Body = io.NopCloser(bytes.NewReader(raw))
	var request windowsruntime.CheckerRequest
	if decodeJSON(decoded, &request) != nil || !windowsruntime.ValidID(request.SubmissionID) {
		writeAPIError(w, 400, "INVALID_REQUEST", "checker request is invalid")
		return
	}
	if request.SelectionMode == "broker_pool" {
		_, hasTemplate := fields["vm_template_sha256"]
		_, hasDriver := fields["driver_sha256"]
		if hasTemplate || hasDriver {
			writeAPIError(w, 400, "INVALID_REQUEST", "broker pool request cannot claim VM image or driver digests")
			return
		}
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || keys[0] != request.SubmissionID {
		writeAPIError(w, 400, "INVALID_REQUEST", "idempotency key must equal submission ID")
		return
	}
	record, created, err := api.checker.SubmitForBackend(r.Context(), checkerBackendID(r), request, token)
	if err != nil {
		switch {
		case errors.Is(err, windowsruntime.ErrInvalidSubmission):
			writeAPIError(w, 400, "INVALID_REQUEST", "checker submission was rejected")
		case errors.Is(err, windowsruntime.ErrConflict):
			writeAPIError(w, 409, "REQUEST_ID_CONFLICT", "checker submission conflicts with an existing job")
		default:
			writeAPIError(w, 503, "CHECKER_UNAVAILABLE", "checker submission could not be accepted")
		}
		return
	}
	if record.Checker == nil || record.Checker.Request == nil || record.Checker.Request.SubmissionID != request.SubmissionID || record.Checker.AssignmentID != request.AssignmentID || !windowsruntime.ValidID(record.ID) {
		writeAPIError(w, 503, "CHECKER_UNAVAILABLE", "checker job acknowledgement was invalid")
		return
	}
	status := 200
	if created {
		status = 202
	}
	writeJSON(w, status, checkerResponse{Code: "SUCCESS", Data: checkerJobData{SubmissionID: request.SubmissionID, AssignmentID: record.Checker.AssignmentID, CheckerJobID: record.ID, QueueState: record.QueueState, QueuePosition: record.QueuePosition}})
}

func (api *API) handleCheckerGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if isCISmokeRequest(r) {
		writeAPIError(w, 403, "FORBIDDEN", "CI smoke token cannot inspect checker jobs")
		return
	}
	if _, ok := checkerToken(r); !ok {
		writeAPIError(w, 400, "INVALID_REQUEST", "job token is required")
		return
	}
	id := r.PathValue("submission_id")
	if !windowsruntime.ValidID(id) {
		writeAPIError(w, 400, "INVALID_REQUEST", "submission ID is invalid")
		return
	}
	record, err := api.checker.GetForBackend(r.Context(), checkerBackendID(r), id)
	if err != nil {
		if errors.Is(err, windowsruntime.ErrNotFound) {
			writeAPIError(w, 404, "CHECKER_JOB_NOT_FOUND", "checker job was not found")
		} else {
			writeAPIError(w, 503, "CHECKER_UNAVAILABLE", "checker job could not be read")
		}
		return
	}
	if record.Checker == nil || record.Checker.Request == nil || record.Checker.Request.SubmissionID != id || !windowsruntime.ValidID(record.ID) {
		writeAPIError(w, 503, "CHECKER_UNAVAILABLE", "checker job record was invalid")
		return
	}
	writeJSON(w, 200, checkerResponse{Code: "SUCCESS", Data: checkerJobData{SubmissionID: id, AssignmentID: record.Checker.AssignmentID, CheckerJobID: record.ID, QueueState: record.QueueState, QueuePosition: record.QueuePosition}})
}
