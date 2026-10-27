package windowsruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrCheckerAuthRejected = errors.New("checker callback authorization rejected")

func prepareCheckerResult(record *Record, finishedAt time.Time) error {
	if record.Checker == nil || record.Checker.Request == nil || record.Outcome == nil {
		return nil
	}
	request := record.Checker.Request
	started := any(nil)
	startedAt := any(nil)
	status := "START_UNKNOWN"
	if record.Outcome.Started != nil && !*record.Outcome.Started {
		started = false
		status = "INFRA_ERROR"
	} else if start := record.Outcome.StartedAt; start != nil && !start.After(finishedAt) && !start.Before(record.CreatedAt) {
		started = true
		startedAt = start.UTC().Format(time.RFC3339Nano)
		switch record.Outcome.Result {
		case "succeeded":
			status = "COMPLETED"
		case "timeout":
			status = "TIMEOUT"
		case "failed":
			status = "CRASH"
			if record.Outcome.ErrorCode != "" {
				status = "INFRA_ERROR"
			}
		default:
			status = "INFRA_ERROR"
		}
	}
	id := uuid.NewString()
	event := map[string]any{
		"request_version":    1,
		"event_id":           id,
		"assignment_id":      request.AssignmentID,
		"payload_sha256":     request.PayloadSHA256,
		"event_type":         "RESULT",
		"observed_at":        finishedAt.UTC().Format(time.RFC3339Nano),
		"config_version":     request.ConfigVersion,
		"checker_commit_sha": request.CheckerCommitSHA,
		"execution_status":   status,
		"started":            started,
		"started_at":         startedAt,
		"finished_at":        finishedAt.UTC().Format(time.RFC3339Nano),
		"output":             map[string]any{"stdout": record.Outcome.Stdout, "stderr": record.Outcome.Stderr, "encoding": "utf-8", "stdout_truncated": record.Outcome.StdoutTruncated, "stderr_truncated": record.Outcome.StderrTruncated},
		"cleanup_complete":   nil,
		"exit_code":          record.Outcome.ExitCode,
	}
	if request.SelectionMode != "broker_pool" {
		event["vm_template_sha256"] = request.VMTemplateSHA256
		event["driver_sha256"] = request.DriverSHA256
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	record.Checker.ResultEventID = id
	record.Checker.ResultBody = body
	record.Checker.ResultPending = true
	return nil
}

func (s *Service) postCheckerResult(ctx context.Context, record Record) error {
	if s.checkerHTTPClient == nil || record.Checker == nil || record.Checker.Request == nil || !record.Checker.ResultPending || len(record.Checker.ResultBody) == 0 {
		return errors.New("checker callback unavailable")
	}
	url := record.Checker.BackendURL + "/internal/v1/checker-submissions/" + record.Checker.Request.SubmissionID + "/events"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(record.Checker.ResultBody))
	if err != nil {
		return errors.New("checker callback request invalid")
	}
	request.Header.Set("Authorization", "Bearer "+record.Checker.JobToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.checkerHTTPClient.Do(request)
	if err != nil {
		return errors.New("checker callback unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return ErrCheckerAuthRejected
	}
	if response.StatusCode != http.StatusOK {
		return errors.New("checker callback rejected")
	}
	var acknowledgement struct {
		Code string `json:"code"`
		Data struct {
			SubmissionID string `json:"submission_id"`
			EventID      string `json:"event_id"`
			Accepted     bool   `json:"accepted"`
		} `json:"data"`
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 || json.Unmarshal(body, &acknowledgement) != nil || acknowledgement.Code != "SUCCESS" || acknowledgement.Data.SubmissionID != record.Checker.Request.SubmissionID || acknowledgement.Data.EventID != record.Checker.ResultEventID || !acknowledgement.Data.Accepted {
		return errors.New("checker callback acknowledgement invalid")
	}
	return nil
}

// refreshCheckerToken exchanges the Runtime/Backend service credential for a
// new scoped job JWT. The service credential never enters the VM or Broker.
func (s *Service) refreshCheckerToken(ctx context.Context, record Record) (string, error) {
	if s.checkerHTTPClient == nil || record.Checker == nil || record.Checker.Request == nil || record.Checker.Request.SelectionMode != "broker_pool" {
		return "", errors.New("checker token refresh unavailable")
	}
	backendID := record.Checker.BackendID
	if backendID == "" {
		backendID = "default"
	}
	serviceToken := s.checkerServiceTokens[backendID]
	if serviceToken == "" {
		return "", errors.New("checker service token unavailable")
	}
	requestBody, err := json.Marshal(map[string]string{"assignment_id": record.Checker.AssignmentID, "payload_sha256": record.Checker.PayloadSHA256})
	if err != nil {
		return "", err
	}
	url := record.Checker.BackendURL + "/internal/v1/checker-submissions/" + record.Checker.Request.SubmissionID + "/token"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestBody))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+serviceToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.checkerHTTPClient.Do(request)
	if err != nil {
		return "", errors.New("checker token refresh unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return "", ErrCheckerAuthRejected
	}
	if response.StatusCode != http.StatusOK {
		return "", errors.New("checker token refresh rejected")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(body) > 8192 {
		return "", errors.New("checker token refresh response too large")
	}
	var receipt struct {
		Code string `json:"code"`
		Data struct {
			SubmissionID string `json:"submission_id"`
			AssignmentID string `json:"assignment_id"`
			JobToken     string `json:"job_token"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &receipt) != nil || receipt.Code != "SUCCESS" || receipt.Data.SubmissionID != record.Checker.Request.SubmissionID || receipt.Data.AssignmentID != record.Checker.AssignmentID || len(receipt.Data.JobToken) < 20 || len(receipt.Data.JobToken) > 4096 || strings.ContainsAny(receipt.Data.JobToken, " \t\r\n\x00") {
		return "", errors.New("checker token refresh response invalid")
	}
	return receipt.Data.JobToken, nil
}
