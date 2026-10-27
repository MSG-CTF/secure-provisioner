package windowsruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (s *Service) ProcessRecoveryOne(ctx context.Context) error {
	store, ok := s.store.(recoveryDeliveryStore)
	if !ok {
		return ErrRecoveryUnavailable
	}
	owner := uuid.NewString()
	lease := max(s.cfg.LeaseDuration, 45*time.Second)
	delivery, err := store.ClaimRecovery(ctx, owner, lease)
	if err != nil || delivery == nil {
		return err
	}
	delivered := false
	sendCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	sendErr := s.postRecoveryCleanup(sendCtx, *delivery)
	if sendErr == nil {
		delivered = true
	}
	cancel()
	retryAt := time.Time{}
	if !delivered {
		retryDelay := s.cfg.RetryInterval
		if errors.Is(sendErr, ErrCheckerAuthRejected) {
			retryDelay = max(retryDelay, time.Minute)
		}
		retryAt = time.Now().UTC().Add(retryDelay)
	}
	saveCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer stop()
	return store.CompleteRecovery(saveCtx, delivery.Receipt.ExecutionID, owner, delivered, retryAt)
}

func (s *Service) postRecoveryCleanup(ctx context.Context, delivery RecoveryDelivery) error {
	if !recoveryResultDelivered(delivery.Record) || delivery.Record.TargetID != delivery.Receipt.TargetID ||
		delivery.Receipt.ExecutionID != delivery.Record.ID || delivery.Receipt.CleanupDelivery != "PENDING" {
		return ErrRecoveryNotReady
	}
	record := delivery.Record
	request := record.Checker.Request
	body, err := json.Marshal(map[string]any{
		"request_version":    1,
		"event_id":           delivery.Receipt.EventID,
		"assignment_id":      request.AssignmentID,
		"payload_sha256":     request.PayloadSHA256,
		"event_type":         "CLEANUP",
		"observed_at":        delivery.Receipt.RecoveredAt.UTC().Format(time.RFC3339Nano),
		"config_version":     request.ConfigVersion,
		"checker_commit_sha": request.CheckerCommitSHA,
		"cleanup_complete":   true,
	})
	if err != nil {
		return err
	}
	accepted, receiptErr := s.checkRecoveryReceipt(ctx, delivery, body)
	if receiptErr == nil && accepted {
		return nil
	}
	if errors.Is(receiptErr, ErrCheckerAuthRejected) {
		return receiptErr
	}
	token, err := s.refreshCheckerToken(ctx, record)
	if err != nil {
		return err
	}
	checker := *record.Checker
	checker.JobToken = token
	checker.ResultEventID = delivery.Receipt.EventID
	checker.ResultBody = body
	checker.ResultPending = true
	record.Checker = &checker
	if err := s.postCheckerResult(ctx, record); err != nil {
		if errors.Is(err, ErrCheckerAuthRejected) {
			return ErrCheckerAuthRejected
		}
		return err
	}
	return nil
}

func (s *Service) checkRecoveryReceipt(ctx context.Context, delivery RecoveryDelivery, body []byte) (bool, error) {
	record := delivery.Record
	if s.checkerHTTPClient == nil || record.Checker == nil || record.Checker.Request == nil {
		return false, ErrRecoveryUnavailable
	}
	backendID := record.Checker.BackendID
	if backendID == "" {
		backendID = "default"
	}
	serviceToken := s.checkerServiceTokens[backendID]
	if serviceToken == "" {
		return false, ErrRecoveryUnavailable
	}
	url := record.Checker.BackendURL + "/internal/v1/checker-submissions/" + record.Checker.Request.SubmissionID + "/events/" + delivery.Receipt.EventID + "/receipt"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, ErrRecoveryUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+serviceToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.checkerHTTPClient.Do(request)
	if err != nil {
		return false, ErrRecoveryUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return false, ErrCheckerAuthRejected
	}
	if response.StatusCode != http.StatusOK {
		return false, ErrRecoveryUnavailable
	}
	var acknowledgement struct {
		Code string `json:"code"`
		Data struct {
			SubmissionID string `json:"submission_id"`
			EventID      string `json:"event_id"`
			Accepted     *bool  `json:"accepted"`
		} `json:"data"`
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(raw) > 8192 || json.Unmarshal(raw, &acknowledgement) != nil || acknowledgement.Code != "SUCCESS" || acknowledgement.Data.SubmissionID != record.Checker.Request.SubmissionID || acknowledgement.Data.EventID != delivery.Receipt.EventID || acknowledgement.Data.Accepted == nil {
		return false, ErrRecoveryUnavailable
	}
	return *acknowledgement.Data.Accepted, nil
}
