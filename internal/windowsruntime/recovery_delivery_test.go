package windowsruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOneSubmissionRecoveryDeliversStableBackendCleanup(t *testing.T) {
	const assignmentID = "00000000-0000-4000-8000-000000000031"
	const eventID = "00000000-0000-4000-8000-000000000032"
	var callbacks [][]byte
	var tokens int
	var receipts int
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/checker-submissions/" + testRequest + "/events/" + eventID + "/receipt":
			receipts++
			if r.Header.Get("Authorization") != "Bearer backend-service-token-secret" {
				t.Error("receipt service token missing")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{
				"submission_id": testRequest, "event_id": eventID, "accepted": false,
			}})
		case "/internal/v1/checker-submissions/" + testRequest + "/token":
			tokens++
			if r.Header.Get("Authorization") != "Bearer backend-service-token-secret" {
				t.Error("service token missing")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{
				"submission_id": testRequest, "assignment_id": assignmentID, "job_token": "refreshed-job-token-secret",
			}})
		case "/internal/v1/checker-submissions/" + testRequest + "/events":
			if r.Header.Get("Authorization") != "Bearer refreshed-job-token-secret" {
				t.Error("job token missing")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["event_type"] != "CLEANUP" || body["event_id"] != eventID || body["assignment_id"] != assignmentID || body["cleanup_complete"] != true || body["checker_commit_sha"] != strings.Repeat("a", 40) || body["config_version"] != "test-v1" {
				t.Errorf("wrong cleanup body: %+v", body)
			}
			encoded, _ := json.Marshal(body)
			callbacks = append(callbacks, encoded)
			if len(callbacks) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable) // response was not confirmed
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{
				"submission_id": testRequest, "event_id": eventID, "accepted": true,
			}})
		default:
			t.Errorf("unexpected Backend path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backend.Close()
	store := NewMemoryStore()
	cfg := DefaultServiceConfig()
	cfg.RetryInterval = time.Nanosecond
	service, err := NewService(cfg, store, &serviceBroker{}, &serviceTransport{})
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := backend.Client().Transport.(*http.Transport).Clone()
	clientTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // test-only: local Avast TLS interception
	service.checkerHTTPClient = &http.Client{Transport: clientTransport}
	service.SetCheckerServiceTokens(map[string]string{"default": "backend-service-token-secret"})
	now := time.Now().UTC()
	record := Record{ID: "00000000-0000-4000-8000-000000000033", RequestID: testRequest, TargetID: testTarget,
		Fingerprint: "fixture", Phase: "FINISHED", CreatedAt: now, UpdatedAt: now,
		Checker: &CheckerJob{AssignmentID: assignmentID, PayloadSHA256: strings.Repeat("b", 64), BackendURL: backend.URL,
			ResultEventID: "00000000-0000-4000-8000-000000000034",
			Request: &CheckerRequest{SelectionMode: "broker_pool", SubmissionID: testRequest, AssignmentID: assignmentID,
				PayloadSHA256: strings.Repeat("b", 64), CheckerCommitSHA: strings.Repeat("a", 40), ConfigVersion: "test-v1"}},
	}
	if _, _, err := store.Submit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConfirmRecovery(context.Background(), testTarget, record.ID, eventID); err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessRecoveryOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := service.ConfirmRecovery(context.Background(), testTarget, record.ID, eventID)
	if err != nil || first.CleanupDelivery != "PENDING" || len(callbacks) != 1 {
		t.Fatalf("failed callback was lost: receipt=%+v callbacks=%d err=%v", first, len(callbacks), err)
	}
	time.Sleep(time.Millisecond)
	if err := service.ProcessRecoveryOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	confirmed, err := service.ConfirmRecovery(context.Background(), testTarget, record.ID, eventID)
	if err != nil || confirmed.CleanupDelivery != "CONFIRMED" || len(callbacks) != 2 || !bytes.Equal(callbacks[0], callbacks[1]) || tokens != 2 || receipts != 2 {
		t.Fatalf("cleanup not confirmed or replay changed: %+v callbacks=%d tokens=%d receipts=%d err=%v", confirmed, len(callbacks), tokens, receipts, err)
	}
	if err := service.ProcessRecoveryOne(context.Background()); err != nil || len(callbacks) != 2 {
		t.Fatalf("confirmed cleanup was resent: callbacks=%d err=%v", len(callbacks), err)
	}
}

func TestRecoveryReconcilesLostBackendCleanupAcknowledgement(t *testing.T) {
	const eventID = "00000000-0000-4000-8000-000000000042"
	const assignmentID = "00000000-0000-4000-8000-000000000043"
	var accepted bool
	var callbacks, tokens int
	var posted []byte
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/checker-submissions/" + testRequest + "/events/" + eventID + "/receipt":
			body := new(bytes.Buffer)
			_, _ = body.ReadFrom(r.Body)
			if accepted && !bytes.Equal(body.Bytes(), posted) {
				t.Error("receipt checked different cleanup event")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "event_id": eventID, "accepted": accepted}})
		case "/internal/v1/checker-submissions/" + testRequest + "/token":
			tokens++
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "assignment_id": assignmentID, "job_token": "refreshed-job-token-secret"}})
		case "/internal/v1/checker-submissions/" + testRequest + "/events":
			callbacks++
			posted, _ = io.ReadAll(r.Body)
			accepted = true
			w.WriteHeader(http.StatusServiceUnavailable) // Backend persisted the event; reply was lost.
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backend.Close()
	store := NewMemoryStore()
	cfg := DefaultServiceConfig()
	cfg.RetryInterval = time.Nanosecond
	service, err := NewService(cfg, store, &serviceBroker{}, &serviceTransport{})
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := backend.Client().Transport.(*http.Transport).Clone()
	clientTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // test-only: local Avast TLS interception
	service.checkerHTTPClient = &http.Client{Transport: clientTransport}
	service.SetCheckerServiceTokens(map[string]string{"default": "backend-service-token-secret"})
	now := time.Now().UTC()
	record := Record{ID: "00000000-0000-4000-8000-000000000044", RequestID: testRequest, TargetID: testTarget, Fingerprint: "fixture", Phase: "FINISHED", CreatedAt: now, UpdatedAt: now,
		Checker: &CheckerJob{AssignmentID: assignmentID, PayloadSHA256: strings.Repeat("b", 64), BackendURL: backend.URL, ResultEventID: "00000000-0000-4000-8000-000000000045",
			Request: &CheckerRequest{SelectionMode: "broker_pool", SubmissionID: testRequest, AssignmentID: assignmentID, PayloadSHA256: strings.Repeat("b", 64), CheckerCommitSHA: strings.Repeat("a", 40), ConfigVersion: "test-v1"}}}
	if _, _, err := store.Submit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConfirmRecovery(context.Background(), testTarget, record.ID, eventID); err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessRecoveryOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if err := service.ProcessRecoveryOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipt, err := service.ConfirmRecovery(context.Background(), testTarget, record.ID, eventID)
	if err != nil || receipt.CleanupDelivery != "CONFIRMED" || callbacks != 1 || tokens != 1 {
		t.Fatalf("lost ack not reconciled: receipt=%+v callbacks=%d tokens=%d err=%v", receipt, callbacks, tokens, err)
	}
}

func TestRecoveryWorkerAutomaticallyDeliversOneSubmission(t *testing.T) {
	const eventID = "00000000-0000-4000-8000-000000000052"
	const assignmentID = "00000000-0000-4000-8000-000000000053"
	callback := make(chan struct{}, 1)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/checker-submissions/" + testRequest + "/events/" + eventID + "/receipt":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "event_id": eventID, "accepted": false}})
		case "/internal/v1/checker-submissions/" + testRequest + "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "assignment_id": assignmentID, "job_token": "refreshed-job-token-secret"}})
		case "/internal/v1/checker-submissions/" + testRequest + "/events":
			callback <- struct{}{}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "event_id": eventID, "accepted": true}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backend.Close()
	store := NewMemoryStore()
	cfg := DefaultServiceConfig()
	cfg.PollInterval = time.Millisecond
	service, err := NewService(cfg, store, &serviceBroker{}, &serviceTransport{})
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := backend.Client().Transport.(*http.Transport).Clone()
	clientTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // test-only: local Avast TLS interception
	service.checkerHTTPClient = &http.Client{Transport: clientTransport}
	service.SetCheckerServiceTokens(map[string]string{"default": "backend-service-token-secret"})
	now := time.Now().UTC()
	record := Record{ID: "00000000-0000-4000-8000-000000000054", RequestID: testRequest, TargetID: testTarget, Fingerprint: "fixture", Phase: "FINISHED", CreatedAt: now, UpdatedAt: now,
		Checker: &CheckerJob{AssignmentID: assignmentID, PayloadSHA256: strings.Repeat("b", 64), BackendURL: backend.URL, ResultEventID: "00000000-0000-4000-8000-000000000055",
			Request: &CheckerRequest{SelectionMode: "broker_pool", SubmissionID: testRequest, AssignmentID: assignmentID, PayloadSHA256: strings.Repeat("b", 64), CheckerCommitSHA: strings.Repeat("a", 40), ConfigVersion: "test-v1"}}}
	if _, _, err := store.Submit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConfirmRecovery(context.Background(), testTarget, record.ID, eventID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { ended <- service.Run(ctx) }()
	select {
	case <-callback:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("automatic recovery worker never called Backend")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		receipt, err := service.ConfirmRecovery(context.Background(), testTarget, record.ID, eventID)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if receipt.CleanupDelivery == "CONFIRMED" {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Backend acknowledgement was not persisted")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-ended; err != nil {
		t.Fatal(err)
	}
}
