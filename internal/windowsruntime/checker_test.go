package windowsruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckerSubmissionPersistsPrivateMetadataWithExecution(t *testing.T) {
	broker := &serviceBroker{}
	service, _, _ := serviceFixture(t, broker, Outcome{Result: "failed"})
	payload := []byte("MZ fixture")
	digest := sha256.Sum256(payload)
	meta := CheckerJob{AssignmentID: "00000000-0000-4000-8000-000000000003", JobToken: "backend-job-token-secret", BackendURL: "https://backend.example", PayloadSHA256: hex.EncodeToString(digest[:])}
	meta.Request = &CheckerRequest{RequestVersion: 1, SubmissionID: testRequest, AssignmentID: meta.AssignmentID, VMID: testTarget, PayloadSHA256: meta.PayloadSHA256, TimeoutSeconds: 30, MaxOutputBytes: 65536}
	record, created, err := service.QueueChecker(context.Background(), testRequest, testTarget, meta, 30*time.Second)
	if err != nil || !created || record.Checker == nil {
		t.Fatalf("submit: created=%v err=%v record=%+v", created, err, record)
	}
	replay, err := service.GetByRequest(context.Background(), testRequest)
	if err != nil || replay.ID != record.ID || replay.Checker.JobToken != meta.JobToken {
		t.Fatalf("request lookup: %+v %v", replay, err)
	}
	public, err := json.Marshal(replay)
	if err != nil {
		t.Fatal(err)
	}
	if string(public) == "" || bytes.Contains(public, []byte(meta.JobToken)) {
		t.Fatalf("private job token exposed in public record: %s", public)
	}
	changed := meta
	changedRequest := *meta.Request
	changedRequest.ReadinessCheckID = "different-evidence"
	changed.Request = &changedRequest
	if _, _, err := service.QueueChecker(context.Background(), testRequest, testTarget, changed, 30*time.Second); err != ErrConflict {
		t.Fatalf("same submission accepted changed metadata: %v", err)
	}
}

func TestCheckerFetchesVerifiedBackendPayloadForConfiguredBrokerTarget(t *testing.T) {
	payload := []byte("MZ fixture")
	digest := sha256.Sum256(payload)
	requests := 0
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/internal/v1/checker-submissions/"+testRequest+"/payload" || r.Header.Get("Authorization") != "Bearer backend-job-token-secret" {
			t.Errorf("unexpected backend request: %s %s", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	}))
	defer backend.Close()
	// Avast on the Windows development host replaces even loopback test TLS
	// certificates. This override is confined to the in-process test client.
	transport := backend.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	testClient := &http.Client{Transport: transport}
	broker := &serviceBroker{}
	service, store, guest := serviceFixture(t, broker, Outcome{Result: "failed"})
	checker, err := NewChecker(service, CheckerConfig{BackendURL: backend.URL, Targets: map[string]bool{testTarget: true}, CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1"}, testClient)
	if err != nil {
		t.Fatal(err)
	}
	request := CheckerRequest{RequestVersion: 1, SubmissionID: testRequest, AssignmentID: "00000000-0000-4000-8000-000000000003", TeamID: "00000000-0000-4000-8000-000000000005", ChallengeID: "00000000-0000-4000-8000-000000000006", ReleaseID: "00000000-0000-4000-8000-000000000007", VMID: testTarget, ReadinessCheckID: "fresh-ready-evidence", PayloadSHA256: hex.EncodeToString(digest[:]), TimeoutSeconds: 30, MaxOutputBytes: 65536, CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1"}
	record, _, err := checker.Submit(context.Background(), request, "backend-job-token-secret")
	if err != nil || record.Checker == nil || requests != 0 || record.Phase != "FETCH_PENDING" {
		t.Fatalf("submit: %+v %v requests=%d", record, err, requests)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	queued, err := store.Get(context.Background(), record.ID)
	if err != nil || requests != 1 || queued.Phase != "QUEUED" || !bytes.Equal(queued.Payload, payload) || len(broker.events) != 0 || guest.calls != 0 {
		t.Fatalf("payload fetch did not safely queue: phase=%s err=%v requests=%d broker=%d guest=%d", queued.Phase, err, requests, len(broker.events), guest.calls)
	}
	request.VMID = "00000000-0000-4000-8000-000000000099"
	if _, _, err = checker.Submit(context.Background(), request, "backend-job-token-secret"); err == nil || requests != 1 {
		t.Fatalf("unconfigured VM was fetched: %v requests=%d", err, requests)
	}
}

func TestCheckerRetriesIdenticalBackendResultAfterResponseFailure(t *testing.T) {
	payload := []byte("MZ fixture")
	digest := sha256.Sum256(payload)
	failCallback := true
	var events [][]byte
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/checker-submissions/" + testRequest + "/payload":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(payload)
		case "/internal/v1/checker-submissions/" + testRequest + "/events":
			body, _ := io.ReadAll(r.Body)
			events = append(events, body)
			if failCallback {
				w.WriteHeader(503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			var event struct {
				EventID string `json:"event_id"`
			}
			_ = json.Unmarshal(body, &event)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "event_id": event.EventID, "accepted": true}})
		default:
			t.Errorf("unexpected Backend path: %s", r.URL.Path)
		}
	}))
	defer backend.Close()
	transport := backend.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec -- local test TLS is intercepted by Avast
	zero := int64(0)
	service, store, guest := serviceFixture(t, &serviceBroker{}, Outcome{Result: "succeeded", ExitCode: &zero, Stdout: "hello"})
	checker, err := NewChecker(service, CheckerConfig{BackendURL: backend.URL, Targets: map[string]bool{testTarget: true}, CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1"}, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	request := CheckerRequest{RequestVersion: 1, SubmissionID: testRequest, AssignmentID: "00000000-0000-4000-8000-000000000003", TeamID: "00000000-0000-4000-8000-000000000005", ChallengeID: "00000000-0000-4000-8000-000000000006", ReleaseID: "00000000-0000-4000-8000-000000000007", VMID: testTarget, ReadinessCheckID: "fresh-ready-evidence", PayloadSHA256: hex.EncodeToString(digest[:]), TimeoutSeconds: 30, MaxOutputBytes: 65536, CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1"}
	record, _, err := checker.Submit(context.Background(), request, "backend-job-token-secret")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	guest.outcome.StartedAt = &started
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	queued, err := store.Get(context.Background(), record.ID)
	if err != nil || queued.Phase != "FINISHED" || queued.BrokerPending || queued.Checker == nil || !queued.Checker.ResultPending || len(events) != 1 {
		t.Fatalf("first callback: %+v err=%v events=%d", queued, err, len(events))
	}
	failCallback = false
	time.Sleep(time.Millisecond)
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	finished, err := store.Get(context.Background(), record.ID)
	if err != nil || finished.Checker.ResultPending || len(events) != 2 || !bytes.Equal(events[0], events[1]) {
		t.Fatalf("callback replay changed: %+v err=%v events=%d", finished, err, len(events))
	}
	var event map[string]any
	if err := json.Unmarshal(events[0], &event); err != nil || event["event_type"] != "RESULT" || event["execution_status"] != "COMPLETED" || event["started"] != true || event["started_at"] == nil {
		t.Fatalf("invalid result event: %s err=%v", events[0], err)
	}
}

func TestCheckerResultDoesNotInventGuestStartOrCleanup(t *testing.T) {
	finished := time.Now().UTC()
	record := Record{
		ID: testRequest, RequestID: testRequest, CreatedAt: finished.Add(-time.Minute),
		Outcome: &Outcome{Result: "unreachable", ErrorCode: "rdp_disconnected"},
		Checker: &CheckerJob{Request: &CheckerRequest{AssignmentID: "00000000-0000-4000-8000-000000000003", PayloadSHA256: strings.Repeat("a", 64), CheckerCommitSHA: strings.Repeat("b", 40), VMTemplateSHA256: strings.Repeat("c", 64), DriverSHA256: strings.Repeat("d", 64), ConfigVersion: "test-v1"}},
	}
	if err := prepareCheckerResult(&record, finished); err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(record.Checker.ResultBody, &event); err != nil {
		t.Fatal(err)
	}
	if event["execution_status"] != "START_UNKNOWN" || event["started"] != nil || event["started_at"] != nil || event["cleanup_complete"] != nil || event["exit_code"] != nil {
		t.Fatalf("unobserved execution was overclaimed: %s", record.Checker.ResultBody)
	}
}

type checkerRoundTrip func(*http.Request) (*http.Response, error)

func (f checkerRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCheckerAcceptedJobRetriesBackendPayloadWithoutBrokerUse(t *testing.T) {
	payload := []byte("MZ fixture")
	digest := sha256.Sum256(payload)
	broker := &serviceBroker{}
	service, store, guest := serviceFixture(t, broker, Outcome{})
	request := &CheckerRequest{RequestVersion: 1, SubmissionID: testRequest, AssignmentID: "00000000-0000-4000-8000-000000000003", VMID: testTarget, PayloadSHA256: hex.EncodeToString(digest[:]), TimeoutSeconds: 30, MaxOutputBytes: 65536}
	calls := 0
	service.checkerHTTPClient = &http.Client{Transport: checkerRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/internal/v1/checker-submissions/"+testRequest+"/payload" {
			t.Fatalf("unexpected payload path: %s", r.URL.Path)
		}
		if calls == 1 {
			return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		headers := make(http.Header)
		headers.Set("Content-Type", "application/octet-stream")
		return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(bytes.NewReader(payload))}, nil
	})}
	record, created, err := service.QueueChecker(context.Background(), testRequest, testTarget, CheckerJob{AssignmentID: request.AssignmentID, PayloadSHA256: request.PayloadSHA256, BackendURL: "https://backend.example", JobToken: "backend-job-token-secret", Request: request}, 30*time.Second)
	if err != nil || !created || record.Phase != "FETCH_PENDING" || calls != 0 {
		t.Fatalf("job was not durably accepted before fetch: %+v %v calls=%d", record, err, calls)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, _ := store.Get(context.Background(), record.ID)
	if pending.Phase != "FETCH_PENDING" || pending.ErrorCode != "CHECKER_PAYLOAD_PENDING" || calls != 1 || len(broker.events) != 0 || guest.calls != 0 {
		t.Fatalf("temporary Backend failure used VM: phase=%s code=%s calls=%d", pending.Phase, pending.ErrorCode, calls)
	}
	time.Sleep(time.Millisecond)
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	queued, _ := store.Get(context.Background(), record.ID)
	if queued.Phase != "QUEUED" || !bytes.Equal(queued.Payload, payload) || calls != 2 || len(broker.events) != 0 {
		t.Fatalf("payload retry failed: phase=%s calls=%d", queued.Phase, calls)
	}
}

func TestCheckerPayload404ReportsUnstartedInfrastructureResult(t *testing.T) {
	payload := []byte("MZ fixture")
	digest := sha256.Sum256(payload)
	broker := &serviceBroker{}
	service, store, guest := serviceFixture(t, broker, Outcome{})
	request := &CheckerRequest{RequestVersion: 1, SubmissionID: testRequest, AssignmentID: "00000000-0000-4000-8000-000000000003", VMID: testTarget, PayloadSHA256: hex.EncodeToString(digest[:]), TimeoutSeconds: 30, MaxOutputBytes: 65536, CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1"}
	var event map[string]any
	service.checkerHTTPClient = &http.Client{Transport: checkerRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			return &http.Response{StatusCode: 404, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &event)
		ack, _ := json.Marshal(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "event_id": event["event_id"], "accepted": true}})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(ack))}, nil
	})}
	record, _, err := service.QueueChecker(context.Background(), testRequest, testTarget, CheckerJob{AssignmentID: request.AssignmentID, PayloadSHA256: request.PayloadSHA256, BackendURL: "https://backend.example", JobToken: "backend-job-token-secret", Request: request}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), record.ID)
	if err != nil || got.Phase != "REJECTED" || guest.calls != 0 || len(broker.events) != 0 || event["execution_status"] != "INFRA_ERROR" || event["started"] != false {
		t.Fatalf("permanent payload absence was retried or VM used: phase=%s guest=%d broker=%d event=%v err=%v", got.Phase, guest.calls, len(broker.events), event, err)
	}
}

func TestCheckerReportsDefinitiveBrokerStartConflictWithoutRunningGuest(t *testing.T) {
	broker := &serviceBroker{startErr: &APIError{Status: 409, Code: "WINDOWS_VM_NOT_READY"}}
	service, store, guest := serviceFixture(t, broker, Outcome{})
	payload := []byte("MZ fixture")
	digest := sha256.Sum256(payload)
	request := &CheckerRequest{RequestVersion: 1, SubmissionID: testRequest, AssignmentID: "00000000-0000-4000-8000-000000000003", VMID: testTarget, PayloadSHA256: hex.EncodeToString(digest[:]), TimeoutSeconds: 30, MaxOutputBytes: 65536, CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1"}
	var event map[string]any
	service.checkerHTTPClient = &http.Client{Transport: checkerRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			headers := make(http.Header)
			headers.Set("Content-Type", "application/octet-stream")
			return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(bytes.NewReader(payload))}, nil
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		ack, _ := json.Marshal(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "event_id": event["event_id"], "accepted": true}})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(ack))}, nil
	})}
	record, _, err := service.QueueChecker(context.Background(), testRequest, testTarget, CheckerJob{AssignmentID: request.AssignmentID, PayloadSHA256: request.PayloadSHA256, BackendURL: "https://backend.example", JobToken: "backend-job-token-secret", Request: request}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), record.ID)
	if err != nil || got.Phase != "REJECTED" || guest.calls != 0 || len(broker.events) != 1 || event["execution_status"] != "INFRA_ERROR" || event["started"] != false || event["started_at"] != nil {
		t.Fatalf("rejected start was not reported safely: phase=%s guest=%d broker=%d event=%v err=%v", got.Phase, guest.calls, len(broker.events), event, err)
	}
}
