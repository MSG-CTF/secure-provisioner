package windowsruntime

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type poolBroker struct {
	serviceBroker
	items []Connection
}

type resumableTestTransport struct{ resumes int }

func (*resumableTestTransport) Execute(context.Context, Connection, Job) Outcome {
	panic("fresh execute must not be used")
}
func (t *resumableTestTransport) Resume(_ context.Context, _ Connection, job Job) Outcome {
	t.resumes++
	zero := int64(0)
	started := time.Now().UTC()
	return Outcome{Result: "succeeded", ExitCode: &zero, StartedAt: &started, Stdout: job.ID}
}

func TestApprovedHTTPSExecutionResumesSameIDAfterRestart(t *testing.T) {
	broker := &serviceBroker{}
	store := NewMemoryStore()
	transport := &resumableTestTransport{}
	service, err := NewService(DefaultServiceConfig(), store, broker, transport)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC()
	record := Record{ID: "bc36c3df-bd24-4df2-9d3d-cf92c5720d32", RequestID: testRequest, TargetID: testTarget, Fingerprint: "payload", Phase: "APPROVED", Payload: []byte("MZtest"), Connection: &Connection{TargetID: testTarget, Host: "192.0.2.10", Protocol: "rdp", Port: 3389, Username: "msgexec"}, CreatedAt: created, UpdatedAt: created, ExecutionTimeout: 30 * time.Second, ConnectTimeout: time.Second, OutputLimit: 65536}
	if _, _, err := store.Submit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	final, err := store.Get(context.Background(), record.ID)
	if err != nil || final.Phase != "FINISHED" || final.Outcome == nil || final.Outcome.Stdout != record.ID || transport.resumes != 1 || len(broker.events) != 1 {
		t.Fatalf("HTTPS recovery failed: %+v err=%v resumes=%d events=%d", final, err, transport.resumes, len(broker.events))
	}
}

func TestDirectCheckerFetchesPayloadAndReturnsResult(t *testing.T) {
	payload := []byte("MZ fixture")
	digest := sha256.Sum256(payload)
	var callback map[string]any
	callbackAttempts, refreshes, payloadAttempts := 0, 0, 0
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/checker-submissions/" + testRequest + "/payload":
			payloadAttempts++
			if payloadAttempts == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Authorization") != "Bearer refreshed-job-token-secret" {
				t.Error("payload did not use refreshed token")
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(payload)
		case "/internal/v1/checker-submissions/" + testRequest + "/events":
			callbackAttempts++
			if err := json.NewDecoder(r.Body).Decode(&callback); err != nil {
				t.Error(err)
			}
			if callbackAttempts == 1 {
				w.WriteHeader(http.StatusUnauthorized) // persisted job token expired
				return
			}
			if r.Header.Get("Authorization") != "Bearer refreshed-job-token-secret" {
				t.Error("result did not use refreshed token")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "event_id": callback["event_id"], "accepted": true}})
		case "/internal/v1/checker-submissions/" + testRequest + "/token":
			refreshes++
			if r.Header.Get("Authorization") != "Bearer runtime-service-token-secret" {
				t.Error("refresh service token missing")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "data": map[string]any{"submission_id": testRequest, "assignment_id": "00000000-0000-4000-8000-000000000003", "job_token": "refreshed-job-token-secret"}})
		default:
			t.Errorf("unexpected Backend path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backend.Close()
	clientTransport := backend.Client().Transport.(*http.Transport).Clone()
	clientTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // test-only: local Avast TLS interception
	broker := &poolBroker{serviceBroker: serviceBroker{finishVMState: "READY"}, items: []Connection{{TargetID: testTarget, Host: "192.0.2.10", Protocol: "rdp", Port: 3389, Username: "msgexec"}}}
	zero := int64(0)
	started := time.Now().UTC()
	guest := &serviceTransport{broker: &broker.serviceBroker, outcome: Outcome{Result: "succeeded", ExitCode: &zero, StartedAt: &started, Stdout: "hello"}}
	cfg := DefaultServiceConfig()
	cfg.RetryInterval = time.Nanosecond
	service, err := NewService(cfg, NewMemoryStore(), broker, guest)
	if err != nil {
		t.Fatal(err)
	}
	service.SetPoolTargets(map[string]ExecutorCredential{testTarget: {}})
	service.SetCheckerServiceTokens(map[string]string{"default": "runtime-service-token-secret"})
	checker, err := NewChecker(service, CheckerConfig{BackendURL: backend.URL, Targets: map[string]bool{testTarget: true}, CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1"}, &http.Client{Transport: clientTransport})
	if err != nil {
		t.Fatal(err)
	}
	request := CheckerRequest{RequestVersion: 1, SelectionMode: "broker_pool", SubmissionID: testRequest, AssignmentID: "00000000-0000-4000-8000-000000000003", TeamID: "00000000-0000-4000-8000-000000000005", ChallengeID: "00000000-0000-4000-8000-000000000006", ReleaseID: "00000000-0000-4000-8000-000000000007", PayloadSHA256: hex.EncodeToString(digest[:]), TimeoutSeconds: 30, MaxOutputBytes: 65536, CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1"}
	record, created, err := checker.Submit(context.Background(), request, "backend-job-token-secret")
	if err != nil || !created {
		t.Fatalf("direct submit: %+v %v", record, err)
	}
	started = time.Now().UTC()
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed, _ := service.Get(context.Background(), record.ID)
	if callback == nil || callback["event_type"] != "RESULT" || callback["execution_status"] != "COMPLETED" || callback["assignment_id"] != request.AssignmentID || callback["output"].(map[string]any)["stdout"] != "hello" || callbackAttempts != 2 || payloadAttempts != 2 || refreshes != 2 || completed.Checker.ResultPending {
		t.Fatalf("Backend result missing or wrong: %+v", callback)
	}
}

func (b *poolBroker) List(context.Context, int, string) (VMPage, error) {
	return VMPage{Items: b.items}, nil
}

func TestDirectCheckerQueuesWithoutVMAndBindsWhenReady(t *testing.T) {
	broker := &poolBroker{}
	store := NewMemoryStore()
	guest := &serviceTransport{broker: &broker.serviceBroker, outcome: Outcome{Result: "failed"}}
	cfg := DefaultServiceConfig()
	cfg.RetryInterval = time.Nanosecond
	service, err := NewService(cfg, store, broker, guest)
	if err != nil {
		t.Fatal(err)
	}
	service.SetPoolAnyTargets()
	digest := sha256.Sum256([]byte("MZ fixture"))
	request := &CheckerRequest{RequestVersion: 1, SelectionMode: "broker_pool", SubmissionID: testRequest, AssignmentID: "00000000-0000-4000-8000-000000000003", PayloadSHA256: hex.EncodeToString(digest[:]), TimeoutSeconds: 30, MaxOutputBytes: 65536}
	checker := CheckerJob{AssignmentID: request.AssignmentID, PayloadSHA256: request.PayloadSHA256, BackendURL: "https://backend.example", JobToken: "backend-job-token-secret", Request: request}
	record, created, err := service.QueueChecker(context.Background(), testRequest, UnboundTargetID, checker, 30*time.Second)
	if err != nil || !created || record.TargetID != UnboundTargetID {
		t.Fatalf("queue: %+v %v", record, err)
	}
	claim, err := store.Claim(context.Background(), "worker-a", time.Minute)
	if err != nil || claim == nil {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	claim.Phase = "QUEUED"
	claim.Payload = []byte("MZ fixture")
	claim.Owner = ""
	if err := store.Save(context.Background(), *claim, "worker-a"); err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, _ := store.Get(context.Background(), record.ID)
	if pending.TargetID != UnboundTargetID || len(broker.events) != 0 || guest.calls != 0 {
		t.Fatalf("empty pool ran job: %+v", pending)
	}
	broker.items = []Connection{{TargetID: testTarget, Host: "192.0.2.10", Protocol: "rdp", Port: 3389, Username: "msgexec"}}
	time.Sleep(time.Millisecond)
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	bound, _ := store.Get(context.Background(), record.ID)
	if bound.TargetID != testTarget || guest.calls != 1 || len(broker.events) != 2 {
		t.Fatalf("ready target not used: %+v calls=%d events=%d", bound, guest.calls, len(broker.events))
	}
	replay, created, err := service.QueueChecker(context.Background(), testRequest, UnboundTargetID, checker, 30*time.Second)
	if err != nil || created || replay.ID != record.ID {
		t.Fatalf("replay after bind: %+v created=%v err=%v", replay, created, err)
	}
}

func TestCheckerAcceptsBrokerDiscoveredPoolWithoutStaticTargets(t *testing.T) {
	service, _, _ := serviceFixture(t, &serviceBroker{}, Outcome{})
	service.SetPoolAnyTargets()
	checker, err := NewChecker(service, CheckerConfig{BackendURL: "https://backend.example", CheckerCommitSHA: strings.Repeat("a", 40), VMTemplateSHA256: strings.Repeat("b", 64), DriverSHA256: strings.Repeat("c", 64), ConfigVersion: "test-v1"}, &http.Client{Timeout: time.Second})
	if err != nil || checker == nil {
		t.Fatalf("dynamic Broker pool rejected: checker=%+v err=%v", checker, err)
	}
}
