package windowsruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

const testTarget = "00000000-0000-4000-8000-000000000001"
const testRequest = "00000000-0000-4000-8000-000000000002"

type serviceBroker struct {
	approved       bool
	startErr       error
	finishFailures int
	events         [][]byte
}

func (b *serviceBroker) Connection(context.Context, string) (Connection, error) {
	return Connection{TargetID: testTarget, Protocol: "rdp", Host: "192.0.2.10", Port: 3389, Username: "msgexec"}, nil
}
func (b *serviceBroker) Event(_ context.Context, _ string, body []byte) (EventAck, error) {
	b.events = append(b.events, bytes.Clone(body))
	var e struct {
		ID    string `json:"execution_id"`
		Event string `json:"event"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Event == "started" {
		if b.startErr != nil {
			return EventAck{}, b.startErr
		}
		b.approved = true
		return EventAck{TargetID: testTarget, ExecutionID: e.ID, ExecutionState: "RUNNING", VMState: "RUNNING"}, nil
	}
	if b.finishFailures > 0 {
		b.finishFailures--
		return EventAck{}, errors.New("offline")
	}
	return EventAck{TargetID: testTarget, ExecutionID: e.ID, ExecutionState: "FINISHED", VMState: "RESET_REQUIRED"}, nil
}

type serviceTransport struct {
	broker  *serviceBroker
	calls   int
	outcome Outcome
	job     Job
}

func (x *serviceTransport) Execute(_ context.Context, _ Connection, job Job) Outcome {
	if !x.broker.approved {
		panic("RDP before broker approval")
	}
	x.calls++
	x.job = job
	return x.outcome
}
func serviceFixture(t *testing.T, b *serviceBroker, o Outcome) (*Service, *MemoryStore, *serviceTransport) {
	t.Helper()
	store := NewMemoryStore()
	tr := &serviceTransport{broker: b, outcome: o}
	c := DefaultServiceConfig()
	c.RetryInterval = time.Nanosecond
	svc, err := NewService(c, store, b, tr)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, tr
}
func TestServiceStartsOnlyAfterApprovalAndFinishesSameID(t *testing.T) {
	zero := int64(0)
	b := &serviceBroker{}
	s, store, tr := serviceFixture(t, b, Outcome{Result: "succeeded", ExitCode: &zero, Stdout: "hello"})
	r, created, err := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ benign fixture"))
	if err != nil || !created {
		t.Fatal(err)
	}
	if err = s.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tr.calls != 1 || got.Phase != "FINISHED" || got.BrokerPending || got.Outcome.Result != "succeeded" {
		t.Fatalf("result=%+v calls=%d", got, tr.calls)
	}
	if len(b.events) != 2 {
		t.Fatalf("events=%d", len(b.events))
	}
	for i, raw := range b.events {
		var e map[string]any
		_ = json.Unmarshal(raw, &e)
		if e["execution_id"] != r.ID {
			t.Fatal("ID changed")
		}
		if _, ok := e["stdout"]; ok {
			t.Fatal("output leaked")
		}
		if i == 1 && e["result"] != "succeeded" {
			t.Fatal(e)
		}
	}
}
func TestServiceStartConflictNeverUsesVM(t *testing.T) {
	b := &serviceBroker{startErr: &APIError{Status: 409, Code: "WINDOWS_VM_NOT_READY"}}
	s, store, tr := serviceFixture(t, b, Outcome{})
	r, _, _ := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ benign"))
	if err := s.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(context.Background(), r.ID)
	if tr.calls != 0 || got.Phase != "REJECTED" || len(b.events) != 1 {
		t.Fatalf("record=%+v calls=%d events=%d", got, tr.calls, len(b.events))
	}
}
func TestServiceLostStartReplyReplaysSameIDThenExecutes(t *testing.T) {
	b := &serviceBroker{startErr: errors.New("Broker reply lost")}
	zero := int64(0)
	s, store, tr := serviceFixture(t, b, Outcome{Result: "succeeded", ExitCode: &zero})
	record, _, err := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ benign"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, _ := store.Get(context.Background(), record.ID)
	if pending.Phase != "START_PENDING" || tr.calls != 0 {
		t.Fatalf("uncertain start executed: %+v calls=%d", pending, tr.calls)
	}
	b.startErr = nil
	time.Sleep(time.Millisecond)
	if err := s.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed, _ := store.Get(context.Background(), record.ID)
	if completed.Phase != "FINISHED" || completed.Outcome == nil || completed.Outcome.Result != "succeeded" || tr.calls != 1 || len(b.events) != 3 {
		t.Fatalf("replayed approval did not execute: %+v calls=%d events=%d", completed, tr.calls, len(b.events))
	}
}
func TestServiceFinishedOutboxRetriesExactBodyWithoutRerun(t *testing.T) {
	b := &serviceBroker{finishFailures: 1}
	s, store, tr := serviceFixture(t, b, Outcome{Result: "timeout"})
	r, _, _ := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ benign"))
	if err := s.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(context.Background(), r.ID)
	if !got.BrokerPending || got.Outcome.Result != "timeout" {
		t.Fatal(got)
	}
	// Make the scheduled retry due without relying on Windows clock resolution.
	store.mu.Lock()
	pending := store.records[r.ID]
	pending.NextAttempt = time.Time{}
	store.records[r.ID] = pending
	store.mu.Unlock()
	if err := s.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = store.Get(context.Background(), r.ID)
	if got.BrokerPending || tr.calls != 1 || len(b.events) != 3 || !bytes.Equal(b.events[1], b.events[2]) {
		t.Fatalf("retry mutated or reran: %+v, %d", got, tr.calls)
	}
	var finished map[string]json.RawMessage
	if err := json.Unmarshal(b.events[1], &finished); err != nil {
		t.Fatal(err)
	}
	if _, present := finished["exit_code"]; present {
		t.Fatalf("unknown exit code must be omitted: %s", b.events[1])
	}
}
func TestServiceApprovedRecoveryNeverRerunsEXE(t *testing.T) {
	b := &serviceBroker{}
	s, store, tr := serviceFixture(t, b, Outcome{})
	r, _, _ := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ benign"))
	claimed, _ := store.Claim(context.Background(), "old", time.Minute)
	claimed.Phase = "APPROVED"
	claimed.Owner = ""
	claimed.Connection = &Connection{TargetID: testTarget}
	if err := store.Save(context.Background(), *claimed, "old"); err != nil {
		t.Fatal(err)
	}
	if err := s.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(context.Background(), r.ID)
	if tr.calls != 0 || got.Outcome == nil || got.Outcome.Result != "unreachable" || got.BrokerPending {
		t.Fatalf("unsafe recovery=%+v calls=%d", got, tr.calls)
	}
}

type failingRecoveryTransport struct{}

func (failingRecoveryTransport) Execute(context.Context, Connection, Job) Outcome {
	panic("guest execution must not restart during recovery")
}
func (failingRecoveryTransport) Recover(context.Context, string) error {
	return errors.New("old RDP process could still be running")
}

func TestServiceRecoveryFailureBlocksWithoutReportingFinished(t *testing.T) {
	broker := &serviceBroker{}
	store := NewMemoryStore()
	service, err := NewService(DefaultServiceConfig(), store, broker, failingRecoveryTransport{})
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := service.Submit(context.Background(), testRequest, testTarget, []byte("MZ benign"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.Claim(context.Background(), "old", time.Minute)
	if err != nil || claimed == nil {
		t.Fatal(err)
	}
	claimed.Phase = "APPROVED"
	claimed.Owner = ""
	if err := store.Save(context.Background(), *claimed, "old"); err != nil {
		t.Fatal(err)
	}
	if err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), record.ID)
	if err != nil || got.Phase != "BLOCKED" || got.Outcome != nil || len(broker.events) != 0 {
		t.Fatalf("unrecovered RDP invocation was finalized: phase=%s outcome=%+v events=%d err=%v", got.Phase, got.Outcome, len(broker.events), err)
	}
}

func TestServiceAllApprovedFailuresFinishAndSuccessNeedsZero(t *testing.T) {
	nonzero := int64(7)
	zero := int64(0)
	for _, tc := range []struct {
		name string
		in   Outcome
		want string
	}{
		{"upload failure", Outcome{Result: "failed", ErrorCode: "COPY_FAILED"}, "failed"},
		{"login failed", Outcome{Result: "unreachable"}, "unreachable"},
		{"timeout", Outcome{Result: "timeout"}, "timeout"},
		{"false success", Outcome{Result: "succeeded", ExitCode: &nonzero}, "failed"},
		{"missing code", Outcome{Result: "succeeded"}, "failed"},
		{"unknown", Outcome{Result: "screen_connected"}, "failed"},
		{"real success", Outcome{Result: "succeeded", ExitCode: &zero}, "succeeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &serviceBroker{}
			s, store, _ := serviceFixture(t, b, tc.in)
			r, _, _ := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ benign"))
			if err := s.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			got, _ := store.Get(context.Background(), r.ID)
			if got.Outcome.Result != tc.want || len(b.events) != 2 {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
func TestServiceSubmitValidatesAndReplays(t *testing.T) {
	b := &serviceBroker{}
	s, _, _ := serviceFixture(t, b, Outcome{})
	if _, _, err := s.Submit(context.Background(), "bad", testTarget, []byte("MZ")); err == nil {
		t.Fatal("bad UUID accepted")
	}
	if _, _, err := s.Submit(context.Background(), testRequest, testTarget, []byte("ELF")); err == nil {
		t.Fatal("non EXE accepted")
	}
	a, _, _ := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ fixture"))
	brec, created, err := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ fixture"))
	if err != nil || created || a.ID != brec.ID {
		t.Fatal("replay changed execution")
	}
	if _, _, err = s.Submit(context.Background(), testRequest, testTarget, []byte("MZ other")); !errors.Is(err, ErrConflict) {
		t.Fatal("conflict not detected", err)
	}
}

func TestServiceBoundsGuestOutputAndSanitizesDiagnostics(t *testing.T) {
	b := &serviceBroker{}
	s, store, _ := serviceFixture(t, b, Outcome{Result: "failed", Stdout: "가나다", Stderr: "abcdefg", ErrorCode: "guest_io_failed"})
	s.cfg.OutputLimit = 5
	r, _, _ := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ fixture"))
	if err := s.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(context.Background(), r.ID)
	if got.Outcome.Stdout != "가" || got.Outcome.Stderr != "abcde" || !got.Outcome.StdoutTruncated || !got.Outcome.StderrTruncated || got.Outcome.ErrorCode != "guest_io_failed" {
		t.Fatalf("bad bounded result %+v", got.Outcome)
	}
}

func TestServiceQueuedLimitsSurviveWorkerConfigChange(t *testing.T) {
	b := &serviceBroker{}
	s, store, tr := serviceFixture(t, b, Outcome{Result: "failed"})
	s.cfg.ExecutionTimeout = 5 * time.Second
	s.cfg.ConnectTimeout = 4 * time.Second
	s.cfg.OutputLimit = 16
	r, _, err := s.Submit(context.Background(), testRequest, testTarget, []byte("MZ fixture"))
	if err != nil {
		t.Fatal(err)
	}
	changed := DefaultServiceConfig()
	changed.ExecutionTimeout = 9 * time.Second
	changed.OutputLimit = 100
	worker, err := NewService(changed, store, b, tr)
	if err != nil {
		t.Fatal(err)
	}
	replay, created, err := worker.Submit(context.Background(), testRequest, testTarget, []byte("MZ fixture"))
	if err != nil || created || replay.ID != r.ID {
		t.Fatal("server config change broke submission replay", err)
	}
	if err = worker.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tr.job.Timeout != 5*time.Second || tr.job.ConnectTimeout != 4*time.Second || tr.job.OutputLimit != 16 {
		t.Fatalf("queued limits changed: %+v", tr.job)
	}
}

type blockedRenewStore struct{ Store }

func (s blockedRenewStore) Renew(ctx context.Context, _, _ string, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

type cancelAwareTransport struct{ stopped chan struct{} }

func (t cancelAwareTransport) Execute(ctx context.Context, _ Connection, _ Job) Outcome {
	<-ctx.Done()
	close(t.stopped)
	return Outcome{Result: "unreachable"}
}

func TestServiceStalledRenewalCancelsBeforeLeaseExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cfg := DefaultServiceConfig()
	cfg.LeaseDuration = time.Second
	transport := cancelAwareTransport{stopped: make(chan struct{})}
	s, err := NewService(cfg, blockedRenewStore{NewMemoryStore()}, &serviceBroker{}, transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Submit(ctx, testRequest, testTarget, []byte("MZ fixture")); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- s.ProcessOne(ctx) }()
	select {
	case <-transport.stopped:
	case <-time.After(1500 * time.Millisecond):
		cancel()
		<-finished
		t.Fatal("RDP stayed alive beyond confirmed lease")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("renewal prevented worker shutdown")
	}
}
