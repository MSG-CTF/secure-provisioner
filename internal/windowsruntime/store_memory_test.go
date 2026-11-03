package windowsruntime_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	win "github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
	"github.com/google/uuid"
)

func queuedRecord(target string) win.Record {
	return win.Record{ID: uuid.NewString(), RequestID: uuid.NewString(), TargetID: target, Fingerprint: "payload-and-limits-digest", Phase: "QUEUED", Payload: []byte("MZ-test-executable"), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
}

func TestMemoryStoreIdempotencyAndCopies(t *testing.T) {
	testStoreIdempotencyAndCopies(t, win.NewMemoryStore())
}

func testStoreIdempotencyAndCopies(t *testing.T, store win.Store) {
	t.Helper()
	ctx := context.Background()
	submitted := queuedRecord(targetID)
	first, created, err := store.Submit(ctx, submitted)
	if err != nil || !created || first.ID != submitted.ID {
		t.Fatalf("submit = %#v, %t, %v", first, created, err)
	}
	submitted.Payload[0] = 'x'
	first.Payload[1] = 'x'
	retry := queuedRecord(targetID)
	retry.RequestID = submitted.RequestID
	again, created, err := store.Submit(ctx, retry)
	if err != nil || created || again.ID != first.ID || string(again.Payload) != "MZ-test-executable" {
		t.Fatalf("retry = %#v, %t, %v", again, created, err)
	}
	for _, mutate := range []func(*win.Record){func(r *win.Record) { r.Fingerprint = "other" }, func(r *win.Record) { r.TargetID = executionID }} {
		conflict := retry
		mutate(&conflict)
		if _, _, err := store.Submit(ctx, conflict); !errors.Is(err, win.ErrConflict) {
			t.Fatalf("conflict = %v", err)
		}
	}
	if _, err := store.Get(ctx, uuid.NewString()); !errors.Is(err, win.ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
}

func TestMemoryStoreSerializesClaimsPerVM(t *testing.T) {
	testStoreSerializesClaimsPerVM(t, win.NewMemoryStore())
}

func TestMemoryStoreBindsOnlyOneUnboundJobPerVM(t *testing.T) {
	testStoreBindsOnlyOneUnboundJobPerVM(t, win.NewMemoryStore())
}

func testStoreBindsOnlyOneUnboundJobPerVM(t *testing.T, store win.Store) {
	t.Helper()
	ctx := context.Background()
	for range 2 {
		record := queuedRecord(win.UnboundTargetID)
		record.Checker = &win.CheckerJob{Request: &win.CheckerRequest{SelectionMode: "broker_pool"}}
		if _, _, err := store.Submit(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.Claim(ctx, "worker-a", time.Minute)
	if err != nil || first == nil {
		t.Fatalf("first claim: %+v %v", first, err)
	}
	second, err := store.Claim(ctx, "worker-b", time.Minute)
	if err != nil || second == nil || first.ID == second.ID {
		t.Fatalf("second unbound claim: %+v %v", second, err)
	}
	bound, err := store.BindTarget(ctx, first.ID, "worker-a", targetID)
	if err != nil || !bound {
		t.Fatalf("first bind: %v %v", bound, err)
	}
	bound, err = store.BindTarget(ctx, second.ID, "worker-b", targetID)
	if err != nil || bound {
		t.Fatalf("double bind: %v %v", bound, err)
	}
	first.TargetID = targetID
	first.Phase = "REJECTED"
	first.Owner = ""
	if err := store.Save(ctx, *first, "worker-a"); err != nil {
		t.Fatal(err)
	}
	bound, err = store.BindTarget(ctx, second.ID, "worker-b", targetID)
	if err != nil || !bound {
		t.Fatalf("bind after release: %v %v", bound, err)
	}
	retry := queuedRecord(win.UnboundTargetID)
	retry.RequestID, retry.Fingerprint, retry.Checker = first.RequestID, first.Fingerprint, first.Checker
	got, created, err := store.Submit(ctx, retry)
	if err != nil || created || got.TargetID != targetID {
		t.Fatalf("idempotent replay after binding: %+v %v %v", got, created, err)
	}
}

func testStoreSerializesClaimsPerVM(t *testing.T, store win.Store) {
	t.Helper()
	ctx := context.Background()
	for range 10 {
		if _, _, err := store.Submit(ctx, queuedRecord(targetID)); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	claims := make(chan *win.Record, 10)
	errs := make(chan error, 10)
	for range 10 {
		wg.Go(func() {
			record, err := store.Claim(ctx, uuid.NewString(), time.Minute)
			if err != nil {
				errs <- err
			}
			if record != nil {
				claims <- record
			}
		})
	}
	wg.Wait()
	close(claims)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	var claimed []*win.Record
	for record := range claims {
		claimed = append(claimed, record)
	}
	if len(claimed) != 1 {
		t.Fatalf("concurrent same-VM claims = %d", len(claimed))
		return
	}
	current := *claimed[0]
	current.Phase = "START_PENDING"
	current.StartUncertain = true
	current.Owner = ""
	current.NextAttempt = time.Now().Add(time.Hour)
	if err := store.Save(ctx, current, claimed[0].Owner); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Claim(ctx, "other-worker", time.Minute); err != nil || got != nil {
		t.Fatalf("claimed another VM execution while start uncertain: %#v, %v", got, err)
	}
	if _, _, err := store.Submit(ctx, queuedRecord(executionID)); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Claim(ctx, "other-worker", time.Minute); err != nil || got == nil || got.TargetID != executionID {
		t.Fatalf("different VM blocked: %#v, %v", got, err)
	}
}

func TestMemoryStoreFencesLeaseAndPersistsOutbox(t *testing.T) {
	testStoreFencesLeaseAndPersistsOutbox(t, win.NewMemoryStore())
}

func testStoreFencesLeaseAndPersistsOutbox(t *testing.T, store win.Store) {
	t.Helper()
	ctx := context.Background()
	submitted := queuedRecord(targetID)
	if _, _, err := store.Submit(ctx, submitted); err != nil {
		t.Fatal(err)
	}
	first, err := store.Claim(ctx, "worker-a", 60*time.Millisecond)
	if err != nil || first == nil {
		t.Fatalf("claim = %#v, %v", first, err)
	}
	if first.Attempt != 1 {
		t.Fatalf("attempt = %d", first.Attempt)
	}
	if err := store.Save(ctx, *first, "worker-b"); !errors.Is(err, win.ErrLeaseLost) {
		t.Fatalf("foreign save = %v", err)
	}
	if err := store.Renew(ctx, first.ID, "worker-b", time.Minute); !errors.Is(err, win.ErrLeaseLost) {
		t.Fatalf("foreign renew = %v", err)
	}
	first.Phase = "RUNNING"
	first.StartedBody = []byte(`{"execution_id":"same","event":"started"}`)
	first.StartUncertain = true
	first.Connection = &win.Connection{TargetID: targetID, Protocol: "rdp", Host: "203.0.113.10", Port: 3389, Username: "msgexec"}
	if err := store.Save(ctx, *first, first.Owner); err != nil {
		t.Fatal(err)
	}
	time.Sleep(85 * time.Millisecond)
	if err := store.Save(ctx, *first, first.Owner); !errors.Is(err, win.ErrLeaseLost) {
		t.Fatalf("expired save = %v", err)
	}
	if err := store.Renew(ctx, first.ID, first.Owner, time.Minute); !errors.Is(err, win.ErrLeaseLost) {
		t.Fatalf("expired renew = %v", err)
	}
	second, err := store.Claim(ctx, "worker-b", time.Minute)
	if err != nil || second == nil {
		t.Fatalf("reclaim = %#v, %v", second, err)
	}
	if second.Attempt != 2 || second.Phase != "RUNNING" || !second.StartUncertain || !reflect.DeepEqual(second.StartedBody, first.StartedBody) || !reflect.DeepEqual(second.Connection, first.Connection) {
		t.Fatalf("lost recovery metadata: %#v", second)
	}
	if err := store.Save(ctx, *first, first.Owner); !errors.Is(err, win.ErrLeaseLost) {
		t.Fatalf("stale save = %v", err)
	}
	second.Phase = "FINISHED"
	second.BrokerPending = true
	second.FinishedBody = []byte(`{"execution_id":"same","event":"finished","result":"unreachable","exit_code":null}`)
	second.Outcome = &win.Outcome{Result: "unreachable", Stdout: "retained output"}
	second.Owner = ""
	if err := store.Save(ctx, *second, "worker-b"); err != nil {
		t.Fatal(err)
	}
	second.FinishedBody[0] = 'x'
	second.Connection.Username = "mutated"
	second.Outcome.Stdout = "mutated"
	third, err := store.Claim(ctx, "outbox-worker", time.Minute)
	if err != nil || third == nil || third.Phase != "FINISHED" || !third.BrokerPending || third.Attempt != 3 || third.FinishedBody[0] != '{' || third.Connection.Username != "msgexec" || third.Outcome.Stdout != "retained output" {
		t.Fatalf("outbox recovery = %#v, %v", third, err)
	}
	third.BrokerPending = false
	third.Owner = ""
	if err := store.Save(ctx, *third, "outbox-worker"); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Claim(ctx, "worker-c", time.Minute); err != nil || got != nil {
		t.Fatalf("claimed delivered execution: %#v, %v", got, err)
	}
}

func TestMemoryStoreSavePreservesRenewedLease(t *testing.T) {
	testStoreSavePreservesRenewedLease(t, win.NewMemoryStore())
}

func testStoreSavePreservesRenewedLease(t *testing.T, store win.Store) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := store.Submit(ctx, queuedRecord(targetID)); err != nil {
		t.Fatal(err)
	}
	record, err := store.Claim(ctx, "worker-a", 60*time.Millisecond)
	if err != nil || record == nil {
		t.Fatalf("claim = %#v, %v", record, err)
	}
	if err := store.Renew(ctx, record.ID, record.Owner, time.Minute); err != nil {
		t.Fatal(err)
	}
	record.Phase = "APPROVED"
	if err := store.Save(ctx, *record, record.Owner); err != nil {
		t.Fatal(err)
	}
	time.Sleep(85 * time.Millisecond)
	if err := store.Save(ctx, *record, record.Owner); err != nil {
		t.Fatalf("save shortened renewed lease: %v", err)
	}
	stored, err := store.Get(ctx, record.ID)
	if err != nil || !stored.LeaseUntil.After(time.Now().Add(30*time.Second)) {
		t.Fatalf("renewed lease lost: %#v, %v", stored, err)
	}
}

func TestMemoryStoreSkipsBlockedRejectedNotDueAndFinished(t *testing.T) {
	testStoreSkipsIneligible(t, win.NewMemoryStore())
}

func testStoreSkipsIneligible(t *testing.T, store win.Store) {
	t.Helper()
	ctx := context.Background()
	for _, phase := range []string{"BLOCKED", "REJECTED", "FINISHED", "QUEUED"} {
		record := queuedRecord(uuid.NewString())
		record.Phase = phase
		if phase == "QUEUED" {
			record.NextAttempt = time.Now().Add(time.Hour)
		}
		if _, _, err := store.Submit(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := store.Claim(ctx, "worker", time.Minute); err != nil || got != nil {
		t.Fatalf("ineligible claim = %#v, %v", got, err)
	}
	tooLarge := queuedRecord(uuid.NewString())
	tooLarge.Payload = make([]byte, 10*1024*1024+1)
	if _, _, err := store.Submit(ctx, tooLarge); err == nil {
		t.Fatal("accepted oversized executable")
	}
}
