package windowsruntime_test

import (
	"context"
	"errors"
	"testing"
	"time"

	win "github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

const recoveryTargetID = "00000000-0000-4000-8000-000000000021"
const recoveryExecutionID = "00000000-0000-4000-8000-000000000022"
const recoveryRequestID = "00000000-0000-4000-8000-000000000023"
const recoveryEventID = "00000000-0000-4000-8000-000000000024"

type recoveryRecorder interface {
	Submit(context.Context, win.Record) (win.Record, bool, error)
	ConfirmRecovery(context.Context, string, string, string) (win.RecoveryReceipt, error)
}

func testRecoveryReceipt(t *testing.T, store recoveryRecorder) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	record := win.Record{ID: recoveryExecutionID, RequestID: recoveryRequestID, TargetID: recoveryTargetID,
		Fingerprint: "fixture", Phase: "FINISHED", BrokerPending: true,
		Checker:   &win.CheckerJob{Request: &win.CheckerRequest{SelectionMode: "broker_pool"}},
		CreatedAt: now, UpdatedAt: now, ExecutionTimeout: time.Minute, ConnectTimeout: time.Minute, OutputLimit: 65536}
	if _, _, err := store.Submit(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRecovery(ctx, recoveryTargetID, recoveryExecutionID, recoveryEventID); !errors.Is(err, win.ErrRecoveryNotReady) {
		t.Fatalf("pending Broker finish accepted: %v", err)
	}
	if _, err := store.ConfirmRecovery(ctx, "00000000-0000-4000-8000-000000000025", recoveryExecutionID, recoveryEventID); !errors.Is(err, win.ErrConflict) {
		t.Fatalf("wrong VM accepted: %v", err)
	}
	if _, err := store.ConfirmRecovery(ctx, recoveryTargetID, "00000000-0000-4000-8000-000000000026", recoveryEventID); !errors.Is(err, win.ErrNotFound) {
		t.Fatalf("unknown execution accepted: %v", err)
	}
	// The Broker finish acknowledgement has now been saved with the execution.
	markBrokerFinished(t, store, record)
	first, err := store.ConfirmRecovery(ctx, recoveryTargetID, recoveryExecutionID, recoveryEventID)
	if err != nil || first.Replayed || first.CleanupDelivery != "PENDING" || first.VMState != "READY" || first.RecoveredAt.IsZero() {
		t.Fatalf("recovery not durably accepted: %+v %v", first, err)
	}
	replay, err := store.ConfirmRecovery(ctx, recoveryTargetID, recoveryExecutionID, recoveryEventID)
	if err != nil || !replay.Replayed || !replay.RecoveredAt.Equal(first.RecoveredAt) {
		t.Fatalf("same event not replayed: %+v %v", replay, err)
	}
	if _, err := store.ConfirmRecovery(ctx, recoveryTargetID, recoveryExecutionID, "00000000-0000-4000-8000-000000000027"); !errors.Is(err, win.ErrConflict) {
		t.Fatalf("changed event ID accepted: %v", err)
	}
}

func markBrokerFinished(t *testing.T, store recoveryRecorder, record win.Record) {
	t.Helper()
	ctx := context.Background()
	claimable, ok := store.(interface {
		Claim(context.Context, string, time.Duration) (*win.Record, error)
		Save(context.Context, win.Record, string) error
	})
	if !ok {
		t.Fatal("store cannot checkpoint Broker finish")
	}
	claimed, err := claimable.Claim(ctx, "recovery-test-worker", time.Minute)
	if err != nil || claimed == nil || claimed.ID != record.ID {
		t.Fatalf("claim pending finish: %+v %v", claimed, err)
	}
	claimed.BrokerPending = false
	claimed.Owner = ""
	if err := claimable.Save(ctx, *claimed, "recovery-test-worker"); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryStoreRecoveryReceipt(t *testing.T) {
	testRecoveryReceipt(t, win.NewMemoryStore())
}

func TestPostgresStoreRecoveryReceipt(t *testing.T) {
	store, db := postgresStore(t)
	testRecoveryReceipt(t, store)
	var state string
	if err := db.QueryRow(`SELECT backend_cleanup_state FROM runtime_windows_recovery_events WHERE execution_id=$1`, recoveryExecutionID).Scan(&state); err != nil || state != "PENDING" {
		t.Fatalf("Backend cleanup outbox not retained: state=%q err=%v", state, err)
	}
	// A fresh store object must observe the same event after a Runtime restart.
	replay, err := win.NewPostgresStore(db).ConfirmRecovery(context.Background(), recoveryTargetID, recoveryExecutionID, recoveryEventID)
	if err != nil || !replay.Replayed {
		t.Fatalf("recovery lost after restart: %+v %v", replay, err)
	}
}

func TestPostgresRecoveryOutboxWaitsForResultAndSurvivesRestart(t *testing.T) {
	store, db := postgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	record := win.Record{ID: recoveryExecutionID, RequestID: recoveryRequestID, TargetID: recoveryTargetID,
		Fingerprint: "fixture", Phase: "FINISHED", CreatedAt: now, UpdatedAt: now,
		Checker: &win.CheckerJob{ResultEventID: "00000000-0000-4000-8000-000000000028", ResultPending: true,
			Request: &win.CheckerRequest{SelectionMode: "broker_pool"}},
		ExecutionTimeout: time.Minute, ConnectTimeout: time.Minute, OutputLimit: 65536}
	if _, _, err := store.Submit(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRecovery(ctx, recoveryTargetID, recoveryExecutionID, recoveryEventID); err != nil {
		t.Fatal(err)
	}
	if pending, err := store.ClaimRecovery(ctx, "worker-a", time.Minute); err != nil || pending != nil {
		t.Fatalf("cleanup ran before RESULT acknowledgement: %+v %v", pending, err)
	}
	claimed, err := store.Claim(ctx, "result-worker", time.Minute)
	if err != nil || claimed == nil {
		t.Fatalf("result claim: %+v %v", claimed, err)
	}
	claimed.Checker.ResultPending = false
	claimed.Owner = ""
	if err := store.Save(ctx, *claimed, "result-worker"); err != nil {
		t.Fatal(err)
	}
	restarted := win.NewPostgresStore(db)
	first, err := restarted.ClaimRecovery(ctx, "worker-a", time.Minute)
	if err != nil || first == nil || first.Receipt.EventID != recoveryEventID {
		t.Fatalf("pending cleanup lost after restart: %+v %v", first, err)
	}
	if duplicate, err := store.ClaimRecovery(ctx, "worker-b", time.Minute); err != nil || duplicate != nil {
		t.Fatalf("second worker claimed same cleanup: %+v %v", duplicate, err)
	}
	if err := store.CompleteRecovery(ctx, recoveryExecutionID, "worker-b", true, time.Time{}); !errors.Is(err, win.ErrLeaseLost) {
		t.Fatalf("wrong owner confirmed cleanup: %v", err)
	}
	if err := restarted.CompleteRecovery(ctx, recoveryExecutionID, "worker-a", false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	second, err := store.ClaimRecovery(ctx, "worker-b", time.Minute)
	if err != nil || second == nil || second.Receipt.EventID != first.Receipt.EventID || !second.Receipt.RecoveredAt.Equal(first.Receipt.RecoveredAt) {
		t.Fatalf("retry changed cleanup identity: %+v %v", second, err)
	}
	if err := store.CompleteRecovery(ctx, recoveryExecutionID, "worker-b", true, time.Time{}); err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.ConfirmRecovery(ctx, recoveryTargetID, recoveryExecutionID, recoveryEventID)
	if err != nil || replayed.CleanupDelivery != "CONFIRMED" || !replayed.Replayed {
		t.Fatalf("confirmed cleanup not visible: %+v %v", replayed, err)
	}
	if remaining, err := restarted.ClaimRecovery(ctx, "worker-c", time.Minute); err != nil || remaining != nil {
		t.Fatalf("confirmed cleanup was reclaimed: %+v %v", remaining, err)
	}
}
