package runtimepg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func TestPostgresCreateReconciliationSurvivesRestartAndRejectsLateCreate(t *testing.T) {
	database := openTestDatabase(t)
	command := validResolvedPwnCommand(t)
	command.RequestFingerprint = "original-input"
	fence, created, err := database.Operations().ReconcileCreate(command, 4)
	if err != nil || !created || fence.Status != operations.OperationStatusFailed ||
		fence.LastErrorCode != "CREATE_NOT_ACCEPTED" || !fence.Result.CreateCleanupCompleted {
		t.Fatalf("fence = %#v, created=%t, err=%v", fence, created, err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(context.Background(), os.Getenv("PROVISIONER_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	late, created, err := restarted.Operations().EnqueueCreate(command, 4)
	if err != nil || created || late.ID != fence.ID || late.Status != operations.OperationStatusFailed {
		t.Fatalf("late create = %#v, created=%t, err=%v", late, created, err)
	}
	_, claimed, err := restarted.Operations().Claim(context.Background(), operations.ClaimOptions{
		WorkerID: "restarted-worker", Now: time.Now().UTC(), LeaseDuration: time.Minute,
	})
	if err != nil || claimed {
		t.Fatalf("terminal fence became executable: claimed=%t, err=%v", claimed, err)
	}
	command.TargetID = "different-target"
	if _, _, err := restarted.Operations().ReconcileCreate(command, 4); !errors.Is(err, operations.ErrIdempotencyConflict) {
		t.Fatalf("identity mismatch = %v", err)
	}
}

func TestPostgresCreateAndReconciliationRaceKeepOneDecision(t *testing.T) {
	database := openTestDatabase(t)
	for iteration := range 25 {
		command := validResolvedPwnCommand(t)
		command.RequestID = fmt.Sprintf("create-reconcile-race-%d", iteration)
		command.RequestFingerprint = "same-original-input"
		start := make(chan struct{})
		ids := make(chan string, 16)
		errorsFound := make(chan error, 16)
		var workers sync.WaitGroup
		for index := range 16 {
			workers.Add(1)
			go func(reconcile bool) {
				defer workers.Done()
				<-start
				var operation operations.Operation
				var err error
				if reconcile {
					operation, _, err = database.Operations().ReconcileCreate(command, 4)
				} else {
					operation, _, err = database.Operations().EnqueueCreate(command, 4)
				}
				ids <- operation.ID
				errorsFound <- err
			}(index%2 == 0)
		}
		close(start)
		workers.Wait()
		close(ids)
		close(errorsFound)
		for err := range errorsFound {
			if err != nil {
				t.Fatal(err)
			}
		}
		stored, err := database.Operations().GetByRequestID(command.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		for id := range ids {
			if id != stored.ID {
				t.Fatalf("race returned different operations: got %s, stored %s", id, stored.ID)
			}
		}
		var count int
		if err := database.db.QueryRow("SELECT count(*) FROM runtime_operations WHERE request_id=$1", command.RequestID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("operation count=%d, err=%v", count, err)
		}
		if stored.Status != operations.OperationStatusQueued &&
			(stored.Status != operations.OperationStatusFailed || !stored.Result.CreateCleanupCompleted) {
			t.Fatalf("invalid race decision: %#v", stored)
		}
	}
}

func TestPostgresReconciliationPreservesAcceptedRunningCreate(t *testing.T) {
	database := openTestDatabase(t)
	command := validResolvedPwnCommand(t)
	command.RequestFingerprint = "original-input"
	accepted, _, err := database.Operations().EnqueueCreate(command, 4)
	if err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := database.Operations().Claim(context.Background(), operations.ClaimOptions{
		WorkerID: "original-worker", Now: time.Now().UTC(), LeaseDuration: time.Minute,
	})
	if err != nil || !ok {
		t.Fatalf("claim ok=%t err=%v", ok, err)
	}
	resolved, created, err := database.Operations().ReconcileCreate(command, 4)
	if err != nil || created || resolved.ID != accepted.ID || resolved.Status != operations.OperationStatusRunning || resolved.Result.CreateCleanupCompleted {
		t.Fatalf("running create was changed: %#v, created=%t, err=%v", resolved, created, err)
	}
	if _, err := database.Operations().MarkLeaseFailed(claimed, operations.Failure{Code: "WORKLOAD_NOT_READY", CreateCleanupCompleted: true}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	resolved, _, err = database.Operations().ReconcileCreate(command, 4)
	if err != nil || !resolved.Result.CreateCleanupCompleted || resolved.LastErrorCode != "WORKLOAD_NOT_READY" {
		t.Fatalf("original terminal result not preserved: %#v, %v", resolved, err)
	}
}
