package operations

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestMemoryCreateReconciliationNeverQueuesUnacceptedCreate(t *testing.T) {
	store := NewMemoryStore(nil)
	command := provisioner.CreateWorkloadCommand{RequestID: "lost-create", InstanceID: "instance", TeamID: "team", TargetID: "target", RequestFingerprint: "input"}
	fence, created, err := store.ReconcileCreate(command, 4)
	if err != nil || !created || !fence.Result.CreateCleanupCompleted {
		t.Fatalf("fence=%#v created=%t err=%v", fence, created, err)
	}
	late, created, err := store.EnqueueCreate(command, 4)
	if err != nil || created || late.ID != fence.ID || late.Status != OperationStatusFailed {
		t.Fatalf("late create=%#v created=%t err=%v", late, created, err)
	}
	if _, claimed, err := store.Claim(context.Background(), ClaimOptions{WorkerID: "worker", Now: time.Now(), LeaseDuration: time.Minute}); err != nil || claimed {
		t.Fatalf("fenced create was claimed: %t, %v", claimed, err)
	}
	command.RequestFingerprint = "changed-input"
	if _, _, err := store.ReconcileCreate(command, 4); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed request conflict=%v", err)
	}
}

func TestMemoryCreateReconciliationReturnsExistingQueuedCreate(t *testing.T) {
	store := NewMemoryStore(nil)
	command := provisioner.CreateWorkloadCommand{RequestID: "accepted-create", RequestFingerprint: "input"}
	original, _, err := store.EnqueueCreate(command, 4)
	if err != nil {
		t.Fatal(err)
	}
	resolved, created, err := store.ReconcileCreate(command, 4)
	if err != nil || created || resolved.ID != original.ID || resolved.Status != OperationStatusQueued || resolved.Result.CreateCleanupCompleted {
		t.Fatalf("queued create changed: %#v, created=%t, err=%v", resolved, created, err)
	}
}
