package runtimepg

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func TestDeploymentHandoffBlocksClaimsAndQueueWritesButNotReads(t *testing.T) {
	database := openTestDatabase(t)
	op, _, err := database.Operations().EnqueueDelete(validDeleteCommand("handoff-delete"), 4)
	if err != nil {
		t.Fatal(err)
	}
	release, err := database.AcquireDeploymentHandoff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := database.Operations().Get(op.ID); err != nil {
		t.Fatal("handoff blocked operation reads", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, ok, err := database.Operations().Claim(ctx, operations.ClaimOptions{WorkerID: "old", Now: time.Now(), LeaseDuration: time.Minute}); err == nil || ok {
		t.Fatal("old worker could claim across the handoff fence")
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := database.Operations().EnqueueDelete(validDeleteCommand("during-handoff"), 4)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("queue write bypassed handoff: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queue write did not resume")
	}
	claimed, ok, err := database.Operations().Claim(context.Background(), operations.ClaimOptions{WorkerID: "new", Now: time.Now(), LeaseDuration: time.Minute})
	if err != nil || !ok || claimed.Operation.ID != op.ID || claimed.Operation.Attempt != 1 {
		t.Fatalf("handoff lost or duplicated operation: %+v, %v", claimed, err)
	}
}

func TestDeploymentHandoffDoesNotCancelRunningOperation(t *testing.T) {
	database := openTestDatabase(t)
	op, _, err := database.Operations().EnqueueDelete(validDeleteCommand("active-before-deploy"), 4)
	if err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := database.Operations().Claim(context.Background(), operations.ClaimOptions{WorkerID: "old", Now: time.Now(), LeaseDuration: time.Minute})
	if err != nil || !ok {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if release, err := database.AcquireDeploymentHandoff(ctx); err == nil {
		_ = release()
		t.Fatal("handoff interrupted active operation")
	}
	if _, err := database.Operations().MarkLeaseSucceeded(claimed, operations.OperationResult{DeleteCompleted: true}, time.Now()); err != nil {
		t.Fatal("handoff broke active lease", err)
	}
	result, err := database.Operations().Get(op.ID)
	if err != nil || result.Status != operations.OperationStatusSucceeded {
		t.Fatalf("active operation did not complete: %+v %v", result, err)
	}
}

func TestDeploymentHandoffDatabaseDeadlineReleasesAbandonedFence(t *testing.T) {
	database := openTestDatabase(t)
	release, err := database.AcquireDeploymentHandoff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	done := make(chan error, 1)
	go func() {
		_, _, err := database.Operations().EnqueueDelete(validDeleteCommand("abandoned-fence"), 4)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("abandoned fence kept blocking API writes")
	}
}

func TestOpenExistingChecksCompatibilityWithoutRepairingSchema(t *testing.T) {
	database := openTestDatabase(t)
	if _, err := database.db.Exec("ALTER TABLE runtime_operations RENAME COLUMN lease_version TO hidden_lease_version"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = database.db.Exec("ALTER TABLE runtime_operations RENAME COLUMN hidden_lease_version TO lease_version")
	}()
	other, err := OpenExisting(context.Background(), os.Getenv("PROVISIONER_TEST_DATABASE_URL"))
	if err == nil {
		_ = other.Close()
		t.Fatal("incompatible live schema was accepted")
	}
	var present bool
	if err := database.db.QueryRow("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='runtime_operations' AND column_name='hidden_lease_version')").Scan(&present); err != nil || !present {
		t.Fatal("bridge changed the live database schema", err)
	}
}
