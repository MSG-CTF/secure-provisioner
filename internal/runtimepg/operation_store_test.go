package runtimepg

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestPostgresOperationStorePrioritizesDeleteAndFencesExpiredLease(t *testing.T) {
	database := openTestDatabase(t)
	store := database.Operations()
	create, _, err := store.EnqueueCreate(validResolvedPwnCommand(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	deleteCommand := validDeleteCommand("delete-request")
	deleted, _, err := store.EnqueueDelete(deleteCommand, 4)
	if err != nil {
		t.Fatal(err)
	}
	first, ok, err := store.Claim(context.Background(), operations.ClaimOptions{WorkerID: "worker-a", Now: time.Unix(100, 0), LeaseDuration: time.Minute})
	if err != nil || !ok || first.Operation.ID != deleted.ID {
		t.Fatalf("first claim = %#v, %t, %v; create=%s delete=%s", first, ok, err, create.ID, deleted.ID)
	}
	reclaimed, ok, err := store.Claim(context.Background(), operations.ClaimOptions{WorkerID: "worker-b", Now: time.Unix(161, 0), LeaseDuration: time.Minute})
	if err != nil || !ok || reclaimed.Operation.ID != deleted.ID {
		t.Fatalf("reclaim = %#v, %t, %v", reclaimed, ok, err)
	}
	if _, err := store.MarkLeaseSucceeded(first, operations.OperationResult{DeleteCompleted: true}, time.Unix(162, 0)); !errors.Is(err, operations.ErrLeaseLost) {
		t.Fatalf("stale completion error = %v", err)
	}
}

func TestPostgresOperationStoreRejectsRequestPayloadConflict(t *testing.T) {
	database := openTestDatabase(t)
	store := database.Operations()
	command := validResolvedPwnCommand(t)
	if _, created, err := store.EnqueueCreate(command, 4); err != nil || !created {
		t.Fatalf("first enqueue created=%t err=%v", created, err)
	}
	command.TargetID = "gcp-k3s-001"
	if _, _, err := store.EnqueueCreate(command, 4); !errors.Is(err, operations.ErrIdempotencyConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}

func openTestDatabase(t *testing.T) *Database {
	t.Helper()
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	database, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(context.Background(), "TRUNCATE runtime_operations"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func validDeleteCommand(requestID string) provisioner.DeleteWorkloadCommand {
	return provisioner.DeleteWorkloadCommand{
		RequestID: requestID, InstanceID: "11111111-1111-4111-8111-111111111111", TeamID: 1,
		RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: "aws-k3s-001",
		RuntimeWorkloadID: "aws-k3s-001/instance-11111111", Reason: provisioner.DeleteReasonUserRequested,
	}
}
