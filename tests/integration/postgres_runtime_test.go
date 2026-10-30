package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimepg"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresLeaseRecoveryAcrossStoreRestart(t *testing.T) {
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	firstDatabase, err := runtimepg.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.Exec(`TRUNCATE runtime_operations, runtime_bindings`); err != nil {
		t.Fatal(err)
	}
	command := provisioner.DeleteWorkloadCommand{RequestID: "restart-delete", InstanceID: "11111111-1111-4111-8111-111111111111", TeamID: "00000000-0000-4000-8000-000000000001", RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: "aws-k3s-001", RuntimeWorkloadID: "aws-k3s-001/instance-11111111", Reason: provisioner.DeleteReasonTTLExpired}
	if _, _, err := firstDatabase.Operations().EnqueueDelete(command, 4); err != nil {
		t.Fatal(err)
	}
	first, ok, err := firstDatabase.Operations().Claim(context.Background(), operations.ClaimOptions{WorkerID: "worker-a", Now: time.Unix(100, 0), LeaseDuration: time.Minute})
	if err != nil || !ok {
		t.Fatalf("first claim = %#v, %t, %v", first, ok, err)
	}
	if err := firstDatabase.Close(); err != nil {
		t.Fatal(err)
	}
	secondDatabase, err := runtimepg.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer secondDatabase.Close()
	second, ok, err := secondDatabase.Operations().Claim(context.Background(), operations.ClaimOptions{WorkerID: "worker-b", Now: time.Unix(161, 0), LeaseDuration: time.Minute})
	if err != nil || !ok || second.Operation.ID != first.Operation.ID || second.Lease.Version <= first.Lease.Version {
		t.Fatalf("reclaim = %#v, %t, %v", second, ok, err)
	}
	if _, err := secondDatabase.Operations().MarkLeaseSucceeded(first, operations.OperationResult{DeleteCompleted: true}, time.Unix(162, 0)); !errors.Is(err, operations.ErrLeaseLost) {
		t.Fatalf("stale completion error = %v", err)
	}
}
