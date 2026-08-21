package workerload_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimepg"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresAccepts500ConcurrentUniqueRequests(t *testing.T) {
	database, sqlDB := openDatabase(t)
	const requestCount = 500
	var failures atomic.Int64
	var wait sync.WaitGroup
	for index := range requestCount {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			command := createCommand(fmt.Sprintf("load-%03d", i), fmt.Sprintf("%08d-1111-4111-8111-111111111111", i))
			if _, created, err := database.Operations().EnqueueCreate(command, 4); err != nil || !created {
				failures.Add(1)
			}
		}(index)
	}
	wait.Wait()
	if failures.Load() != 0 {
		t.Fatalf("enqueue failures = %d", failures.Load())
	}
	var count int
	if err := sqlDB.QueryRow(`SELECT count(*) FROM runtime_operations WHERE request_id LIKE 'load-%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != requestCount {
		t.Fatalf("row count = %d, want %d", count, requestCount)
	}
}

func TestPostgresCollapses100ConcurrentIdempotentRequests(t *testing.T) {
	database, sqlDB := openDatabase(t)
	command := createCommand("duplicate-request", "99999999-1111-4111-8111-111111111111")
	var createdCount atomic.Int64
	var failureCount atomic.Int64
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, created, err := database.Operations().EnqueueCreate(command, 4)
			if err != nil {
				failureCount.Add(1)
				return
			}
			if created {
				createdCount.Add(1)
			}
		}()
	}
	wait.Wait()
	if failureCount.Load() != 0 || createdCount.Load() != 1 {
		t.Fatalf("failures=%d created=%d", failureCount.Load(), createdCount.Load())
	}
	var count int
	if err := sqlDB.QueryRow(`SELECT count(*) FROM runtime_operations WHERE request_id='duplicate-request'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("row count = %d", count)
	}
	conflict := command
	conflict.TargetID = "gcp-k3s-001"
	if _, _, err := database.Operations().EnqueueCreate(conflict, 4); !errors.Is(err, operations.ErrIdempotencyConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}

func openDatabase(t *testing.T) (*runtimepg.Database, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	database, err := runtimepg.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := sqlDB.Exec(`TRUNCATE runtime_operations, runtime_bindings`); err != nil {
		_ = sqlDB.Close()
		_ = database.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close(); _ = database.Close() })
	return database, sqlDB
}

func createCommand(requestID, instanceID string) provisioner.CreateWorkloadCommand {
	return provisioner.CreateWorkloadCommand{RequestID: requestID, InstanceID: instanceID, TeamID: "00000000-0000-4000-8000-000000000001", RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: "aws-k3s-001", Containers: []provisioner.WorkloadContainer{{Name: "web", Image: "ghcr.io/msg-ctf/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ports: []int{8080}, Expose: true}}, ResourceLimits: provisioner.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128}}
}
