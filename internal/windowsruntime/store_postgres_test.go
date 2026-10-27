package windowsruntime_test

import (
	"context"
	"database/sql"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	win "github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Each integration test gets a fresh schema on the explicitly supplied test DB.
// No production connection settings are consulted or modified.
func postgresStore(t *testing.T) (*win.PostgresStore, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("PROVISIONER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PROVISIONER_TEST_DATABASE_URL is not set")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*config)
	schema := "windows_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(context.Background(), `CREATE SCHEMA "`+schema+`"`); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(20)
	t.Cleanup(func() {
		_ = db.Close()
		_, err := admin.ExecContext(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`)
		if err != nil {
			t.Error(err)
		}
		_ = admin.Close()
	})
	for _, path := range []string{
		"../runtimepg/migrations/008_windows_executions.sql",
		"../runtimepg/migrations/009_windows_checker_phase.sql",
	} {
		migration, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(context.Background(), string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	store := win.NewPostgresStore(db)
	if err := store.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store, db
}

func TestPostgresStoreIdempotencyAndCopies(t *testing.T) {
	store, _ := postgresStore(t)
	testStoreIdempotencyAndCopies(t, store)
}

func TestPostgresStoreClaimsCheckerFetchAndRejectedCallback(t *testing.T) {
	store, _ := postgresStore(t)
	ctx := context.Background()
	record := queuedRecord(targetID)
	record.Phase = "FETCH_PENDING"
	record.Payload = nil
	record.Checker = &win.CheckerJob{ResultPending: false}
	if _, _, err := store.Submit(ctx, record); err != nil {
		t.Fatalf("checker metadata could not be queued: %v", err)
	}
	claimed, err := store.Claim(ctx, "worker-a", time.Minute)
	if err != nil || claimed == nil || claimed.ID != record.ID {
		t.Fatalf("FETCH_PENDING was not claimed: %+v %v", claimed, err)
	}
	claimed.Phase = "REJECTED"
	claimed.Checker.ResultPending = true
	claimed.Owner = ""
	if err := store.Save(ctx, *claimed, "worker-a"); err != nil {
		t.Fatal(err)
	}
	retry, err := store.Claim(ctx, "worker-b", time.Minute)
	if err != nil || retry == nil || retry.ID != record.ID || retry.Phase != "REJECTED" || !retry.Checker.ResultPending {
		t.Fatalf("rejected callback was not reclaimed: %+v %v", retry, err)
	}
}

func TestPostgresStoreSerializesClaimsPerVM(t *testing.T) {
	store, _ := postgresStore(t)
	testStoreSerializesClaimsPerVM(t, store)
}
func TestPostgresStoreBindsOnlyOneUnboundJobPerVM(t *testing.T) {
	store, _ := postgresStore(t)
	testStoreBindsOnlyOneUnboundJobPerVM(t, store)
}
func TestPostgresStoreFencesLeaseAndPersistsOutbox(t *testing.T) {
	store, _ := postgresStore(t)
	testStoreFencesLeaseAndPersistsOutbox(t, store)
}
func TestPostgresStoreSavePreservesRenewedLease(t *testing.T) {
	store, _ := postgresStore(t)
	testStoreSavePreservesRenewedLease(t, store)
}
func TestPostgresStoreSkipsBlockedRejectedNotDueAndFinished(t *testing.T) {
	store, _ := postgresStore(t)
	testStoreSkipsIneligible(t, store)
}

func TestPostgresStoreRestartRetainsAllExecutionMetadata(t *testing.T) {
	store, db := postgresStore(t)
	ctx := context.Background()
	submitted := queuedRecord(targetID)
	if _, _, err := store.Submit(ctx, submitted); err != nil {
		t.Fatal(err)
	}
	record, err := store.Claim(ctx, "worker", time.Minute)
	if err != nil || record == nil {
		t.Fatalf("claim = %#v, %v", record, err)
	}
	exit := int64(4294967295)
	record.Phase = "FINISHED"
	record.Outcome = &win.Outcome{Result: "failed", ExitCode: &exit, Stdout: "output", Stderr: "error", StdoutTruncated: true, StderrTruncated: true, ErrorCode: "PAYLOAD_FAILED"}
	record.StartedBody = []byte(`{"execution_id":"exact-bytes","event":"started"}`)
	record.FinishedBody = []byte(`{ "execution_id":"exact-bytes", "event":"finished", "result":"failed", "exit_code":4294967295 }`)
	connection := validConnection()
	record.Connection = &connection
	record.StartUncertain = true
	record.ErrorCode = "BROKER_RETRY"
	record.BrokerPending = true
	record.NextAttempt = time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	record.Owner = ""
	record.LeaseUntil = time.Time{}
	if err := store.Save(ctx, *record, "worker"); err != nil {
		t.Fatal(err)
	}
	restarted := win.NewPostgresStore(db)
	got, err := restarted.Get(ctx, record.ID)
	if err != nil || !reflect.DeepEqual(got, *record) {
		t.Fatalf("restart record mismatch\ngot=%#v\nwant=%#v\nerr=%v", got, *record, err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE runtime_windows_executions RENAME COLUMN finished_pending TO missing_finished_pending"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Check(ctx); err == nil {
		t.Fatal("incompatible execution schema was ready")
	}
}
