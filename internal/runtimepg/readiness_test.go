package runtimepg

import (
	"context"
	"testing"
	"time"
)

func TestReadinessChecksLiveSchemaWithoutMutatingEmptyStores(t *testing.T) {
	database := openTestDatabase(t)
	if err := database.CheckReadiness(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.db.QueryRow("SELECT (SELECT count(*) FROM runtime_operations) + (SELECT count(*) FROM runtime_bindings)").Scan(&count); err != nil || count != 0 {
		t.Fatalf("readiness changed stores: count=%d, err=%v", count, err)
	}
	// A live connection alone is insufficient when a required store column is missing.
	if _, err := database.db.Exec("ALTER TABLE runtime_bindings RENAME COLUMN policy_snapshot TO readiness_hidden_column"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := database.db.Exec("ALTER TABLE runtime_bindings RENAME COLUMN readiness_hidden_column TO policy_snapshot"); err != nil {
			t.Error(err)
		}
	})
	if err := database.CheckReadiness(context.Background()); err == nil {
		t.Fatal("incompatible binding schema was marked ready")
	}
}

func TestReadinessBoundsLockedStoreAndRecoversAfterUnlock(t *testing.T) {
	database := openTestDatabase(t)
	tx, err := database.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("LOCK TABLE runtime_operations IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := database.CheckReadiness(ctx); err == nil || time.Since(started) > time.Second {
		t.Fatalf("locked store did not honor deadline: err=%v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := database.CheckReadiness(context.Background()); err != nil {
		t.Fatalf("readiness failed after unlock: %v", err)
	}
	_ = database.Close()
	if err := database.CheckReadiness(context.Background()); err == nil {
		t.Fatal("closed database was marked ready")
	}
}
