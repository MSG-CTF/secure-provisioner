package runtimepg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/gateway"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func TestGatewayLifecycleSaturationRetainsNormalRetryClassification(t *testing.T) {
	// No database is needed: admission must defer before touching a connection.
	journal := &GatewayJournal{budget: make(chan struct{}, gatewayLockConnections)}
	for range gatewayLockConnections {
		journal.budget <- struct{}{}
	}
	err := journal.WithLock(context.Background(), "budget-full", func(gateway.Session) error {
		t.Fatal("saturated admission entered a mutation callback")
		return nil
	})
	var pending *operations.ProgressPendingError
	code, retryable := operations.ClassifyExecutionError(err)
	if !errors.As(err, &pending) || code != "GATEWAY_LIFECYCLE_BUSY" || !retryable || !pending.HoldRetry() {
		t.Fatalf("normal admission contention inherited fault backoff: code=%s retryable=%v error=%v", code, retryable, err)
	}
	if len(journal.budget) != gatewayLockConnections {
		t.Fatal("deferral changed another worker's admission token")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := journal.WithLock(ctx, "cancelled", func(gateway.Session) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled admission became normal progress: %v", err)
	}
}

func TestGatewayLifecycleContentionWithRealLockPool(t *testing.T) {
	database := openTestDatabase(t)
	journal := database.GatewayJournal()
	entered := make(chan struct{}, gatewayLockConnections)
	release := make(chan struct{})
	done := make(chan error, gatewayLockConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer func() {
		close(release)
		for range gatewayLockConnections {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}()
	for i := range gatewayLockConnections {
		go func() {
			done <- journal.WithLock(ctx, string(rune('a'+i)), func(gateway.Session) error {
				entered <- struct{}{}
				<-release
				return nil
			})
		}()
	}
	for range gatewayLockConnections {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("healthy lock holders did not enter before the test deadline")
		}
	}
	for range 4 {
		err := database.GatewayJournal().WithLock(ctx, "overflow", func(gateway.Session) error {
			t.Error("a ninth concurrent lifecycle callback entered")
			return nil
		})
		var pending *operations.ProgressPendingError
		if !errors.As(err, &pending) {
			t.Fatalf("admission contention lost its progress marker: %v", err)
		}
	}
	var value int
	if err := database.db.QueryRowContext(ctx, "SELECT 42").Scan(&value); err != nil || value != 42 {
		t.Fatalf("gateway admission starved the operation pool: value=%d error=%v", value, err)
	}
}

func TestGatewayLifecycleClosedDatabaseRemainsAFault(t *testing.T) {
	database := openTestDatabase(t)
	if err := database.gatewayLocks.Close(); err != nil {
		t.Fatal(err)
	}
	err := database.GatewayJournal().WithLock(context.Background(), "closed", func(gateway.Session) error {
		t.Error("failed lock pool entered a mutation callback")
		return nil
	})
	var pending *operations.ProgressPendingError
	if err == nil || errors.As(err, &pending) || len(database.gatewayLockBudget) != 0 {
		t.Fatalf("database failure became normal progress or leaked admission: %v", err)
	}
}
