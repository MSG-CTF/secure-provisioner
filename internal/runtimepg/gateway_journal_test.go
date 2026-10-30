package runtimepg

import (
	"context"
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/gateway"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"testing"
	"time"
)

func TestGatewayJournalFencesTransportAndOwnerContract(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	for index, transport := range []gateway.PublicTransport{gateway.TransportLegacy, gateway.TransportPlain} {
		id := "contract-" + time.Now().Format("150405.000000000")
		r := gateway.Record{Command: provisioner.CreateWorkloadCommand{InstanceID: id, TargetID: "test-target", TeamID: "00000000-0000-4000-8000-000000000002"}, Result: provisioner.CreateWorkloadResult{NamespaceUID: "ns-contract"}, Destination: gateway.Destination{TargetIP: "8.8.8.8", TargetPort: 31991 + index, Protocol: "tcp", PublicTransport: transport}, ServiceUID: "svc-contract", Phase: gateway.PhaseApplyPending, CreatedAt: time.Now().UTC()}
		if transport != gateway.TransportLegacy {
			r.Destination.OwnerTeamID = string(r.Command.TeamID)
		}
		t.Cleanup(func() {
			_, _ = db.db.ExecContext(context.Background(), "DELETE FROM runtime_gateway_routes WHERE instance_id=$1", id)
		})
		if err := db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error { return s.Save(r) }); err != nil {
			t.Fatal(err)
		}
		for _, alter := range []func(*gateway.Record){
			func(v *gateway.Record) { v.Destination.PublicTransport = gateway.TransportTLS },
			func(v *gateway.Record) { v.Destination.OwnerTeamID = "00000000-0000-4000-8000-000000000003" },
		} {
			changed := r
			alter(&changed)
			err := db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error { return s.Save(changed) })
			if !errors.Is(err, gateway.ErrConflict) {
				t.Fatalf("contract rewrite accepted: before=%+v after=%+v err=%v", r.Destination, changed.Destination, err)
			}
		}
		r.Phase = gateway.PhaseConflictHold
		if err := db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error { return s.Save(r) }); err != nil {
			t.Fatal(err)
		}
		saved, err := db.GatewayJournal().Get(ctx, id)
		if err != nil || saved.Destination != r.Destination || saved.Phase != gateway.PhaseConflictHold {
			t.Fatalf("contract did not survive phase update/readback: %+v %v", saved, err)
		}
	}
}

func TestGatewayJournalCommitsIntentDespiteInterruptedCallbackAndFencesTuple(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	id := "gateway-" + time.Now().Format("150405.000000000")
	r := gateway.Record{Command: provisioner.CreateWorkloadCommand{InstanceID: id, TargetID: "test-target"}, Result: provisioner.CreateWorkloadResult{NamespaceUID: "ns1", RuntimeWorkloadID: "test/ns/instance"}, Destination: gateway.Destination{TargetIP: "8.8.8.8", TargetPort: 31042, Protocol: "http"}, ServiceUID: "svc1", Phase: gateway.PhaseApplyPending, CreatedAt: time.Now().UTC()}
	r.Command.ReleaseID = "11111111-1111-4111-8111-111111111111"
	r.Command.Architecture = "AMD64"
	interrupted := errors.New("interrupted after intent commit")
	err := db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error {
		if err := s.Save(r); err != nil {
			return err
		}
		return interrupted
	})
	if !errors.Is(err, interrupted) {
		t.Fatal(err)
	}
	saved, err := db.GatewayJournal().Get(ctx, id)
	if err != nil || saved.Destination != r.Destination {
		t.Fatal(saved, err)
	}
	if saved.Command.ReleaseID != r.Command.ReleaseID || saved.Command.Architecture != r.Command.Architecture {
		t.Fatal("Gateway durable recovery lost release metadata")
	}
	err = db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error { r.Destination.TargetPort++; return s.Save(r) })
	if !errors.Is(err, gateway.ErrConflict) {
		t.Fatal("tuple changed", err)
	}
	// An unrelated test must not retain a live port claim.
	err = db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error {
		v, e := s.Load()
		if e != nil {
			return e
		}
		for _, phase := range []gateway.Phase{gateway.PhaseDeletePending, gateway.PhaseRouteDeleted, gateway.PhaseDeleted} {
			v.Phase = phase
			if err := s.Save(v); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGatewayJournalLocksAcrossConnectionsAndHonorsCancellation(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	id := "gateway-lock-" + time.Now().Format("150405.000000000")
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- db.GatewayJournal().WithLock(ctx, id, func(gateway.Session) error { close(entered); <-release; return nil })
	}()
	<-entered
	deadline, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if err := db.GatewayJournal().WithLock(deadline, id, func(gateway.Session) error { t.Error("lock acquired concurrently"); return nil }); err == nil {
		t.Error("missing cancellation")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := db.GatewayJournal().WithLock(ctx, id, func(gateway.Session) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayLocksDoNotExhaustOperationAndLeasePool(t *testing.T) {
	db := openTestDatabase(t)
	db.db.SetMaxOpenConns(1)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- db.GatewayJournal().WithLock(context.Background(), "pool-budget-test", func(gateway.Session) error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var value int
	err := db.db.QueryRowContext(ctx, "SELECT 42").Scan(&value)
	close(release)
	if lockErr := <-done; lockErr != nil {
		t.Fatal(lockErr)
	}
	if err != nil || value != 42 {
		t.Fatalf("operation/lease pool starved: %d %v", value, err)
	}
}

func TestGatewayLifecycleBudgetDefersWithoutHoldingAnotherWorker(t *testing.T) {
	db := openTestDatabase(t)
	for i := 0; i < gatewayLockConnections; i++ {
		db.gatewayLockBudget <- struct{}{}
	}
	start := time.Now()
	err := db.GatewayJournal().WithLock(context.Background(), "budget-full", func(gateway.Session) error { t.Error("exhausted lifecycle budget entered callback"); return nil })
	if err == nil || time.Since(start) > 100*time.Millisecond {
		t.Fatal("budget waited instead of deferring", err)
	}
}

func TestGatewayConflictPhaseCannotPromoteBackToCreate(t *testing.T) {
	db := openTestDatabase(t)
	id := "conflict-phase-" + time.Now().Format("150405.000000000")
	r := gateway.Record{Command: provisioner.CreateWorkloadCommand{InstanceID: id, TargetID: "test-target"}, Result: provisioner.CreateWorkloadResult{NamespaceUID: "ns-conflict"}, Destination: gateway.Destination{TargetIP: "8.8.8.8", TargetPort: 31220, Protocol: "tcp"}, ServiceUID: "svc-conflict", Phase: gateway.PhaseApplyPending, CreatedAt: time.Now().UTC()}
	err := db.GatewayJournal().WithLock(context.Background(), id, func(s gateway.Session) error {
		if err := s.Save(r); err != nil {
			return err
		}
		r.Phase = gateway.PhaseConflictHold
		if err := s.Save(r); err != nil {
			return err
		}
		r.Phase = gateway.PhaseApplied
		if err := s.Save(r); !errors.Is(err, gateway.ErrConflict) {
			t.Fatalf("conflict resumed CREATE: %v", err)
		}
		for _, phase := range []gateway.Phase{gateway.PhaseDeletePending, gateway.PhaseRouteDeleted, gateway.PhaseDeleted} {
			r.Phase = phase
			if err := s.Save(r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
