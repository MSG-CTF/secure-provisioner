package imageprep

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type onceFailedInventory struct {
	Inventory
	calls atomic.Int32
}

func (i *onceFailedInventory) Nodes(ctx context.Context, target, arch string) ([]Node, error) {
	if i.calls.Add(1) == 1 {
		return nil, Failure{Code: "NETWORK_TIMEOUT"}
	}
	return i.Inventory.Nodes(ctx, target, arch)
}
func TestPreparationInventoryRecoversThenRealReplacementRemainsPermanent(t *testing.T) {
	s, _, inv, _, runner := fixture(t)
	ctx := context.Background()
	op, err := s.Create(ctx, "backend", testRequest())
	if err != nil {
		t.Fatal(err)
	}
	s.Inventory = &onceFailedInventory{Inventory: inv}
	now := time.Now().UTC()
	s.Now = func() time.Time { return now }
	for range 8 {
		_, err := s.Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	got, _ := s.Get(ctx, "backend", op.ID)
	if got.Status != "SUCCEEDED" || runner.calls != 2 || got.Nodes[0].Images[0].Attempts != 2 {
		t.Fatalf("temporary inventory did not recover: %+v", got)
	}
	req := testRequest()
	req.RequestID = "replacement"
	op, err = s.Create(ctx, "backend", req)
	if err != nil {
		t.Fatal(err)
	}
	inv.nodes[0].UID = "replacement-uid"
	drain(t, s)
	got, _ = s.Get(ctx, "backend", op.ID)
	if got.Status != "PARTIAL" || got.Nodes[0].Images[0].ErrorCode != "NODE_IDENTITY_MISMATCH" || got.Nodes[0].Images[0].Attempts != 1 {
		t.Fatalf("actual replacement retried or accepted: %+v", got)
	}
}

type stalledInventory struct{ Inventory }

func (i stalledInventory) Nodes(ctx context.Context, target, arch string) ([]Node, error) {
	if target == "target-a" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	nodes, err := i.Inventory.Nodes(ctx, target, arch)
	copy := append([]Node(nil), nodes...)
	for n := range copy {
		copy[n].TargetID = target
	}
	return copy, err
}
func TestObserverCancelsStalledTargetAndContinuesOtherTargets(t *testing.T) {
	s, store, inv, _, _ := fixture(t)
	ctx := context.Background()
	req := testRequest()
	_, err := s.Create(ctx, "backend", req)
	if err != nil {
		t.Fatal(err)
	}
	req.RequestID = "other-target"
	req.TargetIDs = []string{"target-b"}
	_, err = s.Create(ctx, "backend", req)
	if err != nil {
		t.Fatal(err)
	}
	s.Inventory = stalledInventory{Inventory: inv}
	bounded, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	started := time.Now()
	if err := s.Observe(bounded); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 6500*time.Millisecond {
		t.Fatal("stalled inventory exceeded bounded observation")
	}
	bad, _, _ := store.Observation(ctx, "target-a", ImageSetID(req.Architecture, req.Images()))
	good, _, _ := store.Observation(ctx, "target-b", ImageSetID(req.Architecture, req.Images()))
	if bad.Complete || !good.Complete || len(good.Nodes) != 2 {
		t.Fatal("one stalled target blocked or falsified other target observation")
	}
}

type deadlineInventory struct {
	Inventory
	unbounded bool
}

func (i *deadlineInventory) Nodes(ctx context.Context, target, arch string) ([]Node, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 6*time.Second {
		i.unbounded = true
		return nil, errors.New("unbounded inventory")
	}
	return i.Inventory.Nodes(ctx, target, arch)
}

type deadlineStore struct{ Store }

func (s deadlineStore) Claim(ctx context.Context, now time.Time, d time.Duration) (Record, bool, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) >= d {
		return Record{}, false, errors.New("claim has no deadline before lease expiry")
	}
	return s.Store.Claim(ctx, now, d)
}
func TestPreparationStepAndInventoryDeadlinesPrecedeLeaseExpiry(t *testing.T) {
	s, store, inv, _, _ := fixture(t)
	ctx := context.Background()
	op, err := s.Create(ctx, "backend", testRequest())
	if err != nil {
		t.Fatal(err)
	}
	bounded := &deadlineInventory{Inventory: inv}
	s.Inventory = bounded
	s.Store = deadlineStore{Store: store}
	drain(t, s)
	got, _ := s.Get(ctx, "backend", op.ID)
	if bounded.unbounded || got.Status != "SUCCEEDED" {
		t.Fatal("inventory call was not bounded")
	}
	if err := s.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	if bounded.unbounded {
		t.Fatal("observer inventory was not bounded")
	}
}

type failedInventory struct {
	Inventory
	code string
}

func (i failedInventory) Nodes(context.Context, string, string) ([]Node, error) {
	return nil, Failure{Code: i.code}
}
func TestPreparationInventoryTimeoutIsBoundedTransientNotIdentityMismatch(t *testing.T) {
	for _, code := range []string{"NETWORK_TIMEOUT", "REGISTRY_UNAVAILABLE"} {
		t.Run(code, func(t *testing.T) {
			s, _, inv, _, runner := fixture(t)
			ctx := context.Background()
			op, err := s.Create(ctx, "backend", testRequest())
			if err != nil {
				t.Fatal(err)
			}
			s.Inventory = failedInventory{Inventory: inv, code: code}
			now := time.Now().UTC()
			s.Now = func() time.Time { return now }
			for range 20 {
				if _, err := s.Step(ctx); err != nil {
					t.Fatal(err)
				}
				now = now.Add(time.Minute)
			}
			got, _ := s.Get(ctx, "backend", op.ID)
			if got.Status != "FAILED" || runner.calls != 0 {
				t.Fatalf("timeout handling=%+v", got)
			}
			for _, n := range got.Nodes {
				if n.Images[0].Attempts != 3 || n.Images[0].ErrorCode != code {
					t.Fatalf("timeout became identity mismatch or unbounded retry: %+v", n.Images[0])
				}
			}
		})
	}
}
