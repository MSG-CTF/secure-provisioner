package imageprep

import (
	"context"
	"sync"
	"testing"
	"time"
)

type observationQueries struct {
	Store
	queries []Query
}

func (s observationQueries) Watch(context.Context) ([]Query, error) { return s.queries, nil }

type blockedTargets struct {
	Inventory
	entered chan string
	release chan struct{}
	mu      sync.Mutex
	active  map[string]bool
	overlap bool
}

func (i *blockedTargets) Nodes(ctx context.Context, target, arch string) ([]Node, error) {
	i.mu.Lock()
	if i.active[target] {
		i.overlap = true
	}
	i.active[target] = true
	i.mu.Unlock()
	defer func() { i.mu.Lock(); delete(i.active, target); i.mu.Unlock() }()
	select {
	case i.entered <- target:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-i.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []Node{{TargetID: target, UID: target, Name: target, BootID: "boot-1", Architecture: arch}}, nil
}
func TestObservationBoundsIndependentTargetsAndSerializesEachTarget(t *testing.T) {
	s, store, inv, _, _ := fixture(t)
	s.Config.Concurrency = 2
	queries := []Query{
		{Architecture: "AMD64", Images: []string{testImage}, TargetIDs: []string{"target-a", "target-b", "target-c"}},
		{Architecture: "AMD64", Images: []string{testImage2}, TargetIDs: []string{"target-a"}},
	}
	s.Store = observationQueries{Store: store, queries: queries}
	inventory := &blockedTargets{Inventory: inv, entered: make(chan string, 8), release: make(chan struct{}), active: map[string]bool{}}
	s.Inventory = inventory
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Observe(ctx) }()
	first := <-inventory.entered
	select {
	case second := <-inventory.entered:
		if second == first {
			t.Fatal("same target observations overlapped")
		}
	case <-ctx.Done():
		t.Fatal("one stalled target blocked another target")
	}
	select {
	case <-inventory.entered:
		t.Fatal("observer exceeded configured concurrency")
	case <-time.After(30 * time.Millisecond):
	}
	close(inventory.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	inventory.mu.Lock()
	overlap := inventory.overlap
	inventory.mu.Unlock()
	if overlap {
		t.Fatal("same target was observed concurrently")
	}
	for _, q := range queries {
		for _, target := range q.TargetIDs {
			observation, found, err := store.Observation(ctx, target, ImageSetID(q.Architecture, q.Images))
			if err != nil || !found || !observation.Complete || len(observation.Nodes) != 1 || !validEvidence(observation.Nodes[0].Node, q.Images[0], observation.Nodes[0].Images[q.Images[0]]) {
				t.Fatalf("missing current evidence for %s", target)
			}
		}
	}
}

type disabledObservationInventory struct{ Inventory }

func (disabledObservationInventory) Enabled(string, string) bool { return false }
func (disabledObservationInventory) Nodes(context.Context, string, string) ([]Node, error) {
	panic("disabled target contacted")
}
func TestObservationDoesNotContactWithdrawnTargets(t *testing.T) {
	s, store, inv, _, _ := fixture(t)
	ctx := context.Background()
	_, err := s.Create(ctx, "backend", testRequest())
	if err != nil {
		t.Fatal(err)
	}
	s.Inventory = disabledObservationInventory{inv}
	if err := s.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	observation, found, err := store.Observation(ctx, "target-a", ImageSetID("AMD64", []string{testImage}))
	if err != nil || !found || observation.Complete {
		t.Fatal("withdrawn target received ready evidence")
	}
}
