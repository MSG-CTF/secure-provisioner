package windowsruntime_test

import (
	"context"
	"testing"
	"time"

	win "github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
	"github.com/google/uuid"
)

type queueStore interface {
	win.Store
	QueuePosition(context.Context, string) (int, error)
	GetMetadataByRequest(context.Context, string) (win.Record, error)
}

func TestMemoryQueueBindingCannotOvertakeAnEarlierReadyTeam(t *testing.T) {
	testQueueBindingOrder(t, win.NewMemoryStore())
}
func TestPostgresQueueBindingCannotOvertakeAnEarlierReadyTeam(t *testing.T) {
	store, _ := postgresStore(t)
	testQueueBindingOrder(t, store)
}

func testQueueBindingOrder(t *testing.T, store queueStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	a, b := queuedRecord(win.UnboundTargetID), queuedRecord(win.UnboundTargetID)
	a.CreatedAt, b.CreatedAt = now, now.Add(time.Second)
	for _, r := range []*win.Record{&a, &b} {
		r.Checker = &win.CheckerJob{Request: &win.CheckerRequest{TeamID: uuid.NewString(), SelectionMode: "broker_pool"}}
		if _, _, err := store.Submit(ctx, *r); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.Claim(ctx, "worker-a", time.Minute)
	if err != nil || first == nil || first.ID != a.ID {
		t.Fatalf("first claim: %+v %v", first, err)
	}
	second, err := store.Claim(ctx, "worker-b", time.Minute)
	if err != nil || second == nil || second.ID != b.ID {
		t.Fatalf("second claim: %+v %v", second, err)
	}
	if bound, err := store.BindTarget(ctx, b.ID, "worker-b", uuid.NewString()); err != nil || bound {
		t.Fatalf("later team overtook: %v %v", bound, err)
	}
	if bound, err := store.BindTarget(ctx, a.ID, "worker-a", uuid.NewString()); err != nil || !bound {
		t.Fatalf("first binding: %v %v", bound, err)
	}
	if bound, err := store.BindTarget(ctx, b.ID, "worker-b", uuid.NewString()); err != nil || !bound {
		t.Fatalf("second independent VM binding: %v %v", bound, err)
	}
	if position, err := store.QueuePosition(ctx, b.ID); err != nil || position != 0 {
		t.Fatalf("bound team still queued: %d %v", position, err)
	}
}

func TestMemoryTeamQueue(t *testing.T)   { testTeamQueue(t, win.NewMemoryStore()) }
func TestPostgresTeamQueue(t *testing.T) { store, _ := postgresStore(t); testTeamQueue(t, store) }

func testTeamQueue(t *testing.T, store queueStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	teamA, teamB := uuid.NewString(), uuid.NewString()
	add := func(team, backend, phase, target string, offset int) win.Record {
		r := queuedRecord(target)
		r.CreatedAt = now.Add(time.Duration(offset) * time.Second)
		r.Phase = phase
		r.Checker = &win.CheckerJob{BackendID: backend, Request: &win.CheckerRequest{TeamID: team, SelectionMode: "broker_pool"}}
		got, created, err := store.Submit(ctx, r)
		if err != nil || !created {
			t.Fatalf("submit: created=%v err=%v", created, err)
		}
		return got
	}
	a := add(teamA, "internal", "FETCH_PENDING", win.UnboundTargetID, 0)
	metadata, err := store.GetMetadataByRequest(ctx, a.RequestID)
	if err != nil || len(metadata.Payload) != 0 || metadata.ID != a.ID || metadata.Checker.Request.TeamID != teamA {
		t.Fatalf("metadata read loaded payload or lost identity: %+v %v", metadata, err)
	}
	stored, err := store.GetByRequest(ctx, a.RequestID)
	if err != nil || len(stored.Payload) == 0 {
		t.Fatalf("metadata read changed stored payload: %v", err)
	}
	b := add(teamB, "internal", "QUEUED", win.UnboundTargetID, 1)
	duplicate := add(teamA, "internal", "QUEUED", win.UnboundTargetID, 2)
	external := add(teamA, "external", "QUEUED", win.UnboundTargetID, 3)
	bound := add(uuid.NewString(), "internal", "QUEUED", uuid.NewString(), -2)
	finished := add(uuid.NewString(), "internal", "FINISHED", win.UnboundTargetID, -1)
	for _, tc := range []struct {
		id   string
		want int
	}{{a.ID, 1}, {b.ID, 2}, {duplicate.ID, 1}, {external.ID, 3}, {bound.ID, 0}, {finished.ID, 0}, {uuid.NewString(), 0}} {
		got, err := store.QueuePosition(ctx, tc.id)
		if err != nil || got != tc.want {
			t.Fatalf("queue %s: got=%d want=%d err=%v", tc.id, got, tc.want, err)
		}
	}
	// A claimed payload still occupies its queue position until a VM is bound.
	first, err := store.Claim(ctx, "worker", time.Minute)
	if err != nil || first == nil {
		t.Fatalf("claim: %v", err)
	}
	if first.ID == a.ID {
		position, err := store.QueuePosition(ctx, a.ID)
		if err != nil || position != 1 {
			t.Fatalf("leased position=%d err=%v", position, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.QueuePosition(cancelled, b.ID); err == nil {
		t.Fatal("cancelled queue query succeeded")
	}
}

func TestMemoryQueueCounts150TeamsInReceiptOrder(t *testing.T) {
	testQueueCounts150Teams(t, win.NewMemoryStore())
}

func TestPostgresQueueCounts150TeamsAndSurvivesStoreRestart(t *testing.T) {
	store, db := postgresStore(t)
	last := testQueueCounts150Teams(t, store)
	if got, err := win.NewPostgresStore(db).QueuePosition(context.Background(), last); err != nil || got != 150 {
		t.Fatalf("restarted queue position=%d err=%v", got, err)
	}
}

func testQueueCounts150Teams(t *testing.T, store queueStore) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	ids := make([]string, 150)
	for i := range ids {
		r := queuedRecord(win.UnboundTargetID)
		r.CreatedAt = now.Add(time.Duration(i) * time.Millisecond)
		r.Checker = &win.CheckerJob{Request: &win.CheckerRequest{TeamID: uuid.NewString(), SelectionMode: "broker_pool"}}
		if _, _, err := store.Submit(ctx, r); err != nil {
			t.Fatal(err)
		}
		ids[i] = r.ID
	}
	for i, id := range ids {
		if got, err := store.QueuePosition(ctx, id); err != nil || got != i+1 {
			t.Fatalf("team %d: position=%d err=%v", i, got, err)
		}
	}
	return ids[len(ids)-1]
}
