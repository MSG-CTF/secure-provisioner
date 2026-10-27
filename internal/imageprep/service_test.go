package imageprep

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var testImage = "ghcr.io/msg-ctf/challenges/example/web@sha256:" + strings.Repeat("a", 64)
var testImage2 = "ghcr.io/msg-ctf/challenges/example/db@sha256:" + strings.Repeat("b", 64)

type testPolicy struct {
	blocked  bool
	revision string
}

func (p *testPolicy) Revision() string { return p.revision }

func (p *testPolicy) Validate(Request) error {
	if p.blocked {
		return ErrPolicy
	}
	return nil
}
func (p *testPolicy) Approved(string) bool { return !p.blocked }

type testInventory struct {
	nodes   []Node
	enabled bool
}

func (i *testInventory) Known(string) bool                                     { return true }
func (i *testInventory) Enabled(string, string) bool                           { return i.enabled }
func (i *testInventory) Nodes(context.Context, string, string) ([]Node, error) { return i.nodes, nil }

type testRunner struct {
	calls  int
	fail   string
	absent bool
}

func (r *testRunner) Run(_ context.Context, n Node, image string, pull bool) (Evidence, error) {
	r.calls++
	if r.fail != "" {
		return Evidence{}, Failure{Code: r.fail}
	}
	if r.absent {
		return Evidence{}, Failure{Code: "CONTENT_INCOMPLETE"}
	}
	return Evidence{NodeUID: n.UID, BootID: n.BootID, OS: "linux", Architecture: n.Architecture, Image: image, ResolvedDigest: "sha256:" + strings.Repeat("a", 64), Complete: true}, nil
}
func fixture(t *testing.T) (*Service, *MemoryStore, *testInventory, *testPolicy, *testRunner) {
	t.Helper()
	store := NewMemoryStore()
	inv := &testInventory{enabled: true, nodes: []Node{{TargetID: "target-a", UID: "uid-1", Name: "node-1", BootID: "boot-1", Architecture: "AMD64"}, {TargetID: "target-a", UID: "uid-2", Name: "node-2", BootID: "boot-2", Architecture: "AMD64"}}}
	policy := &testPolicy{}
	runner := &testRunner{}
	svc := NewService(store, inv, policy, runner, Config{TTL: time.Minute, ObserveInterval: 30 * time.Second, MaxAttempts: 3, Concurrency: 2})
	return svc, store, inv, policy, runner
}
func testRequest() Request {
	return Request{RequestID: "request-a", Architecture: "AMD64", IsolationProfile: "WEB", Containers: []Container{{Name: "web", Image: testImage, Ports: []int{80}}}, TargetIDs: []string{"target-a"}}
}
func drain(t *testing.T, s *Service) {
	t.Helper()
	for range 20 {
		worked, err := s.Step(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			return
		}
	}
	t.Fatal("worker failed to settle")
}
func TestCanonicalIdentityAndReplayBeforePolicy(t *testing.T) {
	s, _, _, p, _ := fixture(t)
	req := testRequest()
	op, err := s.Create(context.Background(), "backend", req)
	if err != nil {
		t.Fatal(err)
	}
	p.blocked = true
	again, err := s.Create(context.Background(), "backend", req)
	if err != nil || again.ID != op.ID {
		t.Fatalf("replay=%+v %v", again, err)
	}
	req.ReleaseID = "11111111-1111-4111-8111-111111111111"
	if _, err = s.Create(context.Background(), "backend", req); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict=%v", err)
	}
	a := ImageSetID("AMD64", []string{testImage, testImage2})
	b := ImageSetID("AMD64", []string{testImage2, testImage})
	if a != b || a == ImageSetID("ARM64", []string{testImage, testImage2}) {
		t.Fatal("canonical identity")
	}
}
func TestHistoricalSuccessReadinessExpiryAndInvalidation(t *testing.T) {
	s, _, inv, policy, runner := fixture(t)
	ctx := context.Background()
	op, err := s.Create(ctx, "backend", testRequest())
	if err != nil {
		t.Fatal(err)
	}
	drain(t, s)
	got, _ := s.Get(ctx, "backend", op.ID)
	if got.Status != "SUCCEEDED" || len(got.Nodes) != 2 {
		t.Fatalf("operation=%+v", got)
	}
	if err := s.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	q := Query{Architecture: "AMD64", Images: []string{testImage}, TargetIDs: []string{"target-a"}}
	first, _ := s.Query(ctx, q)
	if !first.Targets[0].Ready || first.Targets[0].ReadyNodeCount != 2 {
		t.Fatalf("readiness=%+v", first)
	}
	again, _ := s.Query(ctx, q)
	if !again.Targets[0].ObservedAt.Equal(*first.Targets[0].ObservedAt) {
		t.Fatal("read extended observation")
	}
	policy.blocked = true
	blocked, _ := s.Query(ctx, q)
	if blocked.Targets[0].Ready {
		t.Fatal("policy bypass")
	}
	policy.blocked = false
	inv.nodes[0].BootID = "replacement"
	runner.absent = true
	if err := s.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	empty, _ := s.Query(ctx, q)
	if empty.Targets[0].Ready {
		t.Fatal("deleted cache was reused")
	}
	got, _ = s.Get(ctx, "backend", op.ID)
	if got.Status != "SUCCEEDED" {
		t.Fatal("history was mutated")
	}
	s.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	expired, _ := s.Query(ctx, q)
	if expired.Targets[0].Ready {
		t.Fatal("expired hint")
	}
}
func TestRetryChildAndRestartBoundedPermanentFailure(t *testing.T) {
	s, store, inv, p, r := fixture(t)
	ctx := context.Background()
	r.fail = "REGISTRY_UNAUTHORIZED"
	op, err := s.Create(ctx, "backend", testRequest())
	if err != nil {
		t.Fatal(err)
	}
	drain(t, s)
	got, _ := s.Get(ctx, "backend", op.ID)
	if got.Status != "FAILED" || r.calls != 2 {
		t.Fatalf("permanent failure retried: %+v calls=%d", got, r.calls)
	}
	restarted := NewService(store, inv, p, r, s.Config)
	r.fail = ""
	retry := Retry{RequestID: "retry-a", NodeUIDs: []string{"uid-1"}}
	child, err := restarted.Retry(ctx, "backend", op.ID, retry)
	if err != nil || child.ParentID != op.ID {
		t.Fatalf("child=%+v %v", child, err)
	}
	drain(t, restarted)
	p.blocked = true
	replayed, err := restarted.Retry(ctx, "backend", op.ID, retry)
	if err != nil || replayed.ID != child.ID {
		t.Fatalf("retry replay=%+v %v", replayed, err)
	}
	if _, err := restarted.Get(ctx, "other", op.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("principal scope leaked")
	}
}
