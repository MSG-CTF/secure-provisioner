package imageprep

import (
	"context"
	"testing"
	"time"
)

func TestReadinessSameNodeIntersectionFutureAndPartialInventory(t *testing.T) {
	s, store, inv, _, _ := fixture(t)
	now := time.Now().UTC()
	s.Now = func() time.Time { return now }
	q := Query{Architecture: "AMD64", Images: []string{testImage, testImage2}, TargetIDs: []string{"target-a"}}
	e := func(n Node, ref string) Evidence {
		return Evidence{NodeUID: n.UID, BootID: n.BootID, OS: "linux", Architecture: n.Architecture, Image: ref, ResolvedDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Complete: true}
	}
	obs := Observation{TargetID: "target-a", ImageSetID: ImageSetID(q.Architecture, q.Images), Architecture: q.Architecture, Images: q.Images, ObservedAt: now, ValidUntil: now.Add(time.Minute), Complete: true, Nodes: []NodeObservation{{Node: inv.nodes[0], Images: map[string]Evidence{testImage: e(inv.nodes[0], testImage)}}, {Node: inv.nodes[1], Images: map[string]Evidence{testImage2: e(inv.nodes[1], testImage2)}}}}
	_ = store.PutObservation(context.Background(), obs)
	got, _ := s.Query(context.Background(), q)
	if got.Targets[0].Ready || got.Targets[0].ReadyNodeCount != 0 || got.Targets[0].EligibleNodeCount != 2 {
		t.Fatal("cross-node union counted")
	}
	obs.Nodes[0].Images[testImage2] = e(inv.nodes[0], testImage2)
	_ = store.PutObservation(context.Background(), obs)
	got, _ = s.Query(context.Background(), q)
	if !got.Targets[0].Ready || got.Targets[0].ReadyNodeCount != 1 {
		t.Fatal("intersection missing")
	}
	obs.ObservedAt = now.Add(time.Hour)
	obs.ValidUntil = now.Add(2 * time.Hour)
	_ = store.PutObservation(context.Background(), obs)
	got, _ = s.Query(context.Background(), q)
	if got.Targets[0].Ready {
		t.Fatal("future observation accepted")
	}
	obs.Complete = false
	_ = store.PutObservation(context.Background(), obs)
	got, _ = s.Query(context.Background(), q)
	if got.Targets[0].Ready || got.Targets[0].EligibleNodeCount != 0 {
		t.Fatal("partial inventory counted")
	}
}
func TestPreparationTransientRetriesBoundedAndIdentityMismatchFails(t *testing.T) {
	s, _, _, _, r := fixture(t)
	ctx := context.Background()
	r.fail = "NETWORK_TIMEOUT"
	op, err := s.Create(ctx, "backend", testRequest())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s.Now = func() time.Time { return now }
	for range 20 {
		_, err := s.Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	got, _ := s.Get(ctx, "backend", op.ID)
	if got.Status != "FAILED" || r.calls != 6 {
		t.Fatalf("unbounded retries calls=%d status=%s", r.calls, got.Status)
	}
}
func TestReadinessPolicyRevisionInvalidatesPersistedObservation(t *testing.T) {
	s, _, _, p, _ := fixture(t)
	ctx := context.Background()
	_, _ = s.Create(ctx, "backend", testRequest())
	drain(t, s)
	_ = s.Observe(ctx)
	q := Query{Architecture: "AMD64", Images: []string{testImage}, TargetIDs: []string{"target-a"}}
	p.revision = "new-policy"
	got, _ := s.Query(ctx, q)
	if got.Targets[0].Ready {
		t.Fatal("policy replacement reused positive hint")
	}
}
