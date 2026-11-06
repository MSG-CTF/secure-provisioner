package imageprep

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReadyNodesRejectsChangedCurrentIdentity(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*Node)
	}{
		{"uid", func(n *Node) { n.UID = "replacement" }},
		{"boot", func(n *Node) { n.BootID = "rebooted" }},
		{"machine", func(n *Node) { n.MachineID = "replaced-machine" }},
		{"name", func(n *Node) { n.Name = "renamed" }},
		{"platform", func(n *Node) { n.Architecture = "ARM64" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			s, _, inventory, _, _ := fixture(t)
			ctx := context.Background()
			if _, err := s.Create(ctx, "backend", testRequest()); err != nil {
				t.Fatal(err)
			}
			drain(t, s)
			if err := s.Observe(ctx); err != nil {
				t.Fatal(err)
			}
			change.edit(&inventory.nodes[0])
			got := s.ReadyNodes(ctx, "target-a", "AMD64", []string{testImage})
			if len(got) != 1 || got[0] != "node-2" {
				t.Fatalf("old node identity was trusted: %+v", got)
			}
		})
	}
}

func TestReadyNodesRejectsUnavailableInventoryAndExpiredEvidence(t *testing.T) {
	s, _, inventory, _, _ := fixture(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, "backend", testRequest()); err != nil {
		t.Fatal(err)
	}
	drain(t, s)
	if err := s.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	images := []string{testImage}
	if got := s.ReadyNodes(ctx, "target-a", "AMD64", images); len(got) != 2 {
		t.Fatalf("ready nodes = %+v", got)
	}
	inventory.err = errors.New("inventory unavailable")
	if got := s.ReadyNodes(ctx, "target-a", "AMD64", images); len(got) != 0 {
		t.Fatalf("unverified inventory accepted: %+v", got)
	}
	inventory.err = nil
	inventory.nodes = inventory.nodes[1:]
	if got := s.ReadyNodes(ctx, "target-a", "AMD64", images); len(got) != 1 || got[0] != "node-2" {
		t.Fatalf("removed node accepted: %+v", got)
	}
	s.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if got := s.ReadyNodes(ctx, "target-a", "AMD64", images); len(got) != 0 {
		t.Fatalf("expired evidence accepted: %+v", got)
	}
}
