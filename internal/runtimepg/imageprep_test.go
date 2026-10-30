package runtimepg

import (
	"context"
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	"testing"
	"time"
)

func TestImagePreparationPersistenceReplayRestartAndLeaseFence(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	_, err := db.db.ExecContext(ctx, "TRUNCATE image_preparation_operations, image_preparation_observations, image_preparation_node_locks")
	if err != nil {
		t.Fatal(err)
	}
	s := db.ImagePreparations()
	r := imageprep.Record{Scope: "backend", Endpoint: "create", Fingerprint: "hash", Operation: imageprep.Operation{ID: "op-a", RequestID: "request-a", Status: "QUEUED"}, Next: time.Now().Add(-time.Second)}
	if _, err := s.Insert(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Operation.ID = "op-b"
	old, err := s.Insert(ctx, r)
	if err != nil || old.Operation.ID != "op-a" {
		t.Fatalf("replay=%+v %v", old, err)
	}
	r.Fingerprint = "changed"
	if _, err := s.Insert(ctx, r); !errors.Is(err, imageprep.ErrConflict) {
		t.Fatal(err)
	}
	first, ok, err := s.Claim(ctx, time.Now(), time.Second)
	if err != nil || !ok {
		t.Fatalf("claim %v %v", ok, err)
	}
	restarted := &ImagePreparationStore{db: db.db}
	second, ok, err := restarted.Claim(ctx, time.Now().Add(2*time.Second), time.Minute)
	if err != nil || !ok {
		t.Fatalf("reclaim %v %v", ok, err)
	}
	if err := s.Save(ctx, first, true); !errors.Is(err, imageprep.ErrLeaseLost) {
		t.Fatalf("stale writer=%v", err)
	}
	second.Operation.Status = "SUCCEEDED"
	if err := s.Save(ctx, second, true); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Claim(ctx, time.Now().Add(time.Hour), time.Minute); err != nil || ok {
		t.Fatal("terminal operation reclaimed")
	}
}
