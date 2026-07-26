package runtimebinding

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestMemoryStoreSavesAndReturnsIndependentBinding(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	want := validBinding(now)

	saved, created, err := store.SaveCreated(want)
	if err != nil || !created {
		t.Fatalf("SaveCreated() = (%#v, %t, %v), want created binding", saved, created, err)
	}
	saved.TargetID = "mutated"

	got, err := store.Get(want.InstanceID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != want {
		t.Fatalf("Get() = %#v, want %#v", got, want)
	}
}

func TestMemoryStoreAcceptsIdenticalCreateAsIdempotent(t *testing.T) {
	store := NewMemoryStore()
	binding := validBinding(time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC))
	if _, _, err := store.SaveCreated(binding); err != nil {
		t.Fatalf("first SaveCreated() error = %v", err)
	}

	got, created, err := store.SaveCreated(binding)
	if err != nil || created {
		t.Fatalf("second SaveCreated() = (%#v, %t, %v), want existing binding", got, created, err)
	}
	if got != binding {
		t.Fatalf("second SaveCreated() = %#v, want %#v", got, binding)
	}
}

func TestMemoryStoreRejectsDifferentTargetForSameInstance(t *testing.T) {
	store := NewMemoryStore()
	first := validBinding(time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC))
	if _, _, err := store.SaveCreated(first); err != nil {
		t.Fatalf("first SaveCreated() error = %v", err)
	}
	conflict := first
	conflict.TargetID = "gcp-dev"

	if _, _, err := store.SaveCreated(conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("SaveCreated(conflict) error = %v, want ErrConflict", err)
	}
}

func TestMemoryStoreTransitionsCreatedDeletingDeleted(t *testing.T) {
	store := NewMemoryStore()
	createdAt := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	binding := validBinding(createdAt)
	if _, _, err := store.SaveCreated(binding); err != nil {
		t.Fatalf("SaveCreated() error = %v", err)
	}

	deletingAt := createdAt.Add(time.Minute)
	deleting, err := store.MarkDeleting(binding.InstanceID, deletingAt)
	if err != nil {
		t.Fatalf("MarkDeleting() error = %v", err)
	}
	if deleting.State != StateDeleting || !deleting.UpdatedAt.Equal(deletingAt) {
		t.Fatalf("MarkDeleting() = %#v", deleting)
	}

	deletedAt := deletingAt.Add(time.Minute)
	deleted, err := store.MarkDeleted(binding.InstanceID, deletedAt)
	if err != nil {
		t.Fatalf("MarkDeleted() error = %v", err)
	}
	if deleted.State != StateDeleted || deleted.DeletedAt == nil || !deleted.DeletedAt.Equal(deletedAt) || !deleted.UpdatedAt.Equal(deletedAt) {
		t.Fatalf("MarkDeleted() = %#v", deleted)
	}

	idempotent, err := store.MarkDeleted(binding.InstanceID, deletedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("second MarkDeleted() error = %v", err)
	}
	if !reflect.DeepEqual(idempotent, deleted) {
		t.Fatalf("second MarkDeleted() = %#v, want unchanged %#v", idempotent, deleted)
	}
}

func TestMemoryStoreRejectsDeletingToCreatedRegression(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	binding := validBinding(now)
	if _, _, err := store.SaveCreated(binding); err != nil {
		t.Fatalf("SaveCreated() error = %v", err)
	}
	if _, err := store.MarkDeleting(binding.InstanceID, now.Add(time.Minute)); err != nil {
		t.Fatalf("MarkDeleting() error = %v", err)
	}

	if _, _, err := store.SaveCreated(binding); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("SaveCreated() after deleting error = %v, want ErrInvalidTransition", err)
	}
}

func validBinding(now time.Time) Binding {
	return Binding{
		InstanceID:        "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:            18,
		TargetID:          "aws-dev",
		Namespace:         "ctf-018f3f1e21b87a91a30b63b3400fd001",
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge",
		State:             StateCreated,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}
