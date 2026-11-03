package runtimepg

import (
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"testing"
)

func TestPostgresCleanupLookupKeepsOriginalGenerationAndRejectsAmbiguity(t *testing.T) {
	database := openTestDatabase(t)
	store := database.Operations()
	c := validResolvedPwnCommand(t)
	if _, err := store.GetCreateByInstance(c.InstanceID); !errors.Is(err, operations.ErrOperationNotFound) {
		t.Fatal(err)
	}
	op, _, err := store.EnqueueCreate(c, 4)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetCreateByInstance(c.InstanceID)
	if err != nil || got.ID != op.ID || got.CreateCommand.TargetID != c.TargetID {
		t.Fatal("lost original command")
	}
	c.RequestID = "second-create-for-same-instance"
	if _, _, err := store.EnqueueCreate(c, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetCreateByInstance(c.InstanceID); !errors.Is(err, operations.ErrIdempotencyConflict) {
		t.Fatal("ambiguous create lookup succeeded")
	}
}
