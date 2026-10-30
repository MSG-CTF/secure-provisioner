package runtimeops

import (
	"errors"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

type rejectingTargetCreate struct{ recordingCreate }

func (*rejectingTargetCreate) ValidateCreateCommand(provisioner.CreateWorkloadCommand) error {
	return operations.NewExecutionError("TARGET_NOT_FOUND", false, nil)
}

func TestRejectedTargetIsFencedWithoutWorkloadOrAmbiguousCleanup(t *testing.T) {
	create := &rejectingTargetCreate{}
	store := operations.NewMemoryStore(nil)
	service := newTestServiceWithOperationStore(t, create, &recordingStatus{}, &recordingDelete{}, runtimebinding.NewMemoryStore(), store)
	command := createCommand()
	if _, _, err := service.EnqueueCreate(command); err == nil {
		t.Fatal("unknown target entered the create queue")
	}
	if _, err := store.GetByRequestID(command.RequestID); !errors.Is(err, operations.ErrOperationNotFound) {
		t.Fatal("rejected admission persisted executable work", err)
	}
	fenced, created, err := service.ReconcileCreate(command)
	if err != nil || !created || fenced.Status != operations.OperationStatusFailed ||
		fenced.LastErrorCode != "CREATE_NOT_ACCEPTED" || !fenced.Result.CreateCleanupCompleted {
		t.Fatal("unaccepted create did not produce durable cleanup proof", fenced, created, err)
	}
	replay, created, err := service.EnqueueCreate(command)
	if err != nil || created || replay.ID != fenced.ID || replay.Status != operations.OperationStatusFailed || create.calls != 0 {
		t.Fatal("fenced request could execute on retry", replay, created, err)
	}
}
