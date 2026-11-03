package runtimeops

import (
	"context"
	"errors"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

func failedStartupService(t *testing.T, steady int, failed bool, uid string) (*Service, *recordingDelete, operations.Operation) {
	t.Helper()
	deleter := &recordingDelete{}
	store := operations.NewMemoryStore(nil)
	s := newTestServiceWithOperationStore(t, &recordingCreate{}, &recordingStatus{}, deleter, runtimebinding.NewMemoryStore(), store)
	c := createCommand()
	c.SteadyCPUMillicores = steady
	op, _, err := s.EnqueueCreate(c)
	if err != nil {
		t.Fatal(err)
	}
	if failed {
		if _, err := store.MarkRunning(op.ID); err != nil {
			t.Fatal(err)
		}
		op, err = store.MarkFailed(op.ID, operations.Failure{Code: "ROLLBACK_FAILED", CreateCleanup: &provisioner.CreateCleanup{NamespaceUID: uid, FailureCode: "WORKLOAD_NOT_READY"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	return s, deleter, op
}

func TestFailedStartupRemainsVisibleForExplicitUIDFencedCleanup(t *testing.T) {
	s, deleter, failed := failedStartupService(t, 50, true, "original-namespace-uid")
	c := *failed.CreateCommand
	status, err := s.GetRuntimeStatus(context.Background(), c.InstanceID)
	if err != nil || status.Phase != "TERMINATING" || !status.CleanupPending || len(status.Containers) != 0 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	if _, err := s.bindings.Get(c.InstanceID); !errors.Is(err, runtimebinding.ErrNotFound) {
		t.Fatal("GET wrote a binding")
	}
	if status.EndpointReady {
		t.Fatal("unrestored startup exposed access")
	}
	command := provisioner.DeleteWorkloadCommand{RequestID: "delete-failed-startup", InstanceID: c.InstanceID, TeamID: c.TeamID,
		RuntimeType: c.RuntimeType, TargetID: c.TargetID, RuntimeWorkloadID: status.RuntimeWorkloadID, Reason: provisioner.DeleteReasonCreateFailedCleanup}
	op, created, err := s.EnqueueDelete(command)
	if err != nil || !created {
		t.Fatalf("enqueue delete: %v", err)
	}
	binding, err := s.bindings.Get(c.InstanceID)
	if err != nil || binding.NamespaceUID != "original-namespace-uid" || len(binding.Endpoints) != 0 {
		t.Fatal("lost exact failed namespace identity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	waitForOperationStatus(t, s, op.ID, operations.OperationStatusSucceeded)
	cancel()
	<-done
	if deleter.calls != 1 || deleter.binding.NamespaceUID != "original-namespace-uid" {
		t.Fatal("cleanup did not use the original generation")
	}
	final, err := s.GetRuntimeStatus(context.Background(), c.InstanceID)
	if err != nil || final.Phase != "TERMINATED" {
		t.Fatalf("final=%#v err=%v", final, err)
	}
	if replay, created, err := s.EnqueueDelete(command); err != nil || created || replay.ID != op.ID {
		t.Fatal("delete retry was not idempotent")
	}
}

func TestFailedStartupCleanupRejectsWrongOwnerAndDoesNotInventTerminalProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		steady int
		failed bool
		uid    string
	}{
		{"pending", 50, false, "uid"}, {"legacy", 0, true, "uid"}, {"missing UID", 50, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, op := failedStartupService(t, tc.steady, tc.failed, tc.uid)
			if _, err := s.GetRuntimeStatus(context.Background(), op.CreateCommand.InstanceID); !errors.Is(err, runtimebinding.ErrNotFound) {
				t.Fatalf("unexpected recovery: %v", err)
			}
		})
	}
	s, deleter, op := failedStartupService(t, 50, true, "uid")
	c := *op.CreateCommand
	ns, _ := k3s.NamespaceForInstance(c.InstanceID)
	bad := provisioner.DeleteWorkloadCommand{RequestID: "wrong-owner", InstanceID: c.InstanceID, TeamID: "00000000-0000-4000-8000-000000000099", RuntimeType: c.RuntimeType, TargetID: c.TargetID, RuntimeWorkloadID: k3s.RuntimeWorkloadID(c.TargetID, ns), Reason: provisioner.DeleteReasonCreateFailedCleanup}
	if _, _, err := s.EnqueueDelete(bad); !errors.Is(err, ErrBindingMismatch) {
		t.Fatal("wrong team accepted")
	}
	if deleter.calls != 0 {
		t.Fatal("deleted without identity match")
	}
	if _, err := s.bindings.Get(c.InstanceID); !errors.Is(err, runtimebinding.ErrNotFound) {
		t.Fatal("wrong owner wrote binding")
	}
	c.RequestID = "conflicting-new-create"
	if _, _, err := s.EnqueueCreate(c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRuntimeStatus(context.Background(), c.InstanceID); !errors.Is(err, operations.ErrIdempotencyConflict) {
		t.Fatal("ambiguous generation was adopted")
	}
}
