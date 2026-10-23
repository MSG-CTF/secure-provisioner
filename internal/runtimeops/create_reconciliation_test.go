package runtimeops

import (
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func TestReconcileUnacceptedCreateDoesNotResolvePolicyOrEnqueueExecution(t *testing.T) {
	resolver := &recordingResolver{}
	service := newTestServiceWithResolver(t, resolver, operations.NewMemoryStore(nil))
	command := createCommand()
	command.RequestFingerprint = "original-input"
	fence, created, err := service.ReconcileCreate(command)
	if err != nil || !created || !fence.Result.CreateCleanupCompleted {
		t.Fatalf("reconciliation=%#v created=%t err=%v", fence, created, err)
	}
	late, created, err := service.EnqueueCreate(command)
	if err != nil || created || late.ID != fence.ID || late.Status != operations.OperationStatusFailed || resolver.calls != 0 {
		t.Fatalf("late request=%#v created=%t resolver calls=%d err=%v", late, created, resolver.calls, err)
	}
}
