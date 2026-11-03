package runtimeops

import (
	"context"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"testing"
	"time"
)

type journalRecoveryCreate struct {
	recordingCreate
	binding runtimebinding.Binding
}

func (c *journalRecoveryCreate) RecoveryBinding(context.Context, string) (runtimebinding.Binding, error) {
	return c.binding, nil
}
func (c *journalRecoveryCreate) CleanupPending(context.Context, string) (bool, error) {
	return false, nil
}
func TestGatewayJournalPreventsMissingBindingAndNamespaceFromProvingCleanup(t *testing.T) {
	command := createCommand()
	result := provisioner.CreateWorkloadResult{RuntimeWorkloadID: "aws-dev/ctf-test/challenge", NamespaceUID: "uid"}
	binding := createdBinding(command, result, "ctf-test", time.Now())
	for _, present := range []bool{false, true} {
		store := runtimebinding.NewMemoryStore()
		if present {
			_, _, _ = store.SaveCreated(binding)
		}
		create := &journalRecoveryCreate{binding: binding}
		service := newTestService(t, create, &recordingStatus{result: k3s.RuntimeStatus{Phase: "TERMINATED"}}, &recordingDelete{}, store)
		status, err := service.GetRuntimeStatus(context.Background(), command.InstanceID)
		if err != nil || status.Phase != "TERMINATING" || !status.CleanupPending || status.TargetID != command.TargetID || status.RuntimeWorkloadID != result.RuntimeWorkloadID {
			t.Fatalf("binding=%v status=%+v err=%v", present, status, err)
		}
	}
}
func TestGatewayJournalRecoversBindingForCleanupRetry(t *testing.T) {
	command := createCommand()
	result := provisioner.CreateWorkloadResult{RuntimeWorkloadID: "aws-dev/ctf-test/challenge", NamespaceUID: "uid"}
	binding := createdBinding(command, result, "ctf-test", time.Now())
	service := newTestService(t, &journalRecoveryCreate{binding: binding}, &recordingStatus{}, &recordingDelete{}, runtimebinding.NewMemoryStore())
	_, created, err := service.EnqueueDelete(provisioner.DeleteWorkloadCommand{RequestID: "retry-cleanup-new-generation", InstanceID: command.InstanceID, TeamID: command.TeamID, RuntimeType: command.RuntimeType, TargetID: command.TargetID, RuntimeWorkloadID: result.RuntimeWorkloadID})
	if err != nil || !created {
		t.Fatal(created, err)
	}
}
