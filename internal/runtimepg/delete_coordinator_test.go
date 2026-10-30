package runtimepg

import (
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

func TestBeginDeleteAtomicallyMarksBindingAndEnqueuesOperation(t *testing.T) {
	database := openTestDatabase(t)
	binding := runtimebinding.Binding{
		InstanceID: "11111111-1111-4111-8111-111111111111", TeamID: "00000000-0000-4000-8000-000000000001",
		TargetID: "aws-k3s-001", Namespace: "instance-11111111",
		NamespaceUID: "namespace-uid", RuntimeWorkloadID: "aws-k3s-001/instance-11111111",
		State: runtimebinding.StateCreated, CreatedAt: time.Unix(90, 0), UpdatedAt: time.Unix(90, 0),
	}
	if _, _, err := database.Bindings().SaveCreated(binding); err != nil {
		t.Fatal(err)
	}
	command := provisioner.DeleteWorkloadCommand{
		RequestID: "delete-1", InstanceID: binding.InstanceID, TeamID: binding.TeamID,
		RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: binding.TargetID,
		RuntimeWorkloadID: binding.RuntimeWorkloadID, Reason: provisioner.DeleteReasonTTLExpired,
	}
	operation, created, err := database.DeleteCoordinator().BeginDelete(command, 4, time.Unix(100, 0))
	if err != nil || !created {
		t.Fatalf("BeginDelete = %#v, %t, %v", operation, created, err)
	}
	stored, err := database.Bindings().Get(binding.InstanceID)
	if err != nil || stored.State != runtimebinding.StateDeleting {
		t.Fatalf("binding = %#v, %v", stored, err)
	}
}

func TestBeginDeleteRollsBackBindingWhenOperationInsertFails(t *testing.T) {
	database := openTestDatabase(t)
	binding := runtimebinding.Binding{
		InstanceID: "22222222-2222-4222-8222-222222222222", TeamID: "00000000-0000-4000-8000-000000000002",
		TargetID: "aws-k3s-001", Namespace: "instance-22222222", NamespaceUID: "namespace-uid-2",
		RuntimeWorkloadID: "aws-k3s-001/instance-22222222", State: runtimebinding.StateCreated,
		CreatedAt: time.Unix(90, 0), UpdatedAt: time.Unix(90, 0),
	}
	if _, _, err := database.Bindings().SaveCreated(binding); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`ALTER TABLE runtime_operations ADD CONSTRAINT runtime_operations_test_reject_delete CHECK (operation_type <> 'DELETE')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.db.Exec(`ALTER TABLE runtime_operations DROP CONSTRAINT IF EXISTS runtime_operations_test_reject_delete`)
	})
	command := provisioner.DeleteWorkloadCommand{
		RequestID: "delete-fails", InstanceID: binding.InstanceID, TeamID: binding.TeamID,
		RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: binding.TargetID,
		RuntimeWorkloadID: binding.RuntimeWorkloadID, Reason: provisioner.DeleteReasonUserRequested,
	}
	if _, _, err := database.DeleteCoordinator().BeginDelete(command, 4, time.Unix(100, 0)); err == nil {
		t.Fatal("BeginDelete error = nil")
	}
	stored, err := database.Bindings().Get(binding.InstanceID)
	if err != nil || stored.State != runtimebinding.StateCreated {
		t.Fatalf("binding after rollback = %#v, %v", stored, err)
	}
}
