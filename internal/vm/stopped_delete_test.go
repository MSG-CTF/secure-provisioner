package vm

import (
	"context"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/gateway"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

type stoppedDeleteRecorder struct{ ordinary, stopped int }

func (r *stoppedDeleteRecorder) DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error {
	r.ordinary++
	return nil
}
func (r *stoppedDeleteRecorder) DeleteStoppedWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error {
	r.stopped++
	return nil
}

func TestGatewayStoppedKubernetesDeletionSurvivesInstalledVMRouter(t *testing.T) {
	cfg := target()
	spy := &stoppedDeleteRecorder{}
	router := &Router{targets: map[string]Target{cfg.ID: cfg}, delete: spy}
	backend := &gateway.KubernetesBackend{Delete: router}
	c := provisioner.DeleteWorkloadCommand{RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: "k3s-target"}
	b := runtimebinding.Binding{TargetID: c.TargetID}
	if err := backend.DeleteWorkloadStep(t.Context(), c, b); err != nil {
		t.Fatal(err)
	}
	if spy.stopped != 1 || spy.ordinary != 0 {
		t.Fatal("VM router discarded Gateway's acknowledged stopped-workload path")
	}
	if err := backend.DeleteWorkload(t.Context(), c, b); err != nil {
		t.Fatal(err)
	}
	if spy.stopped != 1 || spy.ordinary != 1 {
		t.Fatal("ordinary deletion inherited Gateway's preparation")
	}
}

func TestStoppedVMDeletionKeepsGuestOwnershipChecksAndNeverReachesKubernetes(t *testing.T) {
	cfg := target()
	transport := &calls{}
	spy := &stoppedDeleteRecorder{}
	router := &Router{targets: map[string]Target{cfg.ID: cfg}, delete: spy, transport: transport}
	b := runtimebinding.Binding{InstanceID: "instance", TeamID: "team", TargetID: cfg.ID, NamespaceUID: "generation", RuntimeWorkloadID: "vm/workload"}
	c := provisioner.DeleteWorkloadCommand{RuntimeType: provisioner.RuntimeTypeVM, InstanceID: b.InstanceID, TeamID: "foreign", TargetID: b.TargetID, RuntimeWorkloadID: b.RuntimeWorkloadID}
	if err := router.DeleteStoppedWorkload(t.Context(), c, b); err == nil || transport.count != 0 {
		t.Fatal("foreign owner reached VM through stopped deletion")
	}
	c.TeamID = b.TeamID
	if err := router.DeleteStoppedWorkload(t.Context(), c, b); err != nil || transport.count != 1 {
		t.Fatal("owned VM did not use its original guest deletion protocol", err)
	}
	b.TargetID, c.TargetID = "removed-vm", "removed-vm"
	if err := router.DeleteStoppedWorkload(t.Context(), c, b); err == nil {
		t.Fatal("missing VM target was reported deleted")
	}
	if spy.stopped != 0 || spy.ordinary != 0 {
		t.Fatal("dedicated VM deletion fell through to Kubernetes")
	}
}
