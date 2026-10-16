package runtimeops

import (
	"context"
	"errors"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

func networkServiceCommand() provisioner.CreateWorkloadCommand {
	command := createPolicyCommand()
	command.PolicyRequest.WorkloadNetwork = &isolation.WorkloadNetwork{
		ID: "sample-v1", Mode: isolation.NetworkModeExplicitTCPV1, IsolationProfile: isolation.WorkloadProfileWeb,
		Containers: []isolation.NetworkIdentity{
			{Name: "web", Image: command.Containers[0].Image, Ports: []int{8000}},
			{Name: "api", Image: command.Containers[1].Image, Ports: []int{8080}},
		},
		Allow: []isolation.NetworkEdge{{From: "web", To: "api", Port: 8080}},
	}
	return command
}

func TestServiceNetworkSnapshotIdempotencyAndBinding(t *testing.T) {
	bindings := runtimebinding.NewMemoryStore()
	service := newTestService(t, &recordingCreate{result: provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge", NamespaceUID: "namespace-uid-01",
	}}, &recordingStatus{}, &recordingDelete{}, bindings)
	command := networkServiceCommand()
	first, created, err := service.EnqueueCreate(command)
	if err != nil || !created || first.CreateCommand.Policy.WorkloadNetwork == nil {
		t.Fatalf("first create = %#v, %t, %v", first, created, err)
	}
	if _, created, err := service.EnqueueCreate(command); err != nil || created {
		t.Fatalf("same graph not idempotent: created=%t err=%v", created, err)
	}
	changed := networkServiceCommand()
	changed.PolicyRequest.WorkloadNetwork.Allow = []isolation.NetworkEdge{}
	if _, _, err := service.EnqueueCreate(changed); !errors.Is(err, operations.ErrIdempotencyConflict) {
		t.Fatalf("changed graph reused request: %v", err)
	}
	if _, err := service.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	binding, err := bindings.Get(command.InstanceID)
	if err != nil || binding.WorkloadNetwork == nil || len(binding.WorkloadNetwork.Allow) != 1 {
		t.Fatalf("binding lost network snapshot: %#v, %v", binding.WorkloadNetwork, err)
	}
}
