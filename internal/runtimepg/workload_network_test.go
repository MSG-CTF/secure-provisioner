package runtimepg

import (
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func TestOperationCodecRoundTripsWorkloadNetwork(t *testing.T) {
	command := validResolvedPwnCommand(t)
	graph := &isolation.WorkloadNetwork{
		ID: "sample-v1", Mode: isolation.NetworkModeExplicitTCPV1, IsolationProfile: isolation.WorkloadProfilePwn,
		Containers: []isolation.NetworkIdentity{{Name: command.Containers[0].Name, Image: command.Containers[0].Image, Ports: []int{31337}}},
		Allow:      []isolation.NetworkEdge{},
	}
	command.PolicyRequest.WorkloadNetwork = graph
	command.Policy.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	op, err := operations.NewCreateOperation("op-network", command, 2)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeOperationCommand(op)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeOperationCommand(operations.OperationTypeCreate, encoded)
	if err != nil || !reflect.DeepEqual(decoded.CreateCommand.PolicyRequest.WorkloadNetwork, graph) || !op.SameRequest(decoded) {
		t.Fatalf("network snapshot changed in operation codec: %v", err)
	}
}
