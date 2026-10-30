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

func TestOperationCodecRetainsPeerGroupsAndExactEgressSnapshot(t *testing.T) {
	command := validResolvedPwnCommand(t)
	graph := &isolation.WorkloadNetwork{
		ID: "peers-v1", Mode: isolation.NetworkModePeerGroupsV1, IsolationProfile: isolation.WorkloadProfilePwn,
		Containers: []isolation.NetworkIdentity{{Name: command.Containers[0].Name, Image: command.Containers[0].Image, Ports: []int{31337}}},
		PeerGroups: []isolation.NetworkPeerGroup{{Name: "private", Members: []string{command.Containers[0].Name}}},
		Egress:     []isolation.NetworkEgress{{From: command.Containers[0].Name, CIDR: "10.20.30.40/32", Ports: []int{443}}},
	}
	command.PolicyRequest.WorkloadNetwork = graph
	command.Policy.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	op, err := operations.NewCreateOperation("op-network-peers", command, 2)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeOperationCommand(op)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeOperationCommand(operations.OperationTypeCreate, encoded)
	if err != nil || !reflect.DeepEqual(decoded.CreateCommand.Policy.WorkloadNetwork, graph) || !reflect.DeepEqual(decoded.CreateCommand.PolicyRequest.WorkloadNetwork, graph) {
		t.Fatalf("network codec lost peer/egress fields: %v", err)
	}
	graph.PeerGroups[0].Members[0] = "other"
	graph.Egress[0].Ports[0] = 80
	if op.CreateCommand.PolicyRequest.WorkloadNetwork.PeerGroups[0].Members[0] == "other" || op.CreateCommand.PolicyRequest.WorkloadNetwork.Egress[0].Ports[0] != 443 {
		t.Fatal("operation snapshot aliases caller")
	}
}

func TestOperationCodecRetainsEmptyPeerAndEgressLists(t *testing.T) {
	command := validResolvedPwnCommand(t)
	graph := &isolation.WorkloadNetwork{
		ID: "empty-peers-v1", Mode: isolation.NetworkModePeerGroupsV1, IsolationProfile: isolation.WorkloadProfilePwn,
		Containers: []isolation.NetworkIdentity{{Name: command.Containers[0].Name, Image: command.Containers[0].Image, Ports: []int{31337}}},
		PeerGroups: []isolation.NetworkPeerGroup{}, Egress: []isolation.NetworkEgress{},
	}
	command.PolicyRequest.WorkloadNetwork = graph
	command.Policy.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	op, err := operations.NewCreateOperation("op-empty-network", command, 2)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeOperationCommand(op)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeOperationCommand(operations.OperationTypeCreate, encoded)
	if err != nil || !op.SameRequest(decoded) {
		t.Fatalf("empty network lists changed saved request identity: %v", err)
	}
}
