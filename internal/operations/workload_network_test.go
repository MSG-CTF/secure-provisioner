package operations

import (
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
)

func TestCreateOperationCopiesNetworkSnapshotAndDetectsDrift(t *testing.T) {
	command := validCreateCommand("network-snapshot")
	graph := &isolation.WorkloadNetwork{
		ID: "sample-v1", Mode: isolation.NetworkModeExplicitTCPV1, IsolationProfile: isolation.WorkloadProfileWeb,
		Containers: []isolation.NetworkIdentity{{Name: "web", Image: "ghcr.io/msg-ctf/sample@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ports: []int{8080}}},
		Allow:      []isolation.NetworkEdge{},
	}
	command.PolicyRequest.WorkloadNetwork = graph
	command.Policy.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	operation, err := NewCreateOperation("network-operation", command, 2)
	if err != nil {
		t.Fatal(err)
	}
	graph.Containers[0].Ports[0] = 9090
	if operation.CreateCommand.PolicyRequest.WorkloadNetwork.Containers[0].Ports[0] != 8080 || operation.CreateCommand.Policy.WorkloadNetwork.Containers[0].Ports[0] != 8080 {
		t.Fatal("network snapshot aliases caller")
	}
	matching, err := NewCreateOperation("network-operation-2", *operation.CreateCommand, 2)
	if err != nil || !operation.SameRequest(matching) {
		t.Fatal("identical network snapshot is not idempotent")
	}
	changed := copyCreateCommand(*operation.CreateCommand)
	changed.PolicyRequest.WorkloadNetwork.Allow = []isolation.NetworkEdge{{From: "web", To: "db", Port: 5432}}
	other, err := NewCreateOperation("network-operation-3", changed, 2)
	if err != nil {
		t.Fatal(err)
	}
	if operation.SameRequest(other) {
		t.Fatal("network policy drift reused the request")
	}
}
