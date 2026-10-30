package gateway

import (
	"context"
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestGatewayRecoveryPreservesApprovedNetworkSnapshot(t *testing.T) {
	graph := &isolation.WorkloadNetwork{
		ID: "reviewed-network-v1", Mode: isolation.NetworkModePeerGroupsV1,
		IsolationProfile: isolation.WorkloadProfileWeb,
		Containers:       []isolation.NetworkIdentity{{Name: "web", Image: "ghcr.io/msg/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ports: []int{8080}}},
		PeerGroups:       []isolation.NetworkPeerGroup{{Name: "appnet", Members: []string{"web"}}},
		Egress:           []isolation.NetworkEgress{{From: "web", CIDR: "10.20.30.40/32", Ports: []int{443}}},
	}
	record := Record{
		Command: provisioner.CreateWorkloadCommand{InstanceID: "instance", TargetID: "target", Policy: isolation.ResolvedPolicy{WorkloadNetwork: graph}},
		Result:  provisioner.CreateWorkloadResult{RuntimeWorkloadID: "target/namespace/instance", NamespaceUID: "namespace-uid"},
		Phase:   PhaseDeletePending,
	}
	journal := &memoryJournal{records: map[string]Record{"instance": record}}
	adapter := NewAdapter(nil, nil, journal)
	got, err := adapter.RecoveryBinding(context.Background(), "instance")
	if err != nil || !reflect.DeepEqual(got.WorkloadNetwork, graph) {
		t.Fatalf("journal recovery lost approved network snapshot: got=%+v want=%+v err=%v", got.WorkloadNetwork, graph, err)
	}
	got.WorkloadNetwork.Containers[0].Ports[0] = 80
	got.WorkloadNetwork.PeerGroups[0].Members[0] = "other"
	got.WorkloadNetwork.Egress[0].Ports[0] = 80
	if graph.Containers[0].Ports[0] != 8080 || graph.PeerGroups[0].Members[0] != "web" || graph.Egress[0].Ports[0] != 443 {
		t.Fatal("recovered binding aliases the immutable journal network snapshot")
	}
}
