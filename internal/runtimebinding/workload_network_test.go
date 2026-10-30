package runtimebinding

import (
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
)

func TestBindingCopiesAndComparesNetworkSnapshot(t *testing.T) {
	graph := &isolation.WorkloadNetwork{ID: "sample-v1", Mode: isolation.NetworkModePeerGroupsV1,
		Containers: []isolation.NetworkIdentity{{Name: "web", Ports: []int{8080}}},
		PeerGroups: []isolation.NetworkPeerGroup{{Name: "private", Members: []string{"web"}}},
		Egress:     []isolation.NetworkEgress{{From: "web", CIDR: "10.20.30.40/32", Ports: []int{443}}}}
	binding := Binding{WorkloadNetwork: graph}
	copied := copyBinding(binding)
	graph.Containers[0].Ports[0] = 9090
	if copied.WorkloadNetwork.Containers[0].Ports[0] != 8080 {
		t.Fatal("binding snapshot aliases source")
	}
	if samePlacement(binding, copied) {
		t.Fatal("changed graph reused binding placement")
	}
	graph.PeerGroups[0].Members[0] = "other"
	graph.Egress[0].Ports[0] = 80
	if copied.WorkloadNetwork.PeerGroups[0].Members[0] != "web" || copied.WorkloadNetwork.Egress[0].Ports[0] != 443 {
		t.Fatal("binding peer/egress snapshot aliases source")
	}
}
