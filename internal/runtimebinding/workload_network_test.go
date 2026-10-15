package runtimebinding

import (
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
)

func TestBindingCopiesAndComparesNetworkSnapshot(t *testing.T) {
	graph := &isolation.WorkloadNetwork{ID: "sample-v1", Mode: isolation.NetworkModeExplicitTCPV1,
		Containers: []isolation.NetworkIdentity{{Name: "web", Ports: []int{8080}}}, Allow: []isolation.NetworkEdge{}}
	binding := Binding{WorkloadNetwork: graph}
	copied := copyBinding(binding)
	graph.Containers[0].Ports[0] = 9090
	if copied.WorkloadNetwork.Containers[0].Ports[0] != 8080 {
		t.Fatal("binding snapshot aliases source")
	}
	if samePlacement(binding, copied) {
		t.Fatal("changed graph reused binding placement")
	}
}
