package isolation

import "testing"

func TestResolverCopiesApprovedWorkloadNetwork(t *testing.T) {
	request := Request{
		WorkloadProfile: WorkloadProfileWeb,
		Containers:      []ContainerRequirement{{Name: "web", Ports: []int{8080}, Expose: true, RunAsUser: 10001}},
		ResourceLimits:  ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
	}
	graph := &WorkloadNetwork{
		ID: "web-v1", Mode: NetworkModeExplicitTCPV1, IsolationProfile: WorkloadProfileWeb,
		Containers: []NetworkIdentity{{Name: request.Containers[0].Name, Image: "ghcr.io/msg-ctf/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ports: []int{request.Containers[0].Ports[0]}}},
		Allow:      []NetworkEdge{},
	}
	request.WorkloadNetwork = graph
	policy, err := NewStaticResolver().Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	graph.Containers[0].Ports[0]++
	if policy.WorkloadNetwork == nil || policy.WorkloadNetwork.Containers[0].Ports[0] == graph.Containers[0].Ports[0] {
		t.Fatal("resolver retained mutable network graph")
	}
	request.WorkloadNetwork = graph
	if _, err := NewStaticResolver().Resolve(request); err == nil {
		t.Fatal("mismatched graph ports accepted")
	}
}
