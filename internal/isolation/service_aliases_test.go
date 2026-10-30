package isolation

import "testing"

func TestServiceAliasCannotShadowAnotherContainerOrAlias(t *testing.T) {
	for _, requirements := range [][]ContainerRequirement{
		{{Name: "one", ServiceAliases: []string{"two"}}, {Name: "two"}},
		{{Name: "one", ServiceAliases: []string{"shared"}}, {Name: "two", ServiceAliases: []string{"shared"}}},
	} {
		if ValidateServiceAliases(requirements) == nil {
			t.Fatal("service alias collision accepted")
		}
	}
}

func TestResolvedPolicyCopiesServiceAliases(t *testing.T) {
	request := Request{WorkloadProfile: WorkloadProfileWeb, ResourceLimits: ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128}, Containers: []ContainerRequirement{{Name: "web-k3s", Ports: []int{8080}, Expose: true, RunAsUser: 10001, ServiceAliases: []string{"web"}}}}
	policy, err := NewStaticResolver().Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Containers[0].ServiceAliases[0] = "changed"
	if policy.Containers[0].ServiceAliases[0] != "web" {
		t.Fatal("mutable request alias changed resolved policy")
	}
}
