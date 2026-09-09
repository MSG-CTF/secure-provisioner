package k3s

import (
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	networkingv1 "k8s.io/api/networking/v1"
)

func TestInstanceNetworkAllowsOnlyOwnedPodsInSameNamespace(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	resources := buildNetworkPolicyResources(t, command)
	if command.Policy.IsolationRef != (isolation.ProfileRef{Name: "STANDARD", Version: "v2"}) {
		t.Fatal("new requests must use STANDARD@v2")
	}
	policy := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-instance-internal")
	assertLabelMap(t, "selected pods", policy.Spec.PodSelector.MatchLabels, ownershipLabels(command))
	if policy.Namespace != resources.Namespace.Name || len(policy.Spec.Ingress) != 1 || len(policy.Spec.Egress) != 1 {
		t.Fatal("instance policy must contain both directions in the owning namespace")
	}
	if len(policy.Spec.PolicyTypes) != 2 || policy.Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress || policy.Spec.PolicyTypes[1] != networkingv1.PolicyTypeEgress {
		t.Fatal("both ingress and egress must be isolated")
	}
	for _, peers := range [][]networkingv1.NetworkPolicyPeer{policy.Spec.Ingress[0].From, policy.Spec.Egress[0].To} {
		if len(peers) != 1 || peers[0].NamespaceSelector != nil || peers[0].IPBlock != nil || peers[0].PodSelector == nil {
			t.Fatal("internal peers must be pods in the policy namespace only")
		}
		assertLabelMap(t, "peer ownership", peers[0].PodSelector.MatchLabels, ownershipLabels(command))
	}
	if len(policy.Spec.Ingress[0].Ports) != 0 || len(policy.Spec.Egress[0].Ports) != 0 {
		t.Fatal("internal communication must not depend on a port or protocol graph")
	}
	if _, broad := firstBroadEgressPolicy(resources.NetworkPolicies); broad {
		t.Fatal("instance allowance must not open external egress")
	}
	public := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-public-ingress-web")
	if len(public.Spec.Ingress[0].Ports) != len(command.Containers[0].PublicPorts()) {
		t.Fatal("public exposure changed")
	}
	if findNetworkPolicy(resources.NetworkPolicies, "allow-public-ingress-internal") != nil {
		t.Fatal("private container became public")
	}
}

func TestInstanceNetworkRejectsAmbiguousOrUnknownPolicy(t *testing.T) {
	for _, version := range []string{"v2", "v99", ""} {
		t.Run(version, func(t *testing.T) {
			command := validMultiCreateCommand("aws-dev")
			command.Policy.IsolationRef.Version = version
			if version == "v2" {
				command.Policy.InternalConnections = []isolation.InternalConnection{}
			}
			_, err := BuildResourceSet(networkPolicyCluster(command.TargetID), command)
			if err == nil || runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
				t.Fatal("ambiguous or unsupported policy must fail closed")
			}
		})
	}
}

func TestLegacyPolicyDoesNotGainInstanceWideAllowance(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Policy.IsolationRef.Version = "v1"
	command.Policy.InternalConnections = []isolation.InternalConnection{{
		SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 9090,
	}}
	resources := buildNetworkPolicyResources(t, command)
	if findNetworkPolicy(resources.NetworkPolicies, "allow-instance-internal") != nil {
		t.Fatal("legacy operation replay must not broaden its approved network policy")
	}
	requireNetworkPolicy(t, resources.NetworkPolicies, "allow-internal-egress-web")
	requireNetworkPolicy(t, resources.NetworkPolicies, "allow-internal-ingress-internal")
}

func TestLegacyPolicyRetainsDeploymentSpecHash(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Policy.IsolationRef.Version = "v1"
	resources := buildNetworkPolicyResources(t, command)
	const original = "4a1a64eed73e02401973e53a58ecbaca0f5d658eefab7f743973c2d8929630a2"
	if resources.ExpectedSpecHash != original {
		t.Fatal("legacy operation replay must retain the existing workload revision")
	}
}
