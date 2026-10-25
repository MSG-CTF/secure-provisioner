package k3s

import (
	"encoding/json"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPeerNetworkRulesAreBidirectionalAllPortsAndNontransitive(t *testing.T) {
	var graph isolation.WorkloadNetwork
	if err := json.Unmarshal([]byte(`{"mode":"PEER_GROUPS_V1","peer_groups":[{"name":"ab","members":["a","b"]},{"name":"bc","members":["b","c"]}],"egress":[{"from":"a","cidr":"10.20.30.40/32","ports":[443,8443]}]}`), &graph); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"instance": "test"}
	containers := []provisioner.WorkloadContainer{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	requirements := map[string]isolation.ContainerRequirement{"a": {Name: "a", Ports: []int{8080}}, "b": {Name: "b", Ports: []int{8080}}, "c": {Name: "c", Ports: []int{8080}}}
	policies, valid := buildNetworkPolicies(Cluster{}, "test", labels, containers, isolation.ResolvedPolicy{IsolationRef: isolation.ProfileRef{Version: "v2"}, WorkloadNetwork: &graph}, requirements)
	if !valid {
		t.Fatal("peer network rejected")
	}
	for _, test := range []struct {
		from, to string
		allowed  bool
	}{{"a", "b", true}, {"b", "a", true}, {"b", "c", true}, {"c", "b", true}, {"a", "c", false}, {"c", "a", false}} {
		for _, protocol := range []corev1.Protocol{corev1.ProtocolTCP, corev1.ProtocolUDP, corev1.ProtocolSCTP} {
			if got := privatePoliciesAllow(policies, labels, test.from, test.to, protocol, 65000); got != test.allowed {
				t.Errorf("%s -> %s %s:65000 = %t, want %t", test.from, test.to, protocol, got, test.allowed)
			}
		}
	}
	if findNetworkPolicy(policies, "allow-instance-internal") != nil {
		t.Fatal("broad instance policy retained")
	}
	external := requireNetworkPolicy(t, policies, "allow-external-egress-a")
	if len(external.Spec.Egress) != 1 || len(external.Spec.Egress[0].To) != 1 || external.Spec.Egress[0].To[0].IPBlock == nil || external.Spec.Egress[0].To[0].IPBlock.CIDR != "10.20.30.40/32" {
		t.Fatalf("external destination broadened: %#v", external.Spec.Egress)
	}
	ports := external.Spec.Egress[0].Ports
	if len(ports) != 2 || ports[0].Port.IntValue() != 443 || ports[1].Port.IntValue() != 8443 || *ports[0].Protocol != corev1.ProtocolTCP || *ports[1].Protocol != corev1.ProtocolTCP {
		t.Fatalf("external ports broadened: %#v", ports)
	}
	if findNetworkPolicy(policies, "allow-external-egress-b") != nil {
		t.Fatal("external egress granted to another source")
	}
}

func TestExplicitTCPNetworkCanAddExactIPv6EgressWithoutPrivateFullMesh(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	graph := graphTestNetwork()
	graph.Egress = []isolation.NetworkEgress{{From: "web", CIDR: "fd00::42/128", Ports: []int{443}}}
	for index := range command.Containers {
		command.Containers[index].Image = graph.Containers[index].Image
	}
	command.Policy.WorkloadNetwork = graph
	command.PolicyRequest.WorkloadNetwork = isolation.CloneWorkloadNetwork(graph)
	resources, err := BuildResourceSet(networkPolicyCluster(command.TargetID), command)
	if err != nil {
		t.Fatal(err)
	}
	policy := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-external-egress-web")
	if policy.Spec.Egress[0].To[0].IPBlock.CIDR != "fd00::42/128" || policy.Spec.Egress[0].Ports[0].Port.IntValue() != 443 {
		t.Fatalf("unexpected external rule: %#v", policy.Spec.Egress)
	}
	if findNetworkPolicy(resources.NetworkPolicies, "allow-instance-internal") != nil || findNetworkPolicy(resources.NetworkPolicies, "allow-internal-egress-internal") != nil {
		t.Fatal("private traffic broadened")
	}
	command.PolicyRequest.WorkloadNetwork.Egress[0].Ports[0] = 80
	if _, err := BuildResourceSet(networkPolicyCluster(command.TargetID), command); runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
		t.Fatalf("egress snapshot drift accepted: %v", err)
	}
}

func selectorMatches(selector metav1.LabelSelector, labels map[string]string) bool {
	for key, value := range selector.MatchLabels {
		if labels[key] != value {
			return false
		}
	}
	for _, expr := range selector.MatchExpressions {
		if expr.Operator != metav1.LabelSelectorOpIn {
			return false
		}
		found := false
		for _, value := range expr.Values {
			if labels[expr.Key] == value {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func privatePoliciesAllow(policies []*networkingv1.NetworkPolicy, owner map[string]string, from, to string, protocol corev1.Protocol, port int) bool {
	source := copyLabels(owner)
	source[containerNameLabel] = from
	destination := copyLabels(owner)
	destination[containerNameLabel] = to
	egress, ingress := false, false
	portAllowed := func(ports []networkingv1.NetworkPolicyPort) bool {
		if len(ports) == 0 {
			return true
		}
		for _, p := range ports {
			if p.Port != nil && p.Port.IntValue() == port && p.Protocol != nil && *p.Protocol == protocol {
				return true
			}
		}
		return false
	}
	for _, policy := range policies {
		if selectorMatches(policy.Spec.PodSelector, source) {
			for _, rule := range policy.Spec.Egress {
				for _, peer := range rule.To {
					if peer.PodSelector != nil && peer.NamespaceSelector == nil && selectorMatches(*peer.PodSelector, destination) && portAllowed(rule.Ports) {
						egress = true
					}
				}
			}
		}
		if selectorMatches(policy.Spec.PodSelector, destination) {
			for _, rule := range policy.Spec.Ingress {
				for _, peer := range rule.From {
					if peer.PodSelector != nil && peer.NamespaceSelector == nil && selectorMatches(*peer.PodSelector, source) && portAllowed(rule.Ports) {
						ingress = true
					}
				}
			}
		}
	}
	return egress && ingress
}
