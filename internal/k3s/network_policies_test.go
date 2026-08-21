package k3s

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildNetworkPoliciesCreatesNamespaceWideDefaultDeny(t *testing.T) {
	resources := buildNetworkPolicyResources(t, validCreateCommand("aws-dev"))
	deny := requireNetworkPolicy(t, resources.NetworkPolicies, "default-deny-all")

	if len(deny.Spec.PodSelector.MatchLabels) != 0 || len(deny.Spec.PodSelector.MatchExpressions) != 0 {
		t.Fatalf("pod selector = %#v, want every pod in the namespace", deny.Spec.PodSelector)
	}
	if !reflect.DeepEqual(deny.Spec.PolicyTypes, []networkingv1.PolicyType{
		networkingv1.PolicyTypeIngress,
		networkingv1.PolicyTypeEgress,
	}) {
		t.Fatalf("policy types = %#v, want explicit ingress and egress", deny.Spec.PolicyTypes)
	}
	if len(deny.Spec.Ingress) != 0 || len(deny.Spec.Egress) != 0 {
		t.Fatalf("default deny contains allow rules: %#v", deny.Spec)
	}
}

func TestBuildNetworkPoliciesAllowsOnlyConfiguredDNSOverTCPAndUDP53(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources := buildNetworkPolicyResources(t, command)
	policy := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-dns")

	assertLabelMap(t, "DNS source selector", policy.Spec.PodSelector.MatchLabels, ownershipLabels(command))
	if !reflect.DeepEqual(policy.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}) ||
		len(policy.Spec.Ingress) != 0 || len(policy.Spec.Egress) != 1 {
		t.Fatalf("DNS policy directions = %#v", policy.Spec)
	}
	rule := policy.Spec.Egress[0]
	if len(rule.To) != 1 {
		t.Fatalf("DNS peers = %#v, want one configured DNS peer", rule.To)
	}
	peer := rule.To[0]
	assertLabelMap(t, "DNS namespace selector", peer.NamespaceSelector.MatchLabels, map[string]string{
		"kubernetes.io/metadata.name": "kube-system",
	})
	assertLabelMap(t, "DNS pod selector", peer.PodSelector.MatchLabels, map[string]string{"k8s-app": "kube-dns"})
	assertNetworkPolicyPorts(t, rule.Ports, []networkPolicyPortExpectation{
		{Protocol: corev1.ProtocolUDP, Port: 53},
		{Protocol: corev1.ProtocolTCP, Port: 53},
	})
}

func TestBuildNetworkPoliciesAllowsPlatformIngressOnlyToExposedDeclaredPorts(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Containers[0].Ports = []int{8443, 8080}
	command.Policy = resolvedPolicyForCommand(command, "SMALL_MULTI")
	resources := buildNetworkPolicyResources(t, command)

	policy := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-public-ingress-web")
	wantTarget := ownershipLabels(command)
	wantTarget[containerNameLabel] = "web"
	assertLabelMap(t, "public ingress target", policy.Spec.PodSelector.MatchLabels, wantTarget)
	if !reflect.DeepEqual(policy.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}) ||
		len(policy.Spec.Ingress) != 1 || len(policy.Spec.Egress) != 0 {
		t.Fatalf("public ingress policy directions = %#v", policy.Spec)
	}
	rule := policy.Spec.Ingress[0]
	if len(rule.From) != 1 {
		t.Fatalf("public ingress peers = %#v, want configured controller only", rule.From)
	}
	assertLabelMap(t, "ingress namespace selector", rule.From[0].NamespaceSelector.MatchLabels, map[string]string{
		"kubernetes.io/metadata.name": "ingress-system",
	})
	assertLabelMap(t, "ingress pod selector", rule.From[0].PodSelector.MatchLabels, map[string]string{
		"app.kubernetes.io/name": "traefik",
	})
	assertNetworkPolicyPorts(t, rule.Ports, []networkPolicyPortExpectation{
		{Protocol: corev1.ProtocolTCP, Port: 8080},
		{Protocol: corev1.ProtocolTCP, Port: 8443},
	})
	if findNetworkPolicy(resources.NetworkPolicies, "allow-public-ingress-internal") != nil {
		t.Fatal("unexposed container received a platform ingress policy")
	}
}

func TestBuildNetworkPoliciesAllowsExternalNodePortIngressOnlyToExposedDeclaredPorts(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Containers[0].Ports = []int{8443, 8080}
	command.Policy = resolvedPolicyForCommand(command, "SMALL_MULTI")
	cluster := networkPolicyCluster(command.TargetID)
	cluster.Config.ExposureMode = ExposureModeNodePort
	cluster.Config.PublicGateway = "http://203.0.113.10"

	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	policy := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-public-ingress-web")
	rule := policy.Spec.Ingress[0]
	if len(rule.From) != 0 {
		t.Fatalf("NodePort public ingress peers = %#v, want all external sources", rule.From)
	}
	assertNetworkPolicyPorts(t, rule.Ports, []networkPolicyPortExpectation{
		{Protocol: corev1.ProtocolTCP, Port: 8080},
		{Protocol: corev1.ProtocolTCP, Port: 8443},
	})
	if findNetworkPolicy(resources.NetworkPolicies, "allow-public-ingress-internal") != nil {
		t.Fatal("unexposed container received a NodePort ingress policy")
	}
}

func TestBuildNetworkPoliciesAllowsInternalConnectionInBothAdditiveDirections(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Policy.InternalConnections = []isolation.InternalConnection{{
		SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 9090,
	}}
	resources := buildNetworkPolicyResources(t, command)

	sourceLabels := ownershipLabels(command)
	sourceLabels[containerNameLabel] = "web"
	destinationLabels := ownershipLabels(command)
	destinationLabels[containerNameLabel] = "internal"

	egress := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-internal-egress-web")
	assertLabelMap(t, "internal egress target", egress.Spec.PodSelector.MatchLabels, sourceLabels)
	if !reflect.DeepEqual(egress.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}) ||
		len(egress.Spec.Egress) != 1 || len(egress.Spec.Ingress) != 0 {
		t.Fatalf("internal egress directions = %#v", egress.Spec)
	}
	assertInternalPeerRule(t, "internal egress", egress.Spec.Egress[0].To, egress.Spec.Egress[0].Ports, destinationLabels, 9090)

	ingress := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-internal-ingress-internal")
	assertLabelMap(t, "internal ingress target", ingress.Spec.PodSelector.MatchLabels, destinationLabels)
	if !reflect.DeepEqual(ingress.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}) ||
		len(ingress.Spec.Ingress) != 1 || len(ingress.Spec.Egress) != 0 {
		t.Fatalf("internal ingress directions = %#v", ingress.Spec)
	}
	assertInternalPeerRule(t, "internal ingress", ingress.Spec.Ingress[0].From, ingress.Spec.Ingress[0].Ports, sourceLabels, 9090)
}

func TestBuildNetworkPoliciesForOutboundNoneHasNoPublicOrCIDREgress(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Policy.InternalConnections = []isolation.InternalConnection{{
		SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 9090,
	}}
	resources := buildNetworkPolicyResources(t, command)

	if policyName, broad := firstBroadEgressPolicy(resources.NetworkPolicies); broad {
		t.Fatalf("%s has an egress rule without destinations", policyName)
	}
	for _, policy := range resources.NetworkPolicies {
		if strings.Contains(policy.Name, "public-egress") {
			t.Fatalf("unexpected public egress policy %q", policy.Name)
		}
		for _, rule := range policy.Spec.Egress {
			for _, peer := range rule.To {
				if peer.IPBlock != nil {
					t.Fatalf("%s contains forbidden CIDR egress %#v", policy.Name, peer.IPBlock)
				}
			}
		}
		for _, rule := range policy.Spec.Ingress {
			for _, peer := range rule.From {
				if peer.IPBlock != nil {
					t.Fatalf("%s contains forbidden CIDR ingress %#v", policy.Name, peer.IPBlock)
				}
			}
		}
	}
}

func TestBroadEgressAssertionRejectsEmptyAllowAllRule(t *testing.T) {
	mutant := []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "mutant-empty-egress-rule"},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
		},
	}}

	policyName, broad := firstBroadEgressPolicy(mutant)
	if !broad || policyName != "mutant-empty-egress-rule" {
		t.Fatalf("empty egress rule was not detected: policy = %q, detected = %t", policyName, broad)
	}
}

func TestBuildNetworkPoliciesPreservesInternalPeerPortPairsAcrossGroupedRules(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Containers = []provisioner.WorkloadContainer{
		{Name: "web", Image: "registry.example.invalid/web:latest", Ports: []int{8000}, Expose: true},
		{Name: "api", Image: "registry.example.invalid/api:latest", Ports: []int{8080, 9090}},
		{Name: "worker", Image: "registry.example.invalid/worker:latest", Ports: []int{7070}},
	}
	command.Policy = resolvedPolicyForCommand(command, "SMALL_MULTI")
	command.Policy.InternalConnections = []isolation.InternalConnection{
		{SourceContainer: "web", DestinationContainer: "api", Protocol: isolation.ProtocolTCP, Port: 8080},
		{SourceContainer: "web", DestinationContainer: "worker", Protocol: isolation.ProtocolTCP, Port: 7070},
		{SourceContainer: "worker", DestinationContainer: "api", Protocol: isolation.ProtocolTCP, Port: 9090},
	}
	resources := buildNetworkPolicyResources(t, command)

	webEgress := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-internal-egress-web")
	assertInternalEgressRulePairs(t, webEgress.Spec.Egress, ownershipLabels(command), []internalRulePair{
		{PeerContainer: "api", Protocol: corev1.ProtocolTCP, Port: 8080},
		{PeerContainer: "worker", Protocol: corev1.ProtocolTCP, Port: 7070},
	})

	apiIngress := requireNetworkPolicy(t, resources.NetworkPolicies, "allow-internal-ingress-api")
	assertInternalIngressRulePairs(t, apiIngress.Spec.Ingress, ownershipLabels(command), []internalRulePair{
		{PeerContainer: "web", Protocol: corev1.ProtocolTCP, Port: 8080},
		{PeerContainer: "worker", Protocol: corev1.ProtocolTCP, Port: 9090},
	})
}

func TestBuildNetworkPoliciesScopesPodSelectorsToOwningTeamAndInstance(t *testing.T) {
	first := validMultiCreateCommand("aws-dev")
	first.Policy.InternalConnections = []isolation.InternalConnection{{
		SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 9090,
	}}
	second := first
	second.TeamID = 84

	firstResources := buildNetworkPolicyResources(t, first)
	secondResources := buildNetworkPolicyResources(t, second)
	firstPolicy := requireNetworkPolicy(t, firstResources.NetworkPolicies, "allow-internal-egress-web")
	secondPolicy := requireNetworkPolicy(t, secondResources.NetworkPolicies, "allow-internal-egress-web")

	firstSource := ownershipLabels(first)
	firstSource[containerNameLabel] = "web"
	secondSource := ownershipLabels(second)
	secondSource[containerNameLabel] = "web"
	assertLabelMap(t, "first team source", firstPolicy.Spec.PodSelector.MatchLabels, firstSource)
	assertLabelMap(t, "second team source", secondPolicy.Spec.PodSelector.MatchLabels, secondSource)
	if reflect.DeepEqual(firstPolicy.Spec.PodSelector.MatchLabels, secondPolicy.Spec.PodSelector.MatchLabels) {
		t.Fatal("different teams received identical pod selectors")
	}

	firstDestination := ownershipLabels(first)
	firstDestination[containerNameLabel] = "internal"
	secondDestination := ownershipLabels(second)
	secondDestination[containerNameLabel] = "internal"
	assertLabelMap(t, "first team destination", firstPolicy.Spec.Egress[0].To[0].PodSelector.MatchLabels, firstDestination)
	assertLabelMap(t, "second team destination", secondPolicy.Spec.Egress[0].To[0].PodSelector.MatchLabels, secondDestination)
}

func TestBuildNetworkPoliciesRejectsMalformedInternalConnections(t *testing.T) {
	valid := isolation.InternalConnection{
		SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 9090,
	}
	tests := map[string][]isolation.InternalConnection{
		"missing source": {{
			SourceContainer: "missing", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 9090,
		}},
		"missing destination": {{
			SourceContainer: "web", DestinationContainer: "missing", Protocol: isolation.ProtocolTCP, Port: 9090,
		}},
		"undeclared destination port": {{
			SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 7070,
		}},
		"unsupported protocol": {{
			SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.Protocol("UDP"), Port: 9090,
		}},
		"invalid port": {{
			SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 0,
		}},
		"duplicate connection": {valid, valid},
	}
	for name, connections := range tests {
		t.Run(name, func(t *testing.T) {
			command := validMultiCreateCommand("aws-dev")
			command.Policy.InternalConnections = connections
			_, err := BuildResourceSet(networkPolicyCluster("aws-dev"), command)
			if runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
				t.Fatalf("code = %q, want INVALID_CREATE_COMMAND", runtimeErrorCode(t, err))
			}
		})
	}
}

func TestBuildNetworkPoliciesRejectsUntrustedTargetSelectors(t *testing.T) {
	cluster := networkPolicyCluster("aws-dev")
	cluster.Config.SecurityCapabilities.DNSPodSelector = nil
	_, err := BuildResourceSet(cluster, validCreateCommand("aws-dev"))
	if runtimeErrorCode(t, err) != "TARGET_CAPABILITY_MISMATCH" {
		t.Fatalf("code = %q, want TARGET_CAPABILITY_MISMATCH", runtimeErrorCode(t, err))
	}
}

func TestBuildNetworkPoliciesUsesDeterministicNamesAndOrder(t *testing.T) {
	first := validMultiCreateCommand("aws-dev")
	first.Containers[1].Expose = true
	first.Policy.Containers[1].Expose = true
	first.Policy.InternalConnections = []isolation.InternalConnection{
		{SourceContainer: "web", DestinationContainer: "internal", Protocol: isolation.ProtocolTCP, Port: 9090},
		{SourceContainer: "internal", DestinationContainer: "web", Protocol: isolation.ProtocolTCP, Port: 8080},
	}
	second := first
	second.Containers = reverseWorkloadContainers(first.Containers)
	second.Policy.Containers = reversePolicyContainers(first.Policy.Containers)
	second.Policy.InternalConnections = append([]isolation.InternalConnection(nil), first.Policy.InternalConnections...)
	sort.Slice(second.Policy.InternalConnections, func(i, j int) bool { return i > j })

	firstPolicies := buildNetworkPolicyResources(t, first).NetworkPolicies
	secondPolicies := buildNetworkPolicyResources(t, second).NetworkPolicies
	if !reflect.DeepEqual(firstPolicies, secondPolicies) {
		t.Fatalf("policy output depends on input ordering:\nfirst = %#v\nsecond = %#v", firstPolicies, secondPolicies)
	}
	wantNames := []string{
		"default-deny-all",
		"allow-dns",
		"allow-public-ingress-internal",
		"allow-public-ingress-web",
		"allow-internal-egress-internal",
		"allow-internal-egress-web",
		"allow-internal-ingress-internal",
		"allow-internal-ingress-web",
	}
	gotNames := make([]string, len(firstPolicies))
	for index, policy := range firstPolicies {
		gotNames[index] = policy.Name
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("policy names = %#v, want %#v", gotNames, wantNames)
	}
}

type networkPolicyPortExpectation struct {
	Protocol corev1.Protocol
	Port     int
}

type internalRulePair struct {
	PeerContainer string
	Protocol      corev1.Protocol
	Port          int
}

func buildNetworkPolicyResources(t *testing.T, command provisioner.CreateWorkloadCommand) ResourceSet {
	t.Helper()
	resources, err := BuildResourceSet(networkPolicyCluster(command.TargetID), command)
	if err != nil {
		t.Fatal(err)
	}
	return resources
}

func networkPolicyCluster(targetID string) Cluster {
	cluster := validCluster(targetID)
	cluster.Config.SecurityCapabilities = SecurityCapabilities{
		NetworkPolicyEnforced:          true,
		SupplementalGroupsPolicyStrict: true,
		PodPIDLimitEnforced:            true,
		NetworkPolicyProvider:          "kube-router",
		DNSNamespace:                   "kube-system",
		DNSPodSelector:                 map[string]string{"k8s-app": "kube-dns"},
		IngressNamespace:               "ingress-system",
		IngressPodSelector:             map[string]string{"app.kubernetes.io/name": "traefik"},
	}
	return cluster
}

func requireNetworkPolicy(t *testing.T, policies []*networkingv1.NetworkPolicy, name string) *networkingv1.NetworkPolicy {
	t.Helper()
	policy := findNetworkPolicy(policies, name)
	if policy == nil {
		t.Fatalf("network policy %q not found", name)
	}
	return policy
}

func findNetworkPolicy(policies []*networkingv1.NetworkPolicy, name string) *networkingv1.NetworkPolicy {
	for _, policy := range policies {
		if policy.Name == name {
			return policy
		}
	}
	return nil
}

func assertLabelMap(t *testing.T, subject string, got, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %#v, want %#v", subject, got, want)
	}
}

func assertNetworkPolicyPorts(t *testing.T, got []networkingv1.NetworkPolicyPort, want []networkPolicyPortExpectation) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ports = %#v, want %#v", got, want)
	}
	for index, expected := range want {
		if got[index].Protocol == nil || *got[index].Protocol != expected.Protocol || got[index].Port == nil || got[index].Port.IntValue() != expected.Port {
			t.Fatalf("port[%d] = %#v, want %s/%d", index, got[index], expected.Protocol, expected.Port)
		}
	}
}

func assertInternalPeerRule(
	t *testing.T,
	subject string,
	peers []networkingv1.NetworkPolicyPeer,
	ports []networkingv1.NetworkPolicyPort,
	wantPeerLabels map[string]string,
	wantPort int,
) {
	t.Helper()
	if len(peers) != 1 || peers[0].NamespaceSelector != nil || peers[0].PodSelector == nil {
		t.Fatalf("%s peers = %#v, want one same-namespace pod peer", subject, peers)
	}
	assertLabelMap(t, subject+" peer selector", peers[0].PodSelector.MatchLabels, wantPeerLabels)
	assertNetworkPolicyPorts(t, ports, []networkPolicyPortExpectation{{Protocol: corev1.ProtocolTCP, Port: wantPort}})
}

func firstBroadEgressPolicy(policies []*networkingv1.NetworkPolicy) (string, bool) {
	for _, policy := range policies {
		for _, rule := range policy.Spec.Egress {
			if len(rule.To) == 0 {
				return policy.Name, true
			}
		}
	}
	return "", false
}

func assertInternalEgressRulePairs(
	t *testing.T,
	rules []networkingv1.NetworkPolicyEgressRule,
	ownerLabels map[string]string,
	want []internalRulePair,
) {
	t.Helper()
	got := make([]internalRulePair, 0, len(rules))
	for _, rule := range rules {
		got = append(got, internalRulePairFromRule(t, "egress", rule.To, rule.Ports, ownerLabels))
	}
	assertInternalRulePairs(t, got, want)
}

func assertInternalIngressRulePairs(
	t *testing.T,
	rules []networkingv1.NetworkPolicyIngressRule,
	ownerLabels map[string]string,
	want []internalRulePair,
) {
	t.Helper()
	got := make([]internalRulePair, 0, len(rules))
	for _, rule := range rules {
		got = append(got, internalRulePairFromRule(t, "ingress", rule.From, rule.Ports, ownerLabels))
	}
	assertInternalRulePairs(t, got, want)
}

func internalRulePairFromRule(
	t *testing.T,
	direction string,
	peers []networkingv1.NetworkPolicyPeer,
	ports []networkingv1.NetworkPolicyPort,
	ownerLabels map[string]string,
) internalRulePair {
	t.Helper()
	if len(peers) != 1 || peers[0].NamespaceSelector != nil || peers[0].PodSelector == nil {
		t.Fatalf("%s rule peers = %#v, want one same-namespace pod peer", direction, peers)
	}
	if len(ports) != 1 || ports[0].Protocol == nil || ports[0].Port == nil {
		t.Fatalf("%s rule ports = %#v, want one explicit protocol/port", direction, ports)
	}
	wantPeerLabels := copyLabels(ownerLabels)
	peerContainer := peers[0].PodSelector.MatchLabels[containerNameLabel]
	wantPeerLabels[containerNameLabel] = peerContainer
	assertLabelMap(t, direction+" peer selector", peers[0].PodSelector.MatchLabels, wantPeerLabels)
	return internalRulePair{
		PeerContainer: peerContainer,
		Protocol:      *ports[0].Protocol,
		Port:          ports[0].Port.IntValue(),
	}
}

func assertInternalRulePairs(t *testing.T, got, want []internalRulePair) {
	t.Helper()
	sort.Slice(got, func(i, j int) bool {
		if got[i].PeerContainer != got[j].PeerContainer {
			return got[i].PeerContainer < got[j].PeerContainer
		}
		if got[i].Protocol != got[j].Protocol {
			return got[i].Protocol < got[j].Protocol
		}
		return got[i].Port < got[j].Port
	})
	sort.Slice(want, func(i, j int) bool {
		if want[i].PeerContainer != want[j].PeerContainer {
			return want[i].PeerContainer < want[j].PeerContainer
		}
		if want[i].Protocol != want[j].Protocol {
			return want[i].Protocol < want[j].Protocol
		}
		return want[i].Port < want[j].Port
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("internal rule pairs = %#v, want %#v", got, want)
	}
}

func reverseWorkloadContainers(containers []provisioner.WorkloadContainer) []provisioner.WorkloadContainer {
	reversed := append([]provisioner.WorkloadContainer(nil), containers...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	return reversed
}

func reversePolicyContainers(containers []isolation.ContainerRequirement) []isolation.ContainerRequirement {
	reversed := append([]isolation.ContainerRequirement(nil), containers...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	return reversed
}
