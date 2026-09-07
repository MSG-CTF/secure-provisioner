package k3s

import (
	"sort"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const namespaceNameLabel = "kubernetes.io/metadata.name"

type approvedInternalConnection struct {
	source      string
	destination string
	protocol    corev1.Protocol
	port        int
}

func buildNetworkPolicies(
	cluster Cluster,
	namespace string,
	ownerLabels map[string]string,
	containers []provisioner.WorkloadContainer,
	policy isolation.ResolvedPolicy,
	policyContainers map[string]isolation.ContainerRequirement,
) ([]*networkingv1.NetworkPolicy, bool) {
	connections, valid := approvedInternalConnections(policy.InternalConnections, policyContainers)
	if !valid {
		return nil, false
	}

	policies := []*networkingv1.NetworkPolicy{
		{
			ObjectMeta: networkPolicyMetadata("default-deny-all", namespace, ownerLabels),
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{},
				Egress:  []networkingv1.NetworkPolicyEgressRule{},
			},
		},
		buildDNSNetworkPolicy(cluster.Config.SecurityCapabilities, namespace, ownerLabels),
	}

	exposedNames := make([]string, 0, len(containers))
	for _, container := range containers {
		if len(container.PublicPorts()) > 0 {
			exposedNames = append(exposedNames, container.Name)
		}
	}
	sort.Strings(exposedNames)
	for _, name := range exposedNames {
		policies = append(policies, buildPublicIngressNetworkPolicy(
			cluster.Config.ExposureMode,
			cluster.Config.SecurityCapabilities,
			namespace,
			ownerLabels,
			policyContainers[name],
		))
	}

	connectionsBySource := make(map[string][]approvedInternalConnection)
	connectionsByDestination := make(map[string][]approvedInternalConnection)
	for _, connection := range connections {
		connectionsBySource[connection.source] = append(connectionsBySource[connection.source], connection)
		connectionsByDestination[connection.destination] = append(connectionsByDestination[connection.destination], connection)
	}
	for _, source := range sortedConnectionGroupNames(connectionsBySource) {
		policies = append(policies, buildInternalEgressNetworkPolicy(
			namespace,
			ownerLabels,
			source,
			connectionsBySource[source],
		))
	}
	for _, destination := range sortedConnectionGroupNames(connectionsByDestination) {
		policies = append(policies, buildInternalIngressNetworkPolicy(
			namespace,
			ownerLabels,
			destination,
			connectionsByDestination[destination],
		))
	}
	return policies, true
}

func buildDNSNetworkPolicy(
	capabilities SecurityCapabilities,
	namespace string,
	ownerLabels map[string]string,
) *networkingv1.NetworkPolicy {
	udp := corev1.ProtocolUDP
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt(53)
	return &networkingv1.NetworkPolicy{
		ObjectMeta: networkPolicyMetadata("allow-dns", namespace, ownerLabels),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: copyLabels(ownerLabels)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: namespaceSelector(capabilities.DNSNamespace),
					PodSelector:       &metav1.LabelSelector{MatchLabels: copyLabels(capabilities.DNSPodSelector)},
				}},
				Ports: []networkingv1.NetworkPolicyPort{
					{Protocol: &udp, Port: &port},
					{Protocol: &tcp, Port: &port},
				},
			}},
		},
	}
}

func buildPublicIngressNetworkPolicy(
	exposureMode ExposureMode,
	capabilities SecurityCapabilities,
	namespace string,
	ownerLabels map[string]string,
	requirement isolation.ContainerRequirement,
) *networkingv1.NetworkPolicy {
	from := []networkingv1.NetworkPolicyPeer{{
		NamespaceSelector: namespaceSelector(capabilities.IngressNamespace),
		PodSelector:       &metav1.LabelSelector{MatchLabels: copyLabels(capabilities.IngressPodSelector)},
	}}
	if exposureMode == ExposureModeNodePort {
		from = nil
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: networkPolicyMetadata("allow-public-ingress-"+requirement.Name, namespace, ownerLabels),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: containerSelector(ownerLabels, requirement.Name),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  from,
				Ports: tcpNetworkPolicyPorts(requirement.PublicPorts()),
			}},
		},
	}
}

func buildInternalEgressNetworkPolicy(
	namespace string,
	ownerLabels map[string]string,
	source string,
	connections []approvedInternalConnection,
) *networkingv1.NetworkPolicy {
	rules := make([]networkingv1.NetworkPolicyEgressRule, 0, len(connections))
	for _, connection := range connections {
		rules = append(rules, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{
				PodSelector: labelSelectorPointer(containerSelector(ownerLabels, connection.destination)),
			}},
			Ports: []networkingv1.NetworkPolicyPort{networkPolicyPort(connection.protocol, connection.port)},
		})
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: networkPolicyMetadata("allow-internal-egress-"+source, namespace, ownerLabels),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: containerSelector(ownerLabels, source),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      rules,
		},
	}
}

func buildInternalIngressNetworkPolicy(
	namespace string,
	ownerLabels map[string]string,
	destination string,
	connections []approvedInternalConnection,
) *networkingv1.NetworkPolicy {
	rules := make([]networkingv1.NetworkPolicyIngressRule, 0, len(connections))
	for _, connection := range connections {
		rules = append(rules, networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{{
				PodSelector: labelSelectorPointer(containerSelector(ownerLabels, connection.source)),
			}},
			Ports: []networkingv1.NetworkPolicyPort{networkPolicyPort(connection.protocol, connection.port)},
		})
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: networkPolicyMetadata("allow-internal-ingress-"+destination, namespace, ownerLabels),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: containerSelector(ownerLabels, destination),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     rules,
		},
	}
}

func approvedInternalConnections(
	requested []isolation.InternalConnection,
	containers map[string]isolation.ContainerRequirement,
) ([]approvedInternalConnection, bool) {
	connections := make([]approvedInternalConnection, 0, len(requested))
	seen := make(map[isolation.InternalConnection]struct{}, len(requested))
	for _, connection := range requested {
		if connection.Protocol != isolation.ProtocolTCP || !validContainerPort(connection.Port) {
			return nil, false
		}
		if _, found := containers[connection.SourceContainer]; !found {
			return nil, false
		}
		destination, found := containers[connection.DestinationContainer]
		if !found || !containsPort(destination.Ports, connection.Port) {
			return nil, false
		}
		if _, duplicate := seen[connection]; duplicate {
			return nil, false
		}
		seen[connection] = struct{}{}
		connections = append(connections, approvedInternalConnection{
			source:      connection.SourceContainer,
			destination: connection.DestinationContainer,
			protocol:    corev1.ProtocolTCP,
			port:        connection.Port,
		})
	}
	sort.Slice(connections, func(first, second int) bool {
		left := connections[first]
		right := connections[second]
		if left.source != right.source {
			return left.source < right.source
		}
		if left.destination != right.destination {
			return left.destination < right.destination
		}
		if left.protocol != right.protocol {
			return left.protocol < right.protocol
		}
		return left.port < right.port
	})
	return connections, true
}

func networkPolicyMetadata(name, namespace string, ownerLabels map[string]string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: copyLabels(ownerLabels)}
}

func namespaceSelector(namespace string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{namespaceNameLabel: namespace}}
}

func containerSelector(ownerLabels map[string]string, container string) metav1.LabelSelector {
	labels := copyLabels(ownerLabels)
	labels[containerNameLabel] = container
	return metav1.LabelSelector{MatchLabels: labels}
}

func labelSelectorPointer(selector metav1.LabelSelector) *metav1.LabelSelector {
	return &selector
}

func tcpNetworkPolicyPorts(ports []int) []networkingv1.NetworkPolicyPort {
	sortedPorts := append([]int(nil), ports...)
	sort.Ints(sortedPorts)
	result := make([]networkingv1.NetworkPolicyPort, 0, len(sortedPorts))
	for _, port := range sortedPorts {
		result = append(result, networkPolicyPort(corev1.ProtocolTCP, port))
	}
	return result
}

func networkPolicyPort(protocol corev1.Protocol, port int) networkingv1.NetworkPolicyPort {
	portValue := intstr.FromInt(port)
	protocolValue := protocol
	return networkingv1.NetworkPolicyPort{Protocol: &protocolValue, Port: &portValue}
}

func containsPort(ports []int, wanted int) bool {
	for _, port := range ports {
		if port == wanted {
			return true
		}
	}
	return false
}

func sortedConnectionGroupNames(groups map[string][]approvedInternalConnection) []string {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
