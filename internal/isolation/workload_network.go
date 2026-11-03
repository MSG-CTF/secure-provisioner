package isolation

import (
	"net/netip"
	"slices"
	"strings"
)

type NetworkMode string

const NetworkModeExplicitTCPV1 NetworkMode = "EXPLICIT_TCP_V1"
const NetworkModePeerGroupsV1 NetworkMode = "PEER_GROUPS_V1"

// WorkloadNetwork is an operator-owned snapshot, never a Create JSON field.
// The image identities keep queued operations tied to the reviewed digest set.
type WorkloadNetwork struct {
	ID               string             `json:"id"`
	Mode             NetworkMode        `json:"mode"`
	IsolationProfile WorkloadProfile    `json:"isolation_profile"`
	Containers       []NetworkIdentity  `json:"containers"`
	Allow            []NetworkEdge      `json:"allow"`
	PeerGroups       []NetworkPeerGroup `json:"peer_groups"`
	Egress           []NetworkEgress    `json:"egress"`
}

type NetworkIdentity struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Ports []int  `json:"ports"`
}

type NetworkEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Port int    `json:"port"`
}

type NetworkPeerGroup struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// NetworkEgress permits only TCP to an operator-reviewed exact host.
type NetworkEgress struct {
	From  string `json:"from"`
	CIDR  string `json:"cidr"`
	Ports []int  `json:"ports"`
}

func CloneWorkloadNetwork(graph *WorkloadNetwork) *WorkloadNetwork {
	if graph == nil {
		return nil
	}
	clone := *graph
	clone.Containers = slices.Clone(graph.Containers)
	for index := range clone.Containers {
		clone.Containers[index].Ports = slices.Clone(graph.Containers[index].Ports)
	}
	clone.Allow = slices.Clone(graph.Allow)
	clone.PeerGroups = slices.Clone(graph.PeerGroups)
	for index := range clone.PeerGroups {
		clone.PeerGroups[index].Members = slices.Clone(graph.PeerGroups[index].Members)
	}
	clone.Egress = slices.Clone(graph.Egress)
	for index := range clone.Egress {
		clone.Egress[index].Ports = slices.Clone(graph.Egress[index].Ports)
	}
	return &clone
}

// ValidateWorkloadNetwork checks the complete name/port set, mode-specific
// peer permissions and exact-host egress. Image identities are checked against
// reviewed policies at admission and the saved command at Kubernetes application.
func ValidateWorkloadNetwork(graph *WorkloadNetwork, profile WorkloadProfile, requirements []ContainerRequirement) error {
	if graph == nil {
		return nil
	}
	if !validNetworkID(graph.ID) || graph.IsolationProfile != profile || len(graph.Containers) == 0 || len(graph.Containers) != len(requirements) {
		return rejected("invalid workload network identity or mode")
	}
	switch graph.Mode {
	case NetworkModeExplicitTCPV1:
		if graph.Allow == nil || graph.PeerGroups != nil {
			return rejected("explicit TCP networks require allow and cannot contain peer groups")
		}
	case NetworkModePeerGroupsV1:
		if graph.Allow != nil {
			return rejected("peer group networks cannot contain directed TCP edges")
		}
	default:
		return rejected("unsupported workload network mode")
	}
	approved := make(map[string]ContainerRequirement, len(requirements))
	for _, requirement := range requirements {
		approved[requirement.Name] = requirement
	}
	seenNames := make(map[string]struct{}, len(graph.Containers))
	for _, identity := range graph.Containers {
		requirement, found := approved[identity.Name]
		if !found || !sameNetworkPorts(identity.Ports, requirement.Ports) || !validNetworkImage(identity.Image) {
			return rejected("workload network container identity does not match")
		}
		if _, duplicate := seenNames[identity.Name]; duplicate {
			return rejected("duplicate workload network container")
		}
		seenNames[identity.Name] = struct{}{}
	}
	seenEdges := make(map[NetworkEdge]struct{}, len(graph.Allow))
	for _, edge := range graph.Allow {
		destination, exists := approved[edge.To]
		if _, sourceExists := approved[edge.From]; !sourceExists || !exists || edge.From == edge.To || !slices.Contains(destination.Ports, edge.Port) {
			return rejected("invalid workload network edge")
		}
		if _, duplicate := seenEdges[edge]; duplicate {
			return rejected("duplicate workload network edge")
		}
		seenEdges[edge] = struct{}{}
	}
	seenGroups := make(map[string]struct{}, len(graph.PeerGroups))
	for _, group := range graph.PeerGroups {
		if !validNetworkID(group.Name) || len(group.Members) == 0 {
			return rejected("invalid workload peer group")
		}
		if _, duplicate := seenGroups[group.Name]; duplicate {
			return rejected("duplicate workload peer group")
		}
		seenGroups[group.Name] = struct{}{}
		seenMembers := make(map[string]struct{}, len(group.Members))
		for _, member := range group.Members {
			if _, known := approved[member]; !known {
				return rejected("unknown workload peer group member")
			}
			if _, duplicate := seenMembers[member]; duplicate {
				return rejected("duplicate workload peer group member")
			}
			seenMembers[member] = struct{}{}
		}
	}
	type egressPort struct {
		source, cidr string
		port         int
	}
	seenEgress := make(map[egressPort]struct{})
	for _, rule := range graph.Egress {
		if _, known := approved[rule.From]; !known || !validNetworkEgressHost(rule.CIDR) || len(rule.Ports) == 0 {
			return rejected("invalid workload egress source or destination")
		}
		for _, port := range rule.Ports {
			if port < 1 || port > 65535 {
				return rejected("invalid workload egress TCP port")
			}
			key := egressPort{rule.From, rule.CIDR, port}
			if _, duplicate := seenEgress[key]; duplicate {
				return rejected("duplicate workload egress TCP port")
			}
			seenEgress[key] = struct{}{}
		}
	}
	return nil
}

var invalidNetworkEgressRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
}

func validNetworkEgressHost(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.String() != value || prefix.Bits() != prefix.Addr().BitLen() {
		return false
	}
	address := prefix.Addr()
	if address.Is4In6() || !address.IsGlobalUnicast() {
		return false
	}
	for _, blocked := range invalidNetworkEgressRanges {
		if blocked.Contains(address) {
			return false
		}
	}
	return true
}

func sameNetworkPorts(first, second []int) bool {
	if len(first) == 0 || len(first) != len(second) {
		return false
	}
	a := slices.Clone(first)
	b := slices.Clone(second)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func validNetworkID(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	for i, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		if c != '-' || i == 0 || i == len(value)-1 {
			return false
		}
	}
	return true
}

func validNetworkImage(image string) bool {
	name, digest, found := strings.Cut(image, "@sha256:")
	if !found || name == "" || len(digest) != 64 || strings.ContainsAny(name, "@ \t\r\n") || name != strings.ToLower(name) {
		return false
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
