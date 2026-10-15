package isolation

import (
	"slices"
	"strings"
)

type NetworkMode string

const NetworkModeExplicitTCPV1 NetworkMode = "EXPLICIT_TCP_V1"

// WorkloadNetwork is an operator-owned snapshot, never a Create JSON field.
// The image identities keep queued operations tied to the reviewed digest set.
type WorkloadNetwork struct {
	ID               string            `json:"id"`
	Mode             NetworkMode       `json:"mode"`
	IsolationProfile WorkloadProfile   `json:"isolation_profile"`
	Containers       []NetworkIdentity `json:"containers"`
	Allow            []NetworkEdge     `json:"allow"`
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
	return &clone
}

// ValidateWorkloadNetwork checks the complete name/port set and directed
// edges. The image identities are checked against reviewed policies at
// admission and against the saved command at Kubernetes application.
func ValidateWorkloadNetwork(graph *WorkloadNetwork, profile WorkloadProfile, requirements []ContainerRequirement) error {
	if graph == nil {
		return nil
	}
	if !validNetworkID(graph.ID) || graph.Mode != NetworkModeExplicitTCPV1 || graph.IsolationProfile != profile || len(graph.Containers) == 0 || len(graph.Containers) != len(requirements) || graph.Allow == nil {
		return rejected("invalid workload network identity or mode")
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
	return nil
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
