package isolation

import (
	"fmt"
	"path"
	"strings"
)

type StaticResolver struct{}

func NewStaticResolver() *StaticResolver {
	return &StaticResolver{}
}

func (r *StaticResolver) Resolve(request Request) (ResolvedPolicy, error) {
	if r == nil {
		return ResolvedPolicy{}, rejected("resolver is required")
	}
	if request.IsolationRef != (ProfileRef{Name: "STANDARD", Version: "v1"}) {
		return ResolvedPolicy{}, rejected("unsupported isolation profile")
	}

	expectedLimits, err := resourceProfile(request.ResourceRef)
	if err != nil {
		return ResolvedPolicy{}, err
	}
	if request.ResourceLimits != expectedLimits {
		return ResolvedPolicy{}, rejected("resource limits do not match resource profile")
	}
	if strings.TrimSpace(request.ChallengeID) == "" {
		return ResolvedPolicy{}, rejected("challenge ID is required")
	}
	if request.OutboundMode != OutboundNone {
		return ResolvedPolicy{}, rejected("outbound mode is not allowed")
	}
	if err := validateContainers(request.Containers, request.ResourceLimits); err != nil {
		return ResolvedPolicy{}, err
	}
	if err := validateInternalConnections(request.Containers, request.InternalConnections); err != nil {
		return ResolvedPolicy{}, err
	}

	return ResolvedPolicy{
		ChallengeID:  request.ChallengeID,
		IsolationRef: request.IsolationRef,
		ResourceRef:  request.ResourceRef,
		Baseline: Baseline{
			AutomountServiceAccountToken: false,
			RunAsNonRoot:                 true,
			ReadOnlyRootFilesystem:       true,
			AllowPrivilegeEscalation:     false,
			Privileged:                   false,
			DropAllCapabilities:          true,
			SeccompRuntimeDefault:        true,
		},
		Containers:          cloneContainerRequirements(request.Containers),
		InternalConnections: append([]InternalConnection(nil), request.InternalConnections...),
		OutboundMode:        request.OutboundMode,
		ResourceLimits:      request.ResourceLimits,
	}, nil
}

func resourceProfile(ref ProfileRef) (ResourceLimits, error) {
	switch ref {
	case ProfileRef{Name: "SMALL_SINGLE", Version: "v1"}:
		return ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128}, nil
	case ProfileRef{Name: "SMALL_MULTI", Version: "v1"}:
		return ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256}, nil
	default:
		return ResourceLimits{}, rejected("unsupported resource profile")
	}
}

func validateContainers(containers []ContainerRequirement, limits ResourceLimits) error {
	names := make(map[string]map[int]struct{}, len(containers))
	totalWritableMiB := 0
	for _, container := range containers {
		if strings.TrimSpace(container.Name) == "" {
			return rejected("container name is required")
		}
		if _, exists := names[container.Name]; exists {
			return rejected("container names must be unique")
		}
		if container.RunAsUser <= 0 {
			return rejected("container must run as a non-root UID")
		}
		ports := make(map[int]struct{}, len(container.Ports))
		for _, port := range container.Ports {
			if port < 1 || port > 65535 {
				return rejected("container port is invalid")
			}
			if _, exists := ports[port]; exists {
				return rejected("container ports must be unique")
			}
			ports[port] = struct{}{}
		}
		names[container.Name] = ports

		cleanPaths := make([]string, 0, len(container.WritablePaths))
		for _, writable := range container.WritablePaths {
			if writable.SizeMiB <= 0 {
				return rejected("writable path size must be positive")
			}
			if !validWritablePath(writable.Path) {
				return rejected("writable path is not allowed")
			}
			for _, existing := range cleanPaths {
				if nestedPath(existing, writable.Path) {
					return rejected("writable paths must not overlap")
				}
			}
			cleanPaths = append(cleanPaths, writable.Path)
			totalWritableMiB += writable.SizeMiB
		}
	}
	if totalWritableMiB > limits.EphemeralStorageMiB {
		return rejected("writable paths exceed ephemeral storage limit")
	}
	return nil
}

func validateInternalConnections(containers []ContainerRequirement, connections []InternalConnection) error {
	portsByContainer := make(map[string]map[int]struct{}, len(containers))
	hasPortInventory := false
	for _, container := range containers {
		ports := make(map[int]struct{}, len(container.Ports))
		for _, port := range container.Ports {
			ports[port] = struct{}{}
			hasPortInventory = true
		}
		portsByContainer[container.Name] = ports
	}
	for _, connection := range connections {
		if connection.Protocol != ProtocolTCP {
			return rejected("internal connection protocol is not allowed")
		}
		if _, exists := portsByContainer[connection.SourceContainer]; !exists {
			return rejected("internal connection source container does not exist")
		}
		destinationPorts, exists := portsByContainer[connection.DestinationContainer]
		if !exists {
			return rejected("internal connection destination container does not exist")
		}
		if _, exists := destinationPorts[connection.Port]; hasPortInventory && !exists {
			return rejected("internal connection destination port does not exist")
		}
	}
	return nil
}

func validWritablePath(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "/" {
		return false
	}
	for _, reserved := range []string{"/proc", "/sys", "/var/run/secrets"} {
		if value == reserved || strings.HasPrefix(value, reserved+"/") {
			return false
		}
	}
	return true
}

func nestedPath(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+"/") || strings.HasPrefix(second, first+"/")
}

func cloneContainerRequirements(containers []ContainerRequirement) []ContainerRequirement {
	cloned := make([]ContainerRequirement, len(containers))
	for index, container := range containers {
		cloned[index] = container
		cloned[index].Ports = append([]int(nil), container.Ports...)
		cloned[index].WritablePaths = append([]WritablePath(nil), container.WritablePaths...)
	}
	return cloned
}

func rejected(message string) error {
	return fmt.Errorf("%w: %s", ErrPolicyRejected, message)
}
