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
	workloadProfileRef, err := workloadProfileRef(request.WorkloadProfile)
	if err != nil {
		return ResolvedPolicy{}, err
	}
	runtimeClassName, endpointProtocol, exposureRequirement, err := resolveWorkloadProfile(workloadProfileRef)
	if err != nil {
		return ResolvedPolicy{}, err
	}
	if request.ResourceLimits.CPUMillicores <= 0 || request.ResourceLimits.MemoryMiB <= 0 ||
		request.ResourceLimits.EphemeralStorageMiB <= 0 {
		return ResolvedPolicy{}, rejected("resource limits must be positive")
	}
	if err := validateContainers(request.Containers, request.ResourceLimits); err != nil {
		return ResolvedPolicy{}, err
	}
	if err := validateWorkloadProfile(workloadProfileRef, request.Containers); err != nil {
		return ResolvedPolicy{}, err
	}
	if request.InternalConnections != nil {
		return ResolvedPolicy{}, rejected("internal connections are no longer accepted")
	}

	return ResolvedPolicy{
		IsolationRef:        ProfileRef{Name: "STANDARD", Version: "v2"},
		WorkloadProfileRef:  workloadProfileRef,
		RuntimeClassName:    runtimeClassName,
		EndpointProtocol:    endpointProtocol,
		ExposureRequirement: exposureRequirement,
		Baseline: Baseline{
			AutomountServiceAccountToken: false,
			RunAsNonRoot:                 true,
			ReadOnlyRootFilesystem:       true,
			AllowPrivilegeEscalation:     false,
			Privileged:                   false,
			DropAllCapabilities:          true,
			SeccompRuntimeDefault:        true,
		},
		Containers:     cloneContainerRequirements(request.Containers),
		OutboundMode:   OutboundNone,
		ResourceLimits: request.ResourceLimits,
	}, nil
}

func workloadProfileRef(profile WorkloadProfile) (ProfileRef, error) {
	switch profile {
	case WorkloadProfileWeb, WorkloadProfilePwn:
		return ProfileRef{Name: string(profile), Version: "v1"}, nil
	default:
		return ProfileRef{}, rejected("unsupported workload profile")
	}
}

func resolveWorkloadProfile(ref ProfileRef) (string, EndpointProtocol, ExposureRequirement, error) {
	switch ref {
	case ProfileRef{Name: "WEB", Version: "v1"}:
		return "", EndpointProtocolHTTP, ExposureAnySupported, nil
	case ProfileRef{Name: "PWN", Version: "v1"}:
		return "gvisor", EndpointProtocolTCP, ExposureNodePortOnly, nil
	default:
		return "", "", "", rejected("unsupported workload profile")
	}
}

func validateContainers(containers []ContainerRequirement, limits ResourceLimits) error {
	if len(containers) == 0 {
		return rejected("at least one container is required")
	}
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
		if !ValidPublicPorts(container.Ports, container.Expose, container.ExposedPorts) {
			return rejected("invalid public port selection")
		}

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

func validateWorkloadProfile(ref ProfileRef, containers []ContainerRequirement) error {
	exposedContainers := 0
	for _, container := range containers {
		if len(container.PublicPorts()) > 0 {
			exposedContainers++
			if ref == (ProfileRef{Name: "PWN", Version: "v1"}) && len(container.Ports) != 1 {
				return rejected("Pwn workload must expose exactly one port")
			}
		}
		if ref == (ProfileRef{Name: "PWN", Version: "v1"}) {
			for _, writable := range container.WritablePaths {
				if writable.Path != "/tmp" && !strings.HasPrefix(writable.Path, "/tmp/") {
					return rejected("Pwn writable path must be under /tmp")
				}
			}
		}
	}

	if ref == (ProfileRef{Name: "PWN", Version: "v1"}) {
		if exposedContainers != 1 {
			return rejected("Pwn workload must expose exactly one container")
		}
		return nil
	}
	if exposedContainers == 0 {
		return rejected("Web workload must expose at least one container")
	}
	return nil
}

func validWritablePath(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "/" {
		return false
	}
	for _, reserved := range []string{"/proc", "/sys", "/dev", "/var/run/secrets"} {
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
		if container.ExposedPorts != nil {
			cloned[index].ExposedPorts = append([]int{}, container.ExposedPorts...)
		}
		cloned[index].WritablePaths = append([]WritablePath(nil), container.WritablePaths...)
	}
	return cloned
}

func rejected(message string) error {
	return fmt.Errorf("%w: %s", ErrPolicyRejected, message)
}
