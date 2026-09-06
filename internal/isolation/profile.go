package isolation

type ProfileRef struct {
	Name    string
	Version string
}

type WorkloadProfile string

const (
	WorkloadProfileWeb WorkloadProfile = "WEB"
	WorkloadProfilePwn WorkloadProfile = "PWN"
)

type Baseline struct {
	AutomountServiceAccountToken bool
	RunAsNonRoot                 bool
	ReadOnlyRootFilesystem       bool
	AllowPrivilegeEscalation     bool
	Privileged                   bool
	DropAllCapabilities          bool
	SeccompRuntimeDefault        bool
}

type ResourceLimits struct {
	CPUMillicores       int
	MemoryMiB           int
	EphemeralStorageMiB int
}

type WritablePath struct {
	Path    string
	SizeMiB int
}

type ContainerRequirement struct {
	Name          string
	Ports         []int
	Expose        bool
	RunAsUser     int64
	WritablePaths []WritablePath
	ExposedPorts  []int `json:",omitempty"`
}

func (container ContainerRequirement) PublicPorts() []int {
	if container.ExposedPorts != nil {
		return container.ExposedPorts
	}
	if container.Expose {
		return container.Ports
	}
	return nil
}

// ValidPublicPorts also rejects ambiguous internal representations.
func ValidPublicPorts(ports []int, expose bool, exposedPorts []int) bool {
	if expose && exposedPorts != nil {
		return false
	}
	allowed := make(map[int]bool, len(ports))
	for _, port := range ports {
		allowed[port] = true
	}
	for _, port := range exposedPorts {
		if port < 1 || port > 65535 || !allowed[port] {
			return false
		}
		allowed[port] = false
	}
	return true
}

type EndpointProtocol string

const (
	EndpointProtocolHTTP EndpointProtocol = "HTTP"
	EndpointProtocolTCP  EndpointProtocol = "TCP"
)

type ExposureRequirement string

const (
	ExposureAnySupported ExposureRequirement = "ANY_SUPPORTED"
	ExposureNodePortOnly ExposureRequirement = "NODE_PORT_ONLY"
)

type Protocol string

const ProtocolTCP Protocol = "TCP"

type InternalConnection struct {
	SourceContainer      string
	DestinationContainer string
	Protocol             Protocol
	Port                 int
}

type OutboundMode string

const (
	OutboundNone OutboundMode = "NONE"
)

type Request struct {
	WorkloadProfile     WorkloadProfile
	Containers          []ContainerRequirement
	InternalConnections []InternalConnection
	ResourceLimits      ResourceLimits
}

type ResolvedPolicy struct {
	IsolationRef        ProfileRef
	WorkloadProfileRef  ProfileRef
	Baseline            Baseline
	RuntimeClassName    string
	EndpointProtocol    EndpointProtocol
	ExposureRequirement ExposureRequirement
	Containers          []ContainerRequirement
	InternalConnections []InternalConnection
	OutboundMode        OutboundMode
	ResourceLimits      ResourceLimits
}
