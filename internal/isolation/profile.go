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
	OutboundNone           OutboundMode = "NONE"
	OutboundPublicInternet OutboundMode = "PUBLIC_INTERNET"
)

type Request struct {
	WorkloadProfile     WorkloadProfile
	Containers          []ContainerRequirement
	InternalConnections []InternalConnection
	ResourceLimits      ResourceLimits
}

type ResolvedPolicy struct {
	ChallengeID         string
	IsolationRef        ProfileRef
	WorkloadProfileRef  ProfileRef
	ResourceRef         ProfileRef
	Baseline            Baseline
	RuntimeClassName    string
	EndpointProtocol    EndpointProtocol
	ExposureRequirement ExposureRequirement
	Containers          []ContainerRequirement
	InternalConnections []InternalConnection
	OutboundMode        OutboundMode
	ResourceLimits      ResourceLimits
}
