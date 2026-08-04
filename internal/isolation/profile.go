package isolation

type ProfileRef struct {
	Name    string
	Version string
}

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
	RunAsUser     int64
	WritablePaths []WritablePath
}

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
	ChallengeID         string
	IsolationRef        ProfileRef
	ResourceRef         ProfileRef
	Containers          []ContainerRequirement
	InternalConnections []InternalConnection
	OutboundMode        OutboundMode
	ResourceLimits      ResourceLimits
}

type ResolvedPolicy struct {
	ChallengeID         string
	IsolationRef        ProfileRef
	ResourceRef         ProfileRef
	Baseline            Baseline
	Containers          []ContainerRequirement
	InternalConnections []InternalConnection
	OutboundMode        OutboundMode
	ResourceLimits      ResourceLimits
}
