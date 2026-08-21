package provisioner

import (
	"context"
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/google/uuid"
)

type RuntimeType string

const RuntimeTypeKubernetes RuntimeType = "KUBERNETES"

var ErrRuntimeUnavailable = errors.New("runtime adapter is unavailable")

// TeamID is the canonical UUID assigned to a team by the scheduler.
type TeamID string

func (id TeamID) Valid() bool {
	parsed, err := uuid.Parse(string(id))
	return err == nil && parsed != uuid.Nil && parsed.String() == string(id)
}

type ResourceLimits struct {
	CPUMillicores       int
	MemoryMiB           int
	EphemeralStorageMiB int
}

type WorkloadContainer struct {
	Name   string
	Image  string
	Ports  []int
	Expose bool
}

type CreateWorkloadCommand struct {
	RequestID      string
	InstanceID     string
	TeamID         TeamID
	RuntimeType    RuntimeType
	TargetID       string
	Containers     []WorkloadContainer
	ResourceLimits ResourceLimits
	PolicyRequest  isolation.Request
	Policy         isolation.ResolvedPolicy
}

type CreateWorkloadResult struct {
	RuntimeWorkloadID string
	NamespaceUID      string
	ServiceURL        string
	Endpoints         []WorkloadEndpoint
}

type WorkloadEndpoint struct {
	ContainerName string
	Port          int
	Protocol      isolation.EndpointProtocol
	ServiceURL    string
}

type CreateWorkloadUseCase interface {
	CreateWorkload(context.Context, CreateWorkloadCommand) (CreateWorkloadResult, error)
}

type UnavailableCreateWorkloadUseCase struct{}

func (UnavailableCreateWorkloadUseCase) CreateWorkload(context.Context, CreateWorkloadCommand) (CreateWorkloadResult, error) {
	return CreateWorkloadResult{}, ErrRuntimeUnavailable
}
