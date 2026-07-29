package provisioner

import (
	"context"
	"errors"
)

type RuntimeType string

const RuntimeTypeKubernetes RuntimeType = "KUBERNETES"

var ErrRuntimeUnavailable = errors.New("runtime adapter is unavailable")

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
	TeamID         int64
	RuntimeType    RuntimeType
	TargetID       string
	Containers     []WorkloadContainer
	ResourceLimits ResourceLimits
}

type CreateWorkloadResult struct {
	RuntimeWorkloadID string
	ServiceURL        string
	Endpoints         []WorkloadEndpoint
}

type WorkloadEndpoint struct {
	ContainerName string
	Port          int
	ServiceURL    string
}

type CreateWorkloadUseCase interface {
	CreateWorkload(context.Context, CreateWorkloadCommand) (CreateWorkloadResult, error)
}

type UnavailableCreateWorkloadUseCase struct{}

func (UnavailableCreateWorkloadUseCase) CreateWorkload(context.Context, CreateWorkloadCommand) (CreateWorkloadResult, error) {
	return CreateWorkloadResult{}, ErrRuntimeUnavailable
}
