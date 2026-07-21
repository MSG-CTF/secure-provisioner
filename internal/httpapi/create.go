package httpapi

import (
	"fmt"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type RuntimeType string

const RuntimeTypeKubernetes RuntimeType = "KUBERNETES"

type RuntimeTarget struct {
	RuntimeType RuntimeType `json:"runtime_type"`
	TargetID    string      `json:"target_id"`
}

type RuntimeWorkload struct {
	Image          string         `json:"image"`
	ContainerPort  int            `json:"container_port"`
	ResourceLimits ResourceLimits `json:"resource_limits"`
}

type ResourceLimits struct {
	CPUMillicores       int `json:"cpu_millicores"`
	MemoryMiB           int `json:"memory_mib"`
	EphemeralStorageMiB int `json:"ephemeral_storage_mib"`
}

type CreateWorkloadRequest struct {
	RequestID  string          `json:"request_id"`
	InstanceID string          `json:"instance_id"`
	TeamID     int64           `json:"team_id"`
	Target     RuntimeTarget   `json:"target"`
	Workload   RuntimeWorkload `json:"workload"`
}

type CreateWorkloadResponse struct {
	RuntimeWorkloadID string `json:"runtime_workload_id"`
	ServiceURL        string `json:"service_url"`
}

func (request CreateWorkloadRequest) Validate() error {
	if strings.TrimSpace(request.RequestID) == "" {
		return fmt.Errorf("request_id is required")
	}
	if !isUUID(request.InstanceID) {
		return fmt.Errorf("instance_id must be a UUID")
	}
	if request.TeamID <= 0 {
		return fmt.Errorf("team_id must be positive")
	}
	if request.Target.RuntimeType != RuntimeTypeKubernetes {
		return fmt.Errorf("runtime_type must be %s", RuntimeTypeKubernetes)
	}
	if strings.TrimSpace(request.Target.TargetID) == "" {
		return fmt.Errorf("target_id is required")
	}
	if strings.TrimSpace(request.Workload.Image) == "" {
		return fmt.Errorf("image is required")
	}
	if request.Workload.ContainerPort < 1 || request.Workload.ContainerPort > 65535 {
		return fmt.Errorf("container_port must be between 1 and 65535")
	}
	if request.Workload.ResourceLimits.CPUMillicores <= 0 {
		return fmt.Errorf("cpu_millicores must be positive")
	}
	if request.Workload.ResourceLimits.MemoryMiB <= 0 {
		return fmt.Errorf("memory_mib must be positive")
	}
	if request.Workload.ResourceLimits.EphemeralStorageMiB <= 0 {
		return fmt.Errorf("ephemeral_storage_mib must be positive")
	}
	return nil
}

func (request CreateWorkloadRequest) ToCommand() provisioner.CreateWorkloadCommand {
	return provisioner.CreateWorkloadCommand{
		RequestID:     request.RequestID,
		InstanceID:    request.InstanceID,
		TeamID:        request.TeamID,
		RuntimeType:   provisioner.RuntimeType(request.Target.RuntimeType),
		TargetID:      request.Target.TargetID,
		Image:         request.Workload.Image,
		ContainerPort: request.Workload.ContainerPort,
		ResourceLimits: provisioner.ResourceLimits{
			CPUMillicores:       request.Workload.ResourceLimits.CPUMillicores,
			MemoryMiB:           request.Workload.ResourceLimits.MemoryMiB,
			EphemeralStorageMiB: request.Workload.ResourceLimits.EphemeralStorageMiB,
		},
	}
}

func NewCreateWorkloadResponse(result provisioner.CreateWorkloadResult) CreateWorkloadResponse {
	return CreateWorkloadResponse{
		RuntimeWorkloadID: result.RuntimeWorkloadID,
		ServiceURL:        result.ServiceURL,
	}
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !isHex(character) {
				return false
			}
		}
	}
	return true
}

func isHex(character rune) bool {
	return character >= '0' && character <= '9' ||
		character >= 'a' && character <= 'f' ||
		character >= 'A' && character <= 'F'
}
