package httpapi

import (
	"fmt"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"k8s.io/apimachinery/pkg/util/validation"
)

type RuntimeType string

const RuntimeTypeKubernetes RuntimeType = "KUBERNETES"

type RuntimeTarget struct {
	RuntimeType RuntimeType `json:"runtime_type"`
	TargetID    string      `json:"target_id"`
}

type RuntimeWorkload struct {
	Image          string             `json:"image,omitempty"`
	ContainerPort  int                `json:"container_port,omitempty"`
	Containers     []RuntimeContainer `json:"containers,omitempty"`
	ResourceLimits ResourceLimits     `json:"resource_limits"`
}

type RuntimeContainer struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Ports  []int  `json:"ports"`
	Expose bool   `json:"expose"`
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
	containers, err := request.normalizedContainers()
	if err != nil {
		return err
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
	if request.Workload.ResourceLimits.CPUMillicores < len(containers) ||
		request.Workload.ResourceLimits.MemoryMiB < len(containers) ||
		request.Workload.ResourceLimits.EphemeralStorageMiB < len(containers) {
		return fmt.Errorf("resource limits must provide at least one unit per container")
	}
	return nil
}

func (request CreateWorkloadRequest) ToCommand() provisioner.CreateWorkloadCommand {
	containers, _ := request.normalizedContainers()
	command := provisioner.CreateWorkloadCommand{
		RequestID:   request.RequestID,
		InstanceID:  request.InstanceID,
		TeamID:      request.TeamID,
		RuntimeType: provisioner.RuntimeType(request.Target.RuntimeType),
		TargetID:    request.Target.TargetID,
		Containers:  containers,
		ResourceLimits: provisioner.ResourceLimits{
			CPUMillicores:       request.Workload.ResourceLimits.CPUMillicores,
			MemoryMiB:           request.Workload.ResourceLimits.MemoryMiB,
			EphemeralStorageMiB: request.Workload.ResourceLimits.EphemeralStorageMiB,
		},
	}
	if len(request.Workload.Containers) == 0 {
		command.Image = request.Workload.Image
		command.ContainerPort = request.Workload.ContainerPort
	}
	return command
}

func (request CreateWorkloadRequest) normalizedContainers() ([]provisioner.WorkloadContainer, error) {
	hasContainers := len(request.Workload.Containers) > 0
	hasLegacy := strings.TrimSpace(request.Workload.Image) != "" || request.Workload.ContainerPort != 0
	if hasContainers && hasLegacy {
		return nil, fmt.Errorf("containers cannot be combined with image or container_port")
	}
	if !hasContainers {
		if strings.TrimSpace(request.Workload.Image) == "" {
			return nil, fmt.Errorf("image is required")
		}
		if !validPort(request.Workload.ContainerPort) {
			return nil, fmt.Errorf("container_port must be between 1 and 65535")
		}
		return []provisioner.WorkloadContainer{{
			Name:   "challenge",
			Image:  request.Workload.Image,
			Ports:  []int{request.Workload.ContainerPort},
			Expose: true,
		}}, nil
	}

	containers := make([]provisioner.WorkloadContainer, 0, len(request.Workload.Containers))
	names := make(map[string]struct{}, len(request.Workload.Containers))
	hasExposed := false
	for _, container := range request.Workload.Containers {
		if problems := validation.IsDNS1123Label(container.Name); len(problems) > 0 {
			return nil, fmt.Errorf("container name must be a DNS label")
		}
		if _, exists := names[container.Name]; exists {
			return nil, fmt.Errorf("container names must be unique")
		}
		names[container.Name] = struct{}{}
		if strings.TrimSpace(container.Image) == "" {
			return nil, fmt.Errorf("container image is required")
		}
		if len(container.Ports) == 0 {
			return nil, fmt.Errorf("container ports must not be empty")
		}
		ports := make([]int, 0, len(container.Ports))
		seenPorts := make(map[int]struct{}, len(container.Ports))
		for _, port := range container.Ports {
			if !validPort(port) {
				return nil, fmt.Errorf("container port must be between 1 and 65535")
			}
			if _, exists := seenPorts[port]; exists {
				return nil, fmt.Errorf("container ports must be unique")
			}
			seenPorts[port] = struct{}{}
			ports = append(ports, port)
		}
		hasExposed = hasExposed || container.Expose
		containers = append(containers, provisioner.WorkloadContainer{
			Name: container.Name, Image: container.Image, Ports: ports, Expose: container.Expose,
		})
	}
	if !hasExposed {
		return nil, fmt.Errorf("at least one container must be exposed")
	}
	return containers, nil
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
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
