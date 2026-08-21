package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
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
	Image               string               `json:"image,omitempty"`
	ContainerPort       int                  `json:"container_port,omitempty"`
	Containers          []RuntimeContainer   `json:"containers,omitempty"`
	InternalConnections []InternalConnection `json:"internal_connections,omitempty"`
	ResourceLimits      ResourceLimits       `json:"resource_limits"`
}

type RuntimeContainer struct {
	Name          string         `json:"name"`
	Image         string         `json:"image"`
	Ports         []int          `json:"ports"`
	Expose        bool           `json:"expose"`
	RunAsUser     int64          `json:"run_as_user"`
	WritablePaths []WritablePath `json:"writable_paths,omitempty"`
}

type WritablePath struct {
	Path    string `json:"path"`
	SizeMiB int    `json:"size_mib"`
}

type InternalConnection struct {
	SourceContainer      string `json:"source_container"`
	DestinationContainer string `json:"destination_container"`
	Protocol             string `json:"protocol"`
	Port                 int    `json:"port"`
}

type ResourceLimits struct {
	CPUMillicores       int `json:"cpu_millicores"`
	MemoryMiB           int `json:"memory_mib"`
	EphemeralStorageMiB int `json:"ephemeral_storage_mib"`
}

type CreateWorkloadRequest struct {
	RequestID        string             `json:"request_id"`
	InstanceID       string             `json:"instance_id"`
	TeamID           provisioner.TeamID `json:"team_id"`
	IsolationProfile string             `json:"isolation_profile"`
	Target           RuntimeTarget      `json:"target"`
	Workload         RuntimeWorkload    `json:"workload"`
}

func (request *CreateWorkloadRequest) UnmarshalJSON(data []byte) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	type wireRequest CreateWorkloadRequest
	var decoded wireRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*request = CreateWorkloadRequest(decoded)
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request must contain one JSON value")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make([]string, 0)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object field name must be a string")
			}
			for _, existing := range seen {
				if strings.EqualFold(existing, key) {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
			}
			seen = append(seen, key)
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

type CreateWorkloadResponse struct {
	RuntimeWorkloadID string                     `json:"runtime_workload_id"`
	ServiceURL        string                     `json:"service_url"`
	Endpoints         []WorkloadEndpointResponse `json:"endpoints"`
}

func (request *CreateWorkloadRequest) Validate() error {
	if strings.TrimSpace(request.RequestID) == "" {
		return fmt.Errorf("request_id is required")
	}
	if !isUUID(request.InstanceID) {
		return fmt.Errorf("instance_id must be a UUID")
	}
	if !request.TeamID.Valid() {
		return fmt.Errorf("team_id must be a canonical UUID")
	}
	if request.IsolationProfile != string(isolation.WorkloadProfileWeb) &&
		request.IsolationProfile != string(isolation.WorkloadProfilePwn) {
		return fmt.Errorf("isolation_profile must be WEB or PWN")
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
	if err := request.validateIsolation(containers); err != nil {
		return err
	}
	if _, err := isolation.NewStaticResolver().Resolve(request.toPolicyRequest(containers)); err != nil {
		return fmt.Errorf("isolation profile requirements are invalid")
	}
	return nil
}

func (request CreateWorkloadRequest) ToCommand() provisioner.CreateWorkloadCommand {
	containers, _ := request.normalizedContainers()
	return provisioner.CreateWorkloadCommand{
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
		PolicyRequest: request.toPolicyRequest(containers),
		Policy:        unresolvedPolicy(request.toPolicyRequest(containers)),
	}
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
		if !validImmutableImageReference(request.Workload.Image) {
			return nil, fmt.Errorf("image must be pinned to a lowercase sha256 digest")
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
		if !validImmutableImageReference(container.Image) {
			return nil, fmt.Errorf("container image must be pinned to a lowercase sha256 digest")
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

func validImmutableImageReference(value string) bool {
	name, digest, found := strings.Cut(value, "@sha256:")
	if !found || name == "" || len(digest) != 64 || strings.Contains(name, "@") {
		return false
	}
	if name != strings.ToLower(name) || strings.ContainsAny(name, " \t\r\n") {
		return false
	}
	lastSlash := strings.LastIndex(name, "/")
	if strings.Contains(name[lastSlash+1:], ":") {
		return false
	}
	for _, character := range digest {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (request CreateWorkloadRequest) validateIsolation(containers []provisioner.WorkloadContainer) error {
	portsByContainer := make(map[string]map[int]struct{}, len(containers))
	for index, container := range containers {
		runAsUser := int64(10001)
		var writablePaths []WritablePath
		if len(request.Workload.Containers) > 0 {
			runAsUser = request.Workload.Containers[index].RunAsUser
			writablePaths = request.Workload.Containers[index].WritablePaths
		}
		if runAsUser <= 0 {
			return fmt.Errorf("run_as_user must be a non-root UID")
		}
		seenPaths := make([]string, 0, len(writablePaths))
		for _, writable := range writablePaths {
			if writable.SizeMiB <= 0 || writable.Path == "" || !strings.HasPrefix(writable.Path, "/") ||
				path.Clean(writable.Path) != writable.Path || writable.Path == "/" {
				return fmt.Errorf("writable path must be absolute and size_mib must be positive")
			}
			for _, existing := range seenPaths {
				if nestedHTTPPath(existing, writable.Path) {
					return fmt.Errorf("writable paths must not overlap")
				}
			}
			seenPaths = append(seenPaths, writable.Path)
		}
		ports := make(map[int]struct{}, len(container.Ports))
		for _, port := range container.Ports {
			ports[port] = struct{}{}
		}
		portsByContainer[container.Name] = ports
	}
	for _, connection := range request.Workload.InternalConnections {
		if connection.Protocol != string(isolation.ProtocolTCP) {
			return fmt.Errorf("internal connection protocol must be TCP")
		}
		if _, exists := portsByContainer[connection.SourceContainer]; !exists {
			return fmt.Errorf("internal connection source container does not exist")
		}
		destinationPorts, exists := portsByContainer[connection.DestinationContainer]
		if !exists {
			return fmt.Errorf("internal connection destination container does not exist")
		}
		if _, exists := destinationPorts[connection.Port]; !exists {
			return fmt.Errorf("internal connection destination port does not exist")
		}
	}
	return nil
}

func (request CreateWorkloadRequest) toPolicyRequest(containers []provisioner.WorkloadContainer) isolation.Request {
	requirements := make([]isolation.ContainerRequirement, len(containers))
	for index, container := range containers {
		runAsUser := int64(10001)
		var writablePaths []WritablePath
		if len(request.Workload.Containers) > 0 {
			runAsUser = request.Workload.Containers[index].RunAsUser
			writablePaths = request.Workload.Containers[index].WritablePaths
		}
		requirements[index] = isolation.ContainerRequirement{
			Name:          container.Name,
			Ports:         append([]int(nil), container.Ports...),
			Expose:        container.Expose,
			RunAsUser:     runAsUser,
			WritablePaths: make([]isolation.WritablePath, len(writablePaths)),
		}
		for pathIndex, writable := range writablePaths {
			requirements[index].WritablePaths[pathIndex] = isolation.WritablePath{Path: writable.Path, SizeMiB: writable.SizeMiB}
		}
	}
	connections := make([]isolation.InternalConnection, len(request.Workload.InternalConnections))
	for index, connection := range request.Workload.InternalConnections {
		connections[index] = isolation.InternalConnection{
			SourceContainer:      connection.SourceContainer,
			DestinationContainer: connection.DestinationContainer,
			Protocol:             isolation.Protocol(connection.Protocol),
			Port:                 connection.Port,
		}
	}
	return isolation.Request{
		WorkloadProfile:     isolation.WorkloadProfile(request.IsolationProfile),
		Containers:          requirements,
		InternalConnections: connections,
		ResourceLimits: isolation.ResourceLimits{
			CPUMillicores:       request.Workload.ResourceLimits.CPUMillicores,
			MemoryMiB:           request.Workload.ResourceLimits.MemoryMiB,
			EphemeralStorageMiB: request.Workload.ResourceLimits.EphemeralStorageMiB,
		},
	}
}

func unresolvedPolicy(request isolation.Request) isolation.ResolvedPolicy {
	return isolation.ResolvedPolicy{
		IsolationRef:        isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
		WorkloadProfileRef:  isolation.ProfileRef{Name: string(request.WorkloadProfile), Version: "v1"},
		Containers:          request.Containers,
		InternalConnections: request.InternalConnections,
		OutboundMode:        isolation.OutboundNone,
		ResourceLimits:      request.ResourceLimits,
	}
}

func nestedHTTPPath(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+"/") || strings.HasPrefix(second, first+"/")
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}

func NewCreateWorkloadResponse(result provisioner.CreateWorkloadResult) CreateWorkloadResponse {
	response := CreateWorkloadResponse{
		RuntimeWorkloadID: result.RuntimeWorkloadID,
		ServiceURL:        result.ServiceURL,
		Endpoints:         make([]WorkloadEndpointResponse, 0, len(result.Endpoints)),
	}
	for _, endpoint := range result.Endpoints {
		response.Endpoints = append(response.Endpoints, newWorkloadEndpointResponse(endpoint))
	}
	return response
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
