package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	OutboundMode        string               `json:"outbound_mode"`
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

type ChallengeRef struct {
	ChallengeID string `json:"challenge_id"`
	Version     string `json:"version"`
}

type ProfileRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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
	RequestID           string          `json:"request_id"`
	InstanceID          string          `json:"instance_id"`
	TeamID              int64           `json:"team_id"`
	ChallengeRef        ChallengeRef    `json:"challenge_ref"`
	IsolationRef        ProfileRef      `json:"isolation_ref"`
	ResourceProfileRef  ProfileRef      `json:"resource_profile_ref"`
	Target              RuntimeTarget   `json:"target"`
	Workload            RuntimeWorkload `json:"workload"`
	policyFieldsPresent bool
}

func (request *CreateWorkloadRequest) UnmarshalJSON(data []byte) error {
	type wireRequest CreateWorkloadRequest
	var decoded wireRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*request = CreateWorkloadRequest(decoded)
	request.policyFieldsPresent = hasPolicyFieldPresence(data)
	return nil
}

func hasPolicyFieldPresence(data []byte) bool {
	var topLevel map[string]json.RawMessage
	if json.Unmarshal(data, &topLevel) != nil {
		return false
	}
	if hasAnyJSONKey(topLevel, "challenge_ref", "isolation_ref", "resource_profile_ref") {
		return true
	}

	var workload map[string]json.RawMessage
	workloadJSON, _ := jsonField(topLevel, "workload")
	if json.Unmarshal(workloadJSON, &workload) != nil {
		return false
	}
	if hasAnyJSONKey(workload, "outbound_mode", "internal_connections") {
		return true
	}

	var containers []json.RawMessage
	containersJSON, _ := jsonField(workload, "containers")
	if json.Unmarshal(containersJSON, &containers) != nil {
		return false
	}
	for _, rawContainer := range containers {
		var container map[string]json.RawMessage
		if json.Unmarshal(rawContainer, &container) != nil {
			continue
		}
		if hasAnyJSONKey(container, "run_as_user", "writable_paths") {
			return true
		}
	}
	return false
}

func hasAnyJSONKey(fields map[string]json.RawMessage, names ...string) bool {
	for key := range fields {
		for _, name := range names {
			if strings.EqualFold(key, name) {
				return true
			}
		}
	}
	return false
}

func jsonField(fields map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	for key, value := range fields {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
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
	request.applyLegacyPolicyDefaults(containers)
	if err := request.validateIsolation(containers); err != nil {
		return err
	}
	return nil
}

func (request *CreateWorkloadRequest) applyLegacyPolicyDefaults(containers []provisioner.WorkloadContainer) {
	if !request.usesLegacyPolicyContract() {
		return
	}
	request.ChallengeRef = ChallengeRef{ChallengeID: "legacy", Version: "v1"}
	request.IsolationRef = ProfileRef{Name: "STANDARD", Version: "v1"}
	request.Workload.OutboundMode = string(isolation.OutboundNone)
	if len(containers) == 1 {
		request.ResourceProfileRef = ProfileRef{Name: "SMALL_SINGLE", Version: "v1"}
		request.Workload.ResourceLimits = ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128}
	} else {
		request.ResourceProfileRef = ProfileRef{Name: "SMALL_MULTI", Version: "v1"}
		request.Workload.ResourceLimits = ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256}
	}
	for index := range request.Workload.Containers {
		request.Workload.Containers[index].RunAsUser = 10001
	}
}

func (request CreateWorkloadRequest) usesLegacyPolicyContract() bool {
	if request.policyFieldsPresent || request.ChallengeRef != (ChallengeRef{}) || request.IsolationRef != (ProfileRef{}) ||
		request.ResourceProfileRef != (ProfileRef{}) || request.Workload.OutboundMode != "" ||
		len(request.Workload.InternalConnections) != 0 {
		return false
	}
	for _, container := range request.Workload.Containers {
		if container.RunAsUser != 0 || len(container.WritablePaths) != 0 {
			return false
		}
	}
	return true
}

func (request CreateWorkloadRequest) ToCommand() provisioner.CreateWorkloadCommand {
	containers, _ := request.normalizedContainers()
	return provisioner.CreateWorkloadCommand{
		RequestID:  request.RequestID,
		InstanceID: request.InstanceID,
		TeamID:     request.TeamID,
		ChallengeRef: provisioner.ChallengeRef{
			ChallengeID: request.ChallengeRef.ChallengeID,
			Version:     request.ChallengeRef.Version,
		},
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

func (request CreateWorkloadRequest) validateIsolation(containers []provisioner.WorkloadContainer) error {
	if strings.TrimSpace(request.ChallengeRef.ChallengeID) == "" || strings.TrimSpace(request.ChallengeRef.Version) == "" {
		return fmt.Errorf("challenge_ref challenge_id and version are required")
	}
	if !validProfileRef(request.IsolationRef) {
		return fmt.Errorf("isolation_ref name and version are required")
	}
	if !validProfileRef(request.ResourceProfileRef) {
		return fmt.Errorf("resource_profile_ref name and version are required")
	}
	if request.Workload.OutboundMode != string(isolation.OutboundNone) &&
		request.Workload.OutboundMode != string(isolation.OutboundPublicInternet) {
		return fmt.Errorf("outbound_mode must be NONE or PUBLIC_INTERNET")
	}

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
		ChallengeID:         request.ChallengeRef.ChallengeID,
		IsolationRef:        isolation.ProfileRef{Name: request.IsolationRef.Name, Version: request.IsolationRef.Version},
		ResourceRef:         isolation.ProfileRef{Name: request.ResourceProfileRef.Name, Version: request.ResourceProfileRef.Version},
		Containers:          requirements,
		InternalConnections: connections,
		OutboundMode:        isolation.OutboundMode(request.Workload.OutboundMode),
		ResourceLimits: isolation.ResourceLimits{
			CPUMillicores:       request.Workload.ResourceLimits.CPUMillicores,
			MemoryMiB:           request.Workload.ResourceLimits.MemoryMiB,
			EphemeralStorageMiB: request.Workload.ResourceLimits.EphemeralStorageMiB,
		},
	}
}

func unresolvedPolicy(request isolation.Request) isolation.ResolvedPolicy {
	return isolation.ResolvedPolicy{
		ChallengeID:         request.ChallengeID,
		IsolationRef:        request.IsolationRef,
		ResourceRef:         request.ResourceRef,
		Containers:          request.Containers,
		InternalConnections: request.InternalConnections,
		OutboundMode:        request.OutboundMode,
		ResourceLimits:      request.ResourceLimits,
	}
}

func validProfileRef(ref ProfileRef) bool {
	return strings.TrimSpace(ref.Name) != "" && strings.TrimSpace(ref.Version) != ""
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
