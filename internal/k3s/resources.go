package k3s

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	resourceName        = "challenge"
	containerNameLabel  = "msgctf.io/container-name"
	specHashAnnotation  = "msgctf.io/spec-hash"
	instancePathSegment = "/instances/"
)

type ResourceSet struct {
	Namespace          *corev1.Namespace
	ServiceAccount     *corev1.ServiceAccount
	ResourceQuota      *corev1.ResourceQuota
	LimitRange         *corev1.LimitRange
	NetworkPolicies    []*networkingv1.NetworkPolicy
	Deployments        []*appsv1.Deployment
	Services           []*corev1.Service
	Ingress            *networkingv1.Ingress
	ExpectedSpecHashes map[string]string
	RuntimeWorkloadID  string
	ServiceURL         string
	Endpoints          []provisioner.WorkloadEndpoint

	// Deprecated single-resource aliases are retained until the Adapter is
	// migrated to iterate over Deployments and Services.
	Deployment       *appsv1.Deployment
	Service          *corev1.Service
	ExpectedSpecHash string
}

func NamespaceForInstance(instanceID string) (string, error) {
	if !isUUID(instanceID) {
		return "", errors.New("invalid instance ID")
	}
	return "ctf-" + strings.ReplaceAll(strings.ToLower(instanceID), "-", ""), nil
}

func RuntimeWorkloadID(targetID, namespace string) string {
	return targetID + "/" + namespace + "/" + resourceName
}

func BuildResourceSet(cluster Cluster, command provisioner.CreateWorkloadCommand) (ResourceSet, error) {
	containers := normalizedCommandContainers(command)
	if !validWorkloadCommand(cluster, command, containers) {
		return ResourceSet{}, newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}
	policyContainers, validPolicy := validateResolvedPolicy(command, containers)
	if !validPolicy {
		return ResourceSet{}, newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}
	if err := cluster.Supports(command.Policy); err != nil {
		return ResourceSet{}, err
	}

	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		return ResourceSet{}, newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}
	labels := ownershipLabels(command)
	networkPolicies, validNetworkPolicies := buildNetworkPolicies(
		cluster,
		namespace,
		labels,
		containers,
		command.Policy,
		policyContainers,
	)
	if !validNetworkPolicies {
		return ResourceSet{}, newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}
	pathType := networkingv1.PathTypePrefix
	replicas := int32(1)
	resources := ResourceSet{
		Namespace: &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: copyLabels(labels)},
		},
		ServiceAccount:     buildRuntimeServiceAccount(namespace, labels),
		ResourceQuota:      buildRuntimeResourceQuota(namespace, labels, command.Policy, len(containers), nodePortQuota(cluster.Config.ExposureMode, containers)),
		LimitRange:         buildRuntimeLimitRange(namespace, labels, command.Policy, len(containers)),
		NetworkPolicies:    networkPolicies,
		Deployments:        make([]*appsv1.Deployment, 0, len(containers)),
		Services:           make([]*corev1.Service, 0, len(containers)),
		ExpectedSpecHashes: make(map[string]string, len(containers)),
		Endpoints:          make([]provisioner.WorkloadEndpoint, 0),
	}
	if cluster.Config.ExposureMode != ExposureModeNodePort {
		resources.Ingress = &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: namespace, Labels: copyLabels(labels)},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{}},
					},
				}},
			},
		}
		if cluster.Config.IngressClass != "" {
			resources.Ingress.Spec.IngressClassName = &cluster.Config.IngressClass
		}
	}

	for index, container := range containers {
		requirement := policyContainers[container.Name]
		limits := distributedResourceLimits(resolvedResourceLimits(command.Policy.ResourceLimits), len(containers), index)
		specHash, hashErr := createContainerSpecHash(command, container, requirement, limits)
		if hashErr != nil {
			return ResourceSet{}, newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
		}
		containerLabels := copyLabels(labels)
		containerLabels[containerNameLabel] = container.Name
		podLabels := copyLabels(containerLabels)
		quantities := resourceList(limits)
		containerPorts := make([]corev1.ContainerPort, 0, len(requirement.Ports))
		servicePorts := make([]corev1.ServicePort, 0, len(requirement.Ports))
		for _, port := range requirement.Ports {
			containerPorts = append(containerPorts, corev1.ContainerPort{ContainerPort: int32(port)})
			servicePorts = append(servicePorts, corev1.ServicePort{
				Name:       fmt.Sprintf("port-%d", port),
				Port:       int32(port),
				TargetPort: intstr.FromInt(port),
			})
		}

		podContainer := corev1.Container{
			Name:            container.Name,
			Image:           container.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Ports:           containerPorts,
			Resources: corev1.ResourceRequirements{
				Requests: quantities,
				Limits:   quantities.DeepCopy(),
			},
		}
		podSpec := corev1.PodSpec{Containers: []corev1.Container{podContainer}}
		applyPodSecurityBaseline(&podSpec, &podSpec.Containers[0], requirement)
		if command.Policy.RuntimeClassName != "" {
			runtimeClassName := command.Policy.RuntimeClassName
			podSpec.RuntimeClassName = &runtimeClassName
		}
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:        container.Name,
				Namespace:   namespace,
				Labels:      copyLabels(containerLabels),
				Annotations: map[string]string{specHashAnnotation: specHash},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas:             &replicas,
				Strategy:             appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
				RevisionHistoryLimit: int32Pointer(1),
				Selector:             &metav1.LabelSelector{MatchLabels: copyLabels(podLabels)},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels:      podLabels,
						Annotations: map[string]string{specHashAnnotation: specHash},
					},
					Spec: podSpec,
				},
			},
		}
		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      container.Name,
				Namespace: namespace,
				Labels:    copyLabels(containerLabels),
			},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeClusterIP,
				Selector: copyLabels(podLabels),
				Ports:    servicePorts,
			},
		}
		if container.Expose && cluster.Config.ExposureMode == ExposureModeNodePort {
			service.Spec.Type = corev1.ServiceTypeNodePort
			service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
		}
		resources.Deployments = append(resources.Deployments, deployment)
		resources.Services = append(resources.Services, service)
		resources.ExpectedSpecHashes[container.Name] = specHash

		if container.Expose && cluster.Config.ExposureMode != ExposureModeNodePort {
			for _, port := range requirement.Ports {
				path := instancePathSegment + command.InstanceID
				if len(resources.Endpoints) > 0 {
					path += "/" + container.Name + "/" + strconv.Itoa(port)
				}
				resources.Ingress.Spec.Rules[0].HTTP.Paths = append(
					resources.Ingress.Spec.Rules[0].HTTP.Paths,
					networkingv1.HTTPIngressPath{
						Path:     path,
						PathType: &pathType,
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
							Name: container.Name,
							Port: networkingv1.ServiceBackendPort{Number: int32(port)},
						}},
					},
				)
				resources.Endpoints = append(resources.Endpoints, provisioner.WorkloadEndpoint{
					ContainerName: container.Name,
					Port:          port,
					Protocol:      isolation.EndpointProtocolHTTP,
					ServiceURL:    strings.TrimRight(cluster.Config.PublicGateway, "/") + path,
				})
			}
		}
	}

	resources.RuntimeWorkloadID = RuntimeWorkloadID(command.TargetID, namespace)
	if len(resources.Endpoints) > 0 {
		resources.ServiceURL = resources.Endpoints[0].ServiceURL
	}
	resources.Deployment = resources.Deployments[0]
	resources.Service = resources.Services[0]
	resources.ExpectedSpecHash = resources.ExpectedSpecHashes[resources.Deployment.Name]
	return resources, nil
}

func BuildNodePortEndpoints(
	publicGateway string,
	protocol isolation.EndpointProtocol,
	services []*corev1.Service,
) ([]provisioner.WorkloadEndpoint, error) {
	if protocol != isolation.EndpointProtocolHTTP && protocol != isolation.EndpointProtocolTCP {
		return nil, newRuntimeError("RESOURCE_APPLY_FAILED", false, nil)
	}
	gateway, err := url.Parse(publicGateway)
	if err != nil || gateway.Scheme == "" || gateway.Hostname() == "" {
		return nil, newRuntimeError("RESOURCE_APPLY_FAILED", true, err)
	}

	endpoints := make([]provisioner.WorkloadEndpoint, 0)
	for _, service := range services {
		if service == nil || service.Spec.Type != corev1.ServiceTypeNodePort {
			continue
		}
		containerName := service.Labels[containerNameLabel]
		if containerName == "" {
			containerName = service.Name
		}
		for _, port := range service.Spec.Ports {
			if port.NodePort <= 0 {
				return nil, newRuntimeError("RESOURCE_APPLY_FAILED", true, nil)
			}
			endpointURL := *gateway
			if protocol == isolation.EndpointProtocolTCP {
				endpointURL.Scheme = "tcp"
			}
			endpointURL.Host = net.JoinHostPort(gateway.Hostname(), strconv.Itoa(int(port.NodePort)))
			endpoints = append(endpoints, provisioner.WorkloadEndpoint{
				ContainerName: containerName,
				Port:          int(port.Port),
				Protocol:      protocol,
				ServiceURL:    endpointURL.String(),
			})
		}
	}
	if len(endpoints) == 0 {
		return nil, newRuntimeError("RESOURCE_APPLY_FAILED", true, nil)
	}
	return endpoints, nil
}

func normalizedCommandContainers(command provisioner.CreateWorkloadCommand) []provisioner.WorkloadContainer {
	return command.Containers
}

func nodePortQuota(mode ExposureMode, containers []provisioner.WorkloadContainer) int {
	if mode != ExposureModeNodePort {
		return 0
	}
	count := 0
	for _, container := range containers {
		if container.Expose {
			count += len(container.Ports)
		}
	}
	return count
}

func distributedResourceLimits(total provisioner.ResourceLimits, count, index int) provisioner.ResourceLimits {
	return provisioner.ResourceLimits{
		CPUMillicores:       distributedValue(total.CPUMillicores, count, index),
		MemoryMiB:           distributedValue(total.MemoryMiB, count, index),
		EphemeralStorageMiB: distributedValue(total.EphemeralStorageMiB, count, index),
	}
}

func distributedValue(total, count, index int) int {
	value := total / count
	if index < total%count {
		value++
	}
	return value
}

func createContainerSpecHash(
	command provisioner.CreateWorkloadCommand,
	container provisioner.WorkloadContainer,
	requirement isolation.ContainerRequirement,
	limits provisioner.ResourceLimits,
) (string, error) {
	spec := struct {
		InstanceID          string                         `json:"instance_id"`
		TeamID              provisioner.TeamID             `json:"team_id"`
		RuntimeType         provisioner.RuntimeType        `json:"runtime_type"`
		TargetID            string                         `json:"target_id"`
		Container           provisioner.WorkloadContainer  `json:"container"`
		Requirement         isolation.ContainerRequirement `json:"requirement"`
		IsolationRef        isolation.ProfileRef           `json:"isolation_ref"`
		WorkloadProfileRef  isolation.ProfileRef           `json:"workload_profile_ref"`
		RuntimeClassName    string                         `json:"runtime_class_name"`
		EndpointProtocol    isolation.EndpointProtocol     `json:"endpoint_protocol"`
		ExposureRequirement isolation.ExposureRequirement  `json:"exposure_requirement"`
		Baseline            isolation.Baseline             `json:"baseline"`
		ResourceLimits      provisioner.ResourceLimits     `json:"resource_limits"`
	}{
		InstanceID:          command.InstanceID,
		TeamID:              command.TeamID,
		RuntimeType:         command.RuntimeType,
		TargetID:            command.TargetID,
		Container:           container,
		Requirement:         requirement,
		IsolationRef:        command.Policy.IsolationRef,
		WorkloadProfileRef:  command.Policy.WorkloadProfileRef,
		RuntimeClassName:    command.Policy.RuntimeClassName,
		EndpointProtocol:    command.Policy.EndpointProtocol,
		ExposureRequirement: command.Policy.ExposureRequirement,
		Baseline:            command.Policy.Baseline,
		ResourceLimits:      limits,
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func resolvedResourceLimits(limits isolation.ResourceLimits) provisioner.ResourceLimits {
	return provisioner.ResourceLimits{
		CPUMillicores:       limits.CPUMillicores,
		MemoryMiB:           limits.MemoryMiB,
		EphemeralStorageMiB: limits.EphemeralStorageMiB,
	}
}

func validWorkloadCommand(
	cluster Cluster,
	command provisioner.CreateWorkloadCommand,
	containers []provisioner.WorkloadContainer,
) bool {
	if strings.TrimSpace(cluster.Config.TargetID) == "" ||
		command.TargetID != cluster.Config.TargetID ||
		!command.TeamID.Valid() ||
		command.RuntimeType != provisioner.RuntimeTypeKubernetes ||
		strings.TrimSpace(cluster.Config.PublicGateway) == "" ||
		len(containers) == 0 ||
		command.ResourceLimits.CPUMillicores < len(containers) ||
		command.ResourceLimits.MemoryMiB < len(containers) ||
		command.ResourceLimits.EphemeralStorageMiB < len(containers) ||
		int64(command.ResourceLimits.MemoryMiB) > math.MaxInt64/(1024*1024) ||
		int64(command.ResourceLimits.EphemeralStorageMiB) > math.MaxInt64/(1024*1024) {
		return false
	}

	names := make(map[string]struct{}, len(containers))
	hasExposed := false
	for _, container := range containers {
		if len(validation.IsDNS1123Label(container.Name)) > 0 ||
			strings.TrimSpace(container.Image) == "" ||
			len(container.Ports) == 0 {
			return false
		}
		if _, exists := names[container.Name]; exists {
			return false
		}
		names[container.Name] = struct{}{}
		ports := make(map[int]struct{}, len(container.Ports))
		for _, port := range container.Ports {
			if !validContainerPort(port) {
				return false
			}
			if _, exists := ports[port]; exists {
				return false
			}
			ports[port] = struct{}{}
		}
		hasExposed = hasExposed || container.Expose
	}
	return hasExposed
}

func validContainerPort(port int) bool {
	return port >= 1 && port <= 65535
}

func ownershipLabels(command provisioner.CreateWorkloadCommand) map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by": "secure-provisioner",
		"app.kubernetes.io/name":       resourceName,
		"msgctf.io/instance-id":        command.InstanceID,
		"msgctf.io/team-id":            string(command.TeamID),
	}
}

func copyLabels(labels map[string]string) map[string]string {
	copy := make(map[string]string, len(labels))
	for key, value := range labels {
		copy[key] = value
	}
	return copy
}

func resourceList(limits provisioner.ResourceLimits) corev1.ResourceList {
	return corev1.ResourceList{
		corev1.ResourceCPU:              *resource.NewMilliQuantity(int64(limits.CPUMillicores), resource.DecimalSI),
		corev1.ResourceMemory:           *resource.NewQuantity(int64(limits.MemoryMiB)*1024*1024, resource.BinarySI),
		corev1.ResourceEphemeralStorage: *resource.NewQuantity(int64(limits.EphemeralStorageMiB)*1024*1024, resource.BinarySI),
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
