package k3s

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	resourceName       = "challenge"
	specHashAnnotation = "msgctf.io/spec-hash"
)

type ResourceSet struct {
	Namespace         *corev1.Namespace
	Deployment        *appsv1.Deployment
	Service           *corev1.Service
	Ingress           *networkingv1.Ingress
	ExpectedSpecHash  string
	RuntimeWorkloadID string
	ServiceURL        string
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
	if !validWorkloadCommand(cluster, command) {
		return ResourceSet{}, newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}

	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		return ResourceSet{}, newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}
	specHash, err := createCommandSpecHash(command)
	if err != nil {
		return ResourceSet{}, newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}
	labels := ownershipLabels(command)
	podLabels := copyLabels(labels)
	containerPort := int32(command.ContainerPort)
	replicas := int32(1)
	quantities := resourceList(command.ResourceLimits)
	pathType := networkingv1.PathTypePrefix

	resources := ResourceSet{
		Namespace: &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: copyLabels(labels)},
		},
		Deployment: &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:        resourceName,
				Namespace:   namespace,
				Labels:      copyLabels(labels),
				Annotations: map[string]string{specHashAnnotation: specHash},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: copyLabels(podLabels)},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels:      podLabels,
						Annotations: map[string]string{specHashAnnotation: specHash},
					},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name:  resourceName,
						Image: command.Image,
						Ports: []corev1.ContainerPort{{ContainerPort: containerPort}},
						Resources: corev1.ResourceRequirements{
							Requests: quantities,
							Limits:   quantities.DeepCopy(),
						},
					}}},
				},
			},
		},
		Service: &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: namespace, Labels: copyLabels(labels)},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeClusterIP,
				Selector: copyLabels(podLabels),
				Ports: []corev1.ServicePort{{
					Name:       "http",
					Port:       containerPort,
					TargetPort: intstr.FromInt(command.ContainerPort),
				}},
			},
		},
		Ingress: &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: namespace, Labels: copyLabels(labels)},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{
					IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
						Path:     "/instances/" + command.InstanceID,
						PathType: &pathType,
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
							Name: resourceName,
							Port: networkingv1.ServiceBackendPort{Number: containerPort},
						}},
					}}}},
				}},
			},
		},
		ExpectedSpecHash: specHash,
	}
	if cluster.Config.IngressClass != "" {
		resources.Ingress.Spec.IngressClassName = &cluster.Config.IngressClass
	}
	resources.RuntimeWorkloadID = RuntimeWorkloadID(command.TargetID, namespace)
	resources.ServiceURL = strings.TrimRight(cluster.Config.PublicGateway, "/") + "/instances/" + command.InstanceID
	return resources, nil
}

func createCommandSpecHash(command provisioner.CreateWorkloadCommand) (string, error) {
	spec := struct {
		InstanceID     string                  `json:"instance_id"`
		TeamID         int64                   `json:"team_id"`
		RuntimeType    provisioner.RuntimeType `json:"runtime_type"`
		TargetID       string                  `json:"target_id"`
		Image          string                  `json:"image"`
		ContainerPort  int                     `json:"container_port"`
		ResourceLimits struct {
			CPUMillicores       int `json:"cpu_millicores"`
			MemoryMiB           int `json:"memory_mib"`
			EphemeralStorageMiB int `json:"ephemeral_storage_mib"`
		} `json:"resource_limits"`
	}{
		InstanceID:    command.InstanceID,
		TeamID:        command.TeamID,
		RuntimeType:   command.RuntimeType,
		TargetID:      command.TargetID,
		Image:         command.Image,
		ContainerPort: command.ContainerPort,
	}
	spec.ResourceLimits.CPUMillicores = command.ResourceLimits.CPUMillicores
	spec.ResourceLimits.MemoryMiB = command.ResourceLimits.MemoryMiB
	spec.ResourceLimits.EphemeralStorageMiB = command.ResourceLimits.EphemeralStorageMiB

	encoded, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validWorkloadCommand(cluster Cluster, command provisioner.CreateWorkloadCommand) bool {
	return strings.TrimSpace(cluster.Config.TargetID) != "" &&
		command.TargetID == cluster.Config.TargetID &&
		strings.TrimSpace(command.Image) != "" &&
		command.ContainerPort >= 1 && command.ContainerPort <= 65535 &&
		command.ResourceLimits.CPUMillicores > 0 &&
		command.ResourceLimits.MemoryMiB > 0 &&
		int64(command.ResourceLimits.MemoryMiB) <= math.MaxInt64/(1024*1024) &&
		command.ResourceLimits.EphemeralStorageMiB > 0 &&
		int64(command.ResourceLimits.EphemeralStorageMiB) <= math.MaxInt64/(1024*1024) &&
		command.TeamID > 0 &&
		command.RuntimeType == provisioner.RuntimeTypeKubernetes &&
		strings.TrimSpace(cluster.Config.PublicGateway) != ""
}

func ownershipLabels(command provisioner.CreateWorkloadCommand) map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by": "secure-provisioner",
		"app.kubernetes.io/name":       resourceName,
		"msgctf.io/instance-id":        command.InstanceID,
		"msgctf.io/team-id":            strconv.FormatInt(command.TeamID, 10),
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
