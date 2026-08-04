package k3s

import (
	"crypto/sha256"
	"encoding/base32"
	"math"
	"path"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const runtimeServiceAccountName = "challenge-runtime"

func validateResolvedPolicy(
	command provisioner.CreateWorkloadCommand,
	containers []provisioner.WorkloadContainer,
) (map[string]isolation.ContainerRequirement, bool) {
	policy := command.Policy
	if policy.ChallengeID == "" ||
		policy.IsolationRef.Name == "" || policy.IsolationRef.Version == "" ||
		policy.ResourceRef.Name == "" || policy.ResourceRef.Version == "" ||
		policy.OutboundMode != isolation.OutboundNone ||
		policy.Baseline != requiredSecurityBaseline() ||
		len(policy.Containers) != len(containers) ||
		policy.ResourceLimits.CPUMillicores != command.ResourceLimits.CPUMillicores ||
		policy.ResourceLimits.MemoryMiB != command.ResourceLimits.MemoryMiB ||
		policy.ResourceLimits.EphemeralStorageMiB != command.ResourceLimits.EphemeralStorageMiB {
		return nil, false
	}

	approved := make(map[string]isolation.ContainerRequirement, len(policy.Containers))
	totalWritableMiB := int64(0)
	totalEphemeralMiB := int64(policy.ResourceLimits.EphemeralStorageMiB)
	for _, requirement := range policy.Containers {
		if requirement.RunAsUser <= 0 {
			return nil, false
		}
		if _, duplicate := approved[requirement.Name]; duplicate {
			return nil, false
		}
		seenPorts := make(map[int]struct{}, len(requirement.Ports))
		for _, port := range requirement.Ports {
			if !validContainerPort(port) {
				return nil, false
			}
			if _, duplicate := seenPorts[port]; duplicate {
				return nil, false
			}
			seenPorts[port] = struct{}{}
		}
		cleanPaths := make([]string, 0, len(requirement.WritablePaths))
		for _, writable := range requirement.WritablePaths {
			if writable.SizeMiB <= 0 || int64(writable.SizeMiB) > math.MaxInt64/(1024*1024) || !safeWritablePath(writable.Path) {
				return nil, false
			}
			for _, existing := range cleanPaths {
				if pathsOverlap(existing, writable.Path) {
					return nil, false
				}
			}
			cleanPaths = append(cleanPaths, writable.Path)
			writableMiB := int64(writable.SizeMiB)
			if writableMiB > totalEphemeralMiB-totalWritableMiB {
				return nil, false
			}
			totalWritableMiB += writableMiB
		}
		approved[requirement.Name] = requirement
	}

	for index, container := range containers {
		requirement, found := approved[container.Name]
		if !found || !samePorts(container.Ports, requirement.Ports) {
			return nil, false
		}
		containerWritableMiB := int64(0)
		for _, writable := range requirement.WritablePaths {
			containerWritableMiB += int64(writable.SizeMiB)
		}
		containerEphemeralMiB := distributedResourceLimits(
			resolvedResourceLimits(policy.ResourceLimits),
			len(containers),
			index,
		).EphemeralStorageMiB
		if containerWritableMiB > int64(containerEphemeralMiB) {
			return nil, false
		}
	}
	return approved, true
}

func requiredSecurityBaseline() isolation.Baseline {
	return isolation.Baseline{
		AutomountServiceAccountToken: false,
		RunAsNonRoot:                 true,
		ReadOnlyRootFilesystem:       true,
		AllowPrivilegeEscalation:     false,
		Privileged:                   false,
		DropAllCapabilities:          true,
		SeccompRuntimeDefault:        true,
	}
}

func safeWritablePath(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "/" {
		return false
	}
	for _, reserved := range []string{"/proc", "/sys", "/var/run/secrets"} {
		if value == reserved || strings.HasPrefix(value, reserved+"/") {
			return false
		}
	}
	return true
}

func pathsOverlap(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+"/") || strings.HasPrefix(second, first+"/")
}

func samePorts(first, second []int) bool {
	if len(first) != len(second) {
		return false
	}
	seen := make(map[int]struct{}, len(first))
	for _, port := range first {
		seen[port] = struct{}{}
	}
	for _, port := range second {
		if _, found := seen[port]; !found {
			return false
		}
	}
	return true
}

func buildRuntimeServiceAccount(namespace string, labels map[string]string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: runtimeServiceAccountName, Namespace: namespace, Labels: copyLabels(labels)},
		AutomountServiceAccountToken: boolPointer(false),
	}
}

func applyPodSecurityBaseline(pod *corev1.PodSpec, container *corev1.Container, requirement isolation.ContainerRequirement) {
	runAsUser := requirement.RunAsUser
	pod.ServiceAccountName = runtimeServiceAccountName
	pod.AutomountServiceAccountToken = boolPointer(false)
	pod.HostNetwork = false
	pod.HostPID = false
	pod.HostIPC = false
	pod.SecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot:   boolPointer(true),
		RunAsUser:      &runAsUser,
		SeccompProfile: runtimeDefaultSeccompProfile(),
	}
	container.SecurityContext = &corev1.SecurityContext{
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		Privileged:               boolPointer(false),
		RunAsUser:                &runAsUser,
		RunAsNonRoot:             boolPointer(true),
		ReadOnlyRootFilesystem:   boolPointer(true),
		AllowPrivilegeEscalation: boolPointer(false),
		SeccompProfile:           runtimeDefaultSeccompProfile(),
	}

	pod.Volumes = make([]corev1.Volume, 0, len(requirement.WritablePaths))
	container.VolumeMounts = make([]corev1.VolumeMount, 0, len(requirement.WritablePaths))
	for _, writable := range requirement.WritablePaths {
		name := writableVolumeName(requirement.Name, writable.Path)
		size := resource.NewQuantity(int64(writable.SizeMiB)*1024*1024, resource.BinarySI)
		pod.Volumes = append(pod.Volumes, corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
				SizeLimit: size,
			}},
		})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: name, MountPath: writable.Path})
	}
}

func writableVolumeName(containerName, mountPath string) string {
	digest := sha256.Sum256([]byte(containerName + "\x00" + mountPath))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])
	return "wp-" + strings.ToLower(encoded)
}

func boolPointer(value bool) *bool {
	return &value
}

func int32Pointer(value int32) *int32 {
	return &value
}

func runtimeDefaultSeccompProfile() *corev1.SeccompProfile {
	return &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
}
