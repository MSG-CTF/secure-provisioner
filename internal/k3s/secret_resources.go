package k3s

import (
	"context"
	"sort"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const environmentSecretName = "challenge-env"

func addSecretResources(ctx context.Context, resources *ResourceSet, command provisioner.CreateWorkloadCommand, resolver SecretResolver) error {
	data := make(map[string][]byte)
	for _, container := range command.Containers {
		if container.FlagFilePath != "" && (!container.RequiresFlag || !provisioner.ValidFlagFilePath(container.FlagFilePath)) {
			return newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
		}
		if container.SecretRef == "" {
			if container.RequiresFlag {
				return newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
			}
			continue
		}
		if resolver == nil {
			return newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
		}
		values, err := resolver.Resolve(ctx, container.SecretRef, container.Name, container.Image)
		if err != nil {
			return err
		}
		if len(values) == 0 || provisioner.ValidateEnvironment(values, true) != nil ||
			len(values)+len(container.Env) > provisioner.MaxEnvironmentEntries {
			return newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
		}
		if flag, found := values["FLAG"]; container.RequiresFlag && (!found || strings.TrimSpace(flag) == "" || strings.ContainsAny(flag, "\r\n")) {
			return newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
		}
		total := 0
		for name, value := range container.Env {
			total += len(name) + len(value)
		}
		names := make([]string, 0, len(values))
		for name, value := range values {
			if _, collision := container.Env[name]; collision {
				return newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
			}
			total += len(name) + len(value)
			names = append(names, name)
		}
		if total > 16384 {
			return newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
		}
		sort.Strings(names)
		matched := false
		for _, deployment := range resources.Deployments {
			if deployment.Name != container.Name {
				continue
			}
			matched = true
			for _, name := range names {
				key := container.Name + "." + name
				data[key] = []byte(values[name])
				deployment.Spec.Template.Spec.Containers[0].Env = append(
					deployment.Spec.Template.Spec.Containers[0].Env,
					corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: environmentSecretName}, Key: key,
					}}},
				)
			}
			if container.FlagFilePath != "" {
				// Project only this container's FLAG; other resolved secrets stay env-only.
				pod := &deployment.Spec.Template.Spec
				group := *pod.SecurityContext.RunAsGroup
				pod.SecurityContext.FSGroup = &group
				mode := int32(0440)
				pod.Volumes = append(pod.Volumes, corev1.Volume{
					Name: "backend-flag",
					VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
						SecretName: environmentSecretName, DefaultMode: &mode,
						Items: []corev1.KeyToPath{{Key: container.Name + ".FLAG", Path: "flag"}},
					}},
				})
				pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts, corev1.VolumeMount{
					Name: "backend-flag", MountPath: container.FlagFilePath, SubPath: "flag", ReadOnly: true,
				})
			}
		}
		if !matched {
			return newRuntimeError("SECRET_RESOLUTION_FAILED", false, nil)
		}
	}
	if len(data) == 0 {
		return nil
	}
	immutable := true
	resources.EnvSecret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: environmentSecretName, Namespace: resources.Namespace.Name, Labels: copyLabels(resources.Namespace.Labels)},
		Type:       corev1.SecretTypeOpaque, Data: data, Immutable: &immutable,
	}
	resources.ResourceQuota.Spec.Hard[corev1.ResourceName("count/secrets")] = countQuantity(1)
	return nil
}
