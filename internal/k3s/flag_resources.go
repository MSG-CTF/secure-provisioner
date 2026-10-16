package k3s

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const flagSecretName = "challenge-env"

func addFlagResources(resources *ResourceSet, command provisioner.CreateWorkloadCommand, catalog *FlagCatalog) error {
	if resources == nil {
		return errors.New("FLAG resource set is missing")
	}
	if catalog == nil {
		return nil
	}
	data := make(map[string][]byte)
	for _, container := range command.Containers {
		flag, found := catalog.Flag(container.Image)
		if !found {
			continue
		}
		matched := false
		for _, deployment := range resources.Deployments {
			if deployment.Name != container.Name {
				continue
			}
			matched = true
			deployment.Spec.Template.Spec.Containers[0].Env = append(
				deployment.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{Name: "FLAG", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: flagSecretName}, Key: container.Name,
				}}},
			)
			oldHash := resources.ExpectedSpecHashes[deployment.Name]
			newHash := sha256.Sum256([]byte(oldHash + "\x00FLAG:" + flagSecretName + "/" + container.Name))
			hash := hex.EncodeToString(newHash[:])
			deployment.Annotations[specHashAnnotation] = hash
			deployment.Spec.Template.Annotations[specHashAnnotation] = hash
			resources.ExpectedSpecHashes[deployment.Name] = hash
			if resources.Deployment == deployment {
				resources.ExpectedSpecHash = hash
			}
			break
		}
		if !matched {
			return errors.New("FLAG container is missing from resource set")
		}
		data[container.Name] = []byte(flag)
	}
	if len(data) == 0 {
		return nil
	}
	immutable := true
	resources.FlagSecret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: flagSecretName, Namespace: resources.Namespace.Name,
			Labels: copyLabels(resources.Namespace.Labels),
		},
		Type: corev1.SecretTypeOpaque, Data: data, Immutable: &immutable,
	}
	resources.ResourceQuota.Spec.Hard[corev1.ResourceName("count/secrets")] = countQuantity(1)
	return nil
}
