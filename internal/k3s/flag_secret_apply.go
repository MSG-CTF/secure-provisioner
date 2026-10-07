package k3s

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// applyFlagSecret only creates in the newly owned namespace. A failed create
// leaves ownership uncertain, so the caller rolls back the whole namespace.
func applyFlagSecret(ctx context.Context, client kubernetes.Interface, desired *corev1.Secret) error {
	secrets := client.CoreV1().Secrets(desired.Namespace)
	if _, err := secrets.Create(ctx, desired.DeepCopy(), metav1.CreateOptions{}); err != nil {
		return newRuntimeError("RESOURCE_APPLY_FAILED", kubernetesErrorRetryable(err), nil)
	}
	actual, err := secrets.Get(ctx, desired.Name, metav1.GetOptions{})
	if err != nil {
		return newRuntimeError("RESOURCE_APPLY_FAILED", kubernetesErrorRetryable(err), nil)
	}
	if !approvedSemanticMetadata(actual, desired, false) || actual.Type != desired.Type ||
		!apiequality.Semantic.DeepEqual(actual.Immutable, desired.Immutable) ||
		!apiequality.Semantic.DeepEqual(actual.Data, desired.Data) {
		return newRuntimeError("RESOURCE_APPLY_FAILED", false, nil)
	}
	return nil
}
