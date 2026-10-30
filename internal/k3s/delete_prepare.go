package k3s

import (
	"context"

	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Remove the stopped workload's controllers and Services before the Namespace
// controller's first sweep. The normal Namespace finalizer remains responsible
// for every other resource, including resources with their own finalizers.
// This is an optional optimization: a target with narrower child-resource RBAC
// can still use the original, preconditioned Namespace deletion below.
func prepareStoppedNamespaceDelete(ctx context.Context, client kubernetes.Interface, binding runtimebinding.Binding) error {
	pods, err := client.CoreV1().Pods(binding.Namespace).List(ctx, metav1.ListOptions{})
	if optionalDeletePreparationUnavailable(err) {
		return nil
	}
	if err != nil {
		return namespaceAPIError(err)
	}
	if len(pods.Items) != 0 {
		return nil
	}
	options := metav1.ListOptions{LabelSelector: "msgctf.io/instance-id=" + binding.InstanceID}
	deployments, err := client.AppsV1().Deployments(binding.Namespace).List(ctx, options)
	if optionalDeletePreparationUnavailable(err) {
		return nil
	}
	if err != nil {
		return namespaceAPIError(err)
	}
	for _, item := range deployments.Items {
		if namespaceOwnedByBinding(item.Labels, binding) && (item.Spec.Replicas == nil || *item.Spec.Replicas != 0) {
			return nil
		}
	}
	replicaSets, err := client.AppsV1().ReplicaSets(binding.Namespace).List(ctx, options)
	if optionalDeletePreparationUnavailable(err) {
		return nil
	}
	if err != nil {
		return namespaceAPIError(err)
	}
	for _, item := range replicaSets.Items {
		if namespaceOwnedByBinding(item.Labels, binding) && (item.Spec.Replicas == nil || *item.Spec.Replicas != 0) {
			return nil
		}
	}
	services, err := client.CoreV1().Services(binding.Namespace).List(ctx, options)
	if optionalDeletePreparationUnavailable(err) {
		return nil
	}
	if err != nil {
		return namespaceAPIError(err)
	}

	type item struct {
		metadata metav1.Object
		remove   func(context.Context, string, metav1.DeleteOptions) error
	}
	items := make([]item, 0, len(deployments.Items)+len(replicaSets.Items)+len(services.Items))
	for i := range deployments.Items {
		items = append(items, item{&deployments.Items[i], client.AppsV1().Deployments(binding.Namespace).Delete})
	}
	for i := range replicaSets.Items {
		items = append(items, item{&replicaSets.Items[i], client.AppsV1().ReplicaSets(binding.Namespace).Delete})
	}
	for i := range services.Items {
		items = append(items, item{&services.Items[i], client.CoreV1().Services(binding.Namespace).Delete})
	}
	for _, object := range items {
		meta := object.metadata
		if !namespaceOwnedByBinding(meta.GetLabels(), binding) || meta.GetUID() == "" || meta.GetResourceVersion() == "" || meta.GetDeletionTimestamp() != nil {
			continue
		}
		current, err := client.CoreV1().Namespaces().Get(ctx, binding.Namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return namespaceAPIError(err)
		}
		if err := namespaceBindingError(current, binding); err != nil {
			return err
		}
		uid, version := meta.GetUID(), meta.GetResourceVersion()
		background := metav1.DeletePropagationBackground
		err = object.remove(ctx, meta.GetName(), metav1.DeleteOptions{
			PropagationPolicy: &background,
			Preconditions:     &metav1.Preconditions{UID: &uid, ResourceVersion: &version},
		})
		if optionalDeletePreparationUnavailable(err) {
			return nil
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return namespaceAPIError(err)
		}
	}
	return nil
}

func optionalDeletePreparationUnavailable(err error) bool {
	return apierrors.IsForbidden(err) || apierrors.IsMethodNotSupported(err) || apierrors.IsNotFound(err) || apierrors.IsConflict(err)
}
