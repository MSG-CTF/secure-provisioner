package k3s

import (
	"context"
	"errors"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

// Keep this optional work within the short Gateway cleanup step, including
// targets sharing the client-side API budget with other instances.
const terminatingContentDeletesPerStep = 2

const terminatingContentPreparationBudget = 250 * time.Millisecond

// prepareTerminatingNamespaceContent only touches an already terminating,
// identity-checked namespace with no Pods. Namespace admission therefore fences
// new Pods before isolation controls or credentials can be removed. The normal
// namespace controller remains responsible for finalization and unknown content.
func prepareTerminatingNamespaceContent(ctx context.Context, client kubernetes.Interface, namespace *corev1.Namespace, binding runtimebinding.Binding) (result error) {
	parent := ctx
	ctx, cancel := context.WithTimeout(parent, terminatingContentPreparationBudget)
	defer cancel()
	defer func() {
		// Optional preparation must not exhaust the Gateway step. Falling back
		// leaves the namespace controller in charge; the caller still requires
		// actual namespace absence. Parent cancellation and API errors propagate.
		if parent.Err() == nil && ctx.Err() != nil && errors.Is(result, context.DeadlineExceeded) {
			result = nil
		}
	}()
	if err := namespaceBindingError(namespace, binding); err != nil {
		return err
	}
	if namespace.DeletionTimestamp == nil {
		return nil
	}
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
	type group struct {
		list   func(context.Context) (runtime.Object, error)
		remove func(context.Context, string, metav1.DeleteOptions) error
	}
	groups := []group{
		{func(ctx context.Context) (runtime.Object, error) {
			return client.NetworkingV1().NetworkPolicies(binding.Namespace).List(ctx, options)
		}, client.NetworkingV1().NetworkPolicies(binding.Namespace).Delete},
		{func(ctx context.Context) (runtime.Object, error) {
			return client.CoreV1().Secrets(binding.Namespace).List(ctx, options)
		}, client.CoreV1().Secrets(binding.Namespace).Delete},
		{func(ctx context.Context) (runtime.Object, error) {
			return client.CoreV1().ServiceAccounts(binding.Namespace).List(ctx, options)
		}, client.CoreV1().ServiceAccounts(binding.Namespace).Delete},
		{func(ctx context.Context) (runtime.Object, error) {
			return client.CoreV1().LimitRanges(binding.Namespace).List(ctx, options)
		}, client.CoreV1().LimitRanges(binding.Namespace).Delete},
		{func(ctx context.Context) (runtime.Object, error) {
			return client.CoreV1().ResourceQuotas(binding.Namespace).List(ctx, options)
		}, client.CoreV1().ResourceQuotas(binding.Namespace).Delete},
	}
	deleted := 0
	for _, resource := range groups {
		list, err := resource.list(ctx)
		if optionalDeletePreparationUnavailable(err) {
			return nil
		}
		if err != nil {
			return namespaceAPIError(err)
		}
		objects, err := meta.ExtractList(list)
		if err != nil {
			return namespaceAPIError(err)
		}
		for _, object := range objects {
			metadata, err := meta.Accessor(object)
			if err != nil {
				return namespaceAPIError(err)
			}
			if !namespaceOwnedByBinding(metadata.GetLabels(), binding) || metadata.GetUID() == "" || metadata.GetResourceVersion() == "" || metadata.GetDeletionTimestamp() != nil || len(metadata.GetFinalizers()) != 0 {
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
			if current.DeletionTimestamp == nil {
				return newRuntimeError("RUNTIME_IDENTITY_MISMATCH", false, nil)
			}
			uid, version := metadata.GetUID(), metadata.GetResourceVersion()
			background := metav1.DeletePropagationBackground
			err = resource.remove(ctx, metadata.GetName(), metav1.DeleteOptions{
				PropagationPolicy: &background,
				Preconditions:     &metav1.Preconditions{UID: &uid, ResourceVersion: &version},
			})
			if optionalDeletePreparationUnavailable(err) {
				return nil
			}
			if err != nil {
				return namespaceAPIError(err)
			}
			deleted++
			if deleted == terminatingContentDeletesPerStep {
				return operations.NewProgressPendingError("NAMESPACE_CONTENT_DELETE_PENDING", nil)
			}
		}
	}
	return nil
}
