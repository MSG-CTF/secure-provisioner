package k3s

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

type AdapterConfig struct {
	ReadyTimeout time.Duration
	PollInterval time.Duration
}

type Adapter struct {
	registry *Registry
	config   AdapterConfig
}

func NewAdapter(registry *Registry, config AdapterConfig) (*Adapter, error) {
	if registry == nil || config.ReadyTimeout <= 0 || config.PollInterval <= 0 {
		return nil, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	return &Adapter{registry: registry, config: config}, nil
}

func (a *Adapter) CreateWorkload(ctx context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	if err := ctx.Err(); err != nil {
		return provisioner.CreateWorkloadResult{}, operationCancelledError(err)
	}
	cluster, err := a.registry.Lookup(command.TargetID)
	if err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	if cluster.Client == nil {
		return provisioner.CreateWorkloadResult{}, newRuntimeError("K3S_UNAVAILABLE", true, nil)
	}

	_, err = ensureNamespace(ctx, cluster.Client, resources.Namespace)
	if err != nil {
		if parentErr := ctx.Err(); parentErr != nil {
			return provisioner.CreateWorkloadResult{}, operationCancelledError(parentErr)
		}
		return provisioner.CreateWorkloadResult{}, err
	}
	if err := applyResourceSet(ctx, cluster.Client, resources); err != nil {
		if parentErr := ctx.Err(); parentErr != nil {
			return provisioner.CreateWorkloadResult{}, a.failWithRollback(cluster.Client, resources.Namespace, "OPERATION_CANCELLED", parentErr)
		}
		return provisioner.CreateWorkloadResult{}, a.failWithRollback(cluster.Client, resources.Namespace, "RESOURCE_APPLY_FAILED", err)
	}

	readyCtx, cancel := context.WithTimeout(ctx, a.config.ReadyTimeout)
	defer cancel()
	if err := waitUntilReady(readyCtx, cluster.Client, resources.Namespace.Name, a.config.PollInterval); err != nil {
		if parentErr := ctx.Err(); parentErr != nil {
			return provisioner.CreateWorkloadResult{}, a.failWithRollback(cluster.Client, resources.Namespace, "OPERATION_CANCELLED", parentErr)
		}
		code := "RESOURCE_APPLY_FAILED"
		if errors.Is(err, context.DeadlineExceeded) {
			code = "WORKLOAD_NOT_READY"
		}
		return provisioner.CreateWorkloadResult{}, a.failWithRollback(cluster.Client, resources.Namespace, code, err)
	}
	return provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: resources.RuntimeWorkloadID,
		ServiceURL:        resources.ServiceURL,
	}, nil
}

func ensureNamespace(ctx context.Context, client kubernetes.Interface, desired *corev1.Namespace) (bool, error) {
	existing, err := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := client.CoreV1().Namespaces().Create(ctx, desired, metav1.CreateOptions{}); err != nil {
			return false, newRuntimeError("RESOURCE_APPLY_FAILED", true, err)
		}
		return true, nil
	}
	if err != nil {
		return false, newRuntimeError("RESOURCE_APPLY_FAILED", true, err)
	}
	if !hasOwnership(existing.Labels, desired.Labels) {
		return false, newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
	}
	return false, nil
}

func applyResourceSet(ctx context.Context, client kubernetes.Interface, resources ResourceSet) error {
	if err := upsertDeployment(ctx, client, resources.Deployment); err != nil {
		return err
	}
	if err := upsertService(ctx, client, resources.Service); err != nil {
		return err
	}
	return upsertIngress(ctx, client, resources.Ingress)
}

func upsertDeployment(ctx context.Context, client kubernetes.Interface, desired *appsv1.Deployment) error {
	existing, err := client.AppsV1().Deployments(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = client.AppsV1().Deployments(desired.Namespace).Create(ctx, desired, metav1.CreateOptions{})
	} else if err == nil {
		if !hasOwnership(existing.Labels, desired.Labels) {
			return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		desired.ResourceVersion = existing.ResourceVersion
		_, err = client.AppsV1().Deployments(desired.Namespace).Update(ctx, desired, metav1.UpdateOptions{})
	}
	return applyError(err)
}

func upsertService(ctx context.Context, client kubernetes.Interface, desired *corev1.Service) error {
	existing, err := client.CoreV1().Services(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = client.CoreV1().Services(desired.Namespace).Create(ctx, desired, metav1.CreateOptions{})
	} else if err == nil {
		if !hasOwnership(existing.Labels, desired.Labels) {
			return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		preserveServiceAllocation(desired, existing)
		desired.ResourceVersion = existing.ResourceVersion
		_, err = client.CoreV1().Services(desired.Namespace).Update(ctx, desired, metav1.UpdateOptions{})
	}
	return applyError(err)
}

func preserveServiceAllocation(desired, existing *corev1.Service) {
	desired.Spec.ClusterIP = existing.Spec.ClusterIP
	desired.Spec.ClusterIPs = append([]string(nil), existing.Spec.ClusterIPs...)
	desired.Spec.IPFamilies = append([]corev1.IPFamily(nil), existing.Spec.IPFamilies...)
	desired.Spec.IPFamilyPolicy = existing.Spec.IPFamilyPolicy
	desired.Spec.HealthCheckNodePort = existing.Spec.HealthCheckNodePort
}

func upsertIngress(ctx context.Context, client kubernetes.Interface, desired *networkingv1.Ingress) error {
	existing, err := client.NetworkingV1().Ingresses(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = client.NetworkingV1().Ingresses(desired.Namespace).Create(ctx, desired, metav1.CreateOptions{})
	} else if err == nil {
		if !hasOwnership(existing.Labels, desired.Labels) {
			return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		desired.ResourceVersion = existing.ResourceVersion
		_, err = client.NetworkingV1().Ingresses(desired.Namespace).Update(ctx, desired, metav1.UpdateOptions{})
	}
	return applyError(err)
}

func applyError(err error) error {
	if err == nil {
		return nil
	}
	var runtimeErr *RuntimeError
	if errors.As(err, &runtimeErr) {
		return err
	}
	return newRuntimeError("RESOURCE_APPLY_FAILED", true, err)
}

func operationCancelledError(cause error) error {
	return newRuntimeError("OPERATION_CANCELLED", true, cause)
}

func (a *Adapter) failWithRollback(client kubernetes.Interface, namespace *corev1.Namespace, code string, cause error) error {
	if err := rollbackNamespace(client, namespace); err != nil {
		return newRuntimeError("ROLLBACK_FAILED", true, err)
	}
	var runtimeErr *RuntimeError
	if errors.As(cause, &runtimeErr) && runtimeErr.Code() == "RESOURCE_OWNERSHIP_CONFLICT" {
		return runtimeErr
	}
	return newRuntimeError(code, code == "RESOURCE_APPLY_FAILED" || code == "WORKLOAD_NOT_READY" || code == "OPERATION_CANCELLED", cause)
}

func rollbackNamespace(client kubernetes.Interface, desired *corev1.Namespace) error {
	ctx := context.Background()
	existing, err := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil || !hasOwnership(existing.Labels, desired.Labels) {
		return errors.New("namespace ownership cannot be confirmed")
	}
	propagation := metav1.DeletePropagationBackground
	preconditions := &metav1.Preconditions{UID: &existing.UID, ResourceVersion: &existing.ResourceVersion}
	return client.CoreV1().Namespaces().Delete(ctx, desired.Name, metav1.DeleteOptions{
		PropagationPolicy: &propagation,
		Preconditions:     preconditions,
	})
}

func hasOwnership(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func waitUntilReady(ctx context.Context, client kubernetes.Interface, namespace string, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		readyPod, err := hasReadyPod(ctx, client, namespace)
		if err != nil {
			return err
		}
		readyEndpoint, err := hasReadyEndpoint(ctx, client, namespace)
		if err != nil {
			return err
		}
		if readyPod && readyEndpoint {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func hasReadyPod(ctx context.Context, client kubernetes.Interface, namespace string) (bool, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{"app.kubernetes.io/name": resourceName}.String()})
	if err != nil {
		return false, err
	}
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp != nil {
			continue
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
	}
	return false, nil
}

func hasReadyEndpoint(ctx context.Context, client kubernetes.Interface, namespace string) (bool, error) {
	endpointSlices, err := client.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{discoveryv1.LabelServiceName: resourceName}.String()})
	if err != nil {
		return false, err
	}
	for _, endpointSlice := range endpointSlices.Items {
		for _, endpoint := range endpointSlice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			for _, address := range endpoint.Addresses {
				if strings.TrimSpace(address) != "" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
