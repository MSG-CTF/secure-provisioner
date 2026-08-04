package k3s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

type AdapterConfig struct {
	ReadyTimeout    time.Duration
	PollInterval    time.Duration
	RollbackTimeout time.Duration
}

type Adapter struct {
	registry      *Registry
	config        AdapterConfig
	workloadLocks *workloadLockSet
}

const (
	maxReconcileAttempts   = 3
	defaultRollbackTimeout = 30 * time.Second
)

func NewAdapter(registry *Registry, config AdapterConfig) (*Adapter, error) {
	if registry == nil || config.ReadyTimeout <= 0 || config.PollInterval <= 0 || config.RollbackTimeout < 0 {
		return nil, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	if config.RollbackTimeout == 0 {
		config.RollbackTimeout = defaultRollbackTimeout
	}
	return &Adapter{registry: registry, config: config, workloadLocks: newWorkloadLockSet()}, nil
}

func (a *Adapter) CreateWorkload(ctx context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	if err := ctx.Err(); err != nil {
		return provisioner.CreateWorkloadResult{}, operationCancelledError(err)
	}
	release, err := a.workloadLocks.acquire(ctx, workloadLockKey(command.TargetID, command.InstanceID))
	if err != nil {
		return provisioner.CreateWorkloadResult{}, operationCancelledError(err)
	}
	defer release()

	cluster, err := a.registry.Lookup(command.TargetID)
	if err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	if err := cluster.Supports(command.Policy); err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	if cluster.Client == nil {
		return provisioner.CreateWorkloadResult{}, newRuntimeError("K3S_UNAVAILABLE", true, nil)
	}
	if err := prepareProtectionHashes(resources); err != nil {
		return provisioner.CreateWorkloadResult{}, newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}
	if err := preflightResourceSet(ctx, cluster.Client, resources); err != nil {
		if parentErr := ctx.Err(); parentErr != nil {
			return provisioner.CreateWorkloadResult{}, operationCancelledError(parentErr)
		}
		return provisioner.CreateWorkloadResult{}, failureWithoutRollback("RESOURCE_APPLY_FAILED", err)
	}

	createdNamespace, err := ensureNamespace(ctx, cluster.Client, resources.Namespace)
	if err != nil {
		if parentErr := ctx.Err(); parentErr != nil {
			return provisioner.CreateWorkloadResult{}, operationCancelledError(parentErr)
		}
		return provisioner.CreateWorkloadResult{}, err
	}
	appliedDeployments, err := applyResourceSet(ctx, cluster.Client, resources)
	if err != nil {
		if parentErr := ctx.Err(); parentErr != nil {
			return provisioner.CreateWorkloadResult{}, a.failAfterNamespace(cluster.Client, createdNamespace, "OPERATION_CANCELLED", parentErr)
		}
		return provisioner.CreateWorkloadResult{}, a.failAfterNamespace(cluster.Client, createdNamespace, "RESOURCE_APPLY_FAILED", err)
	}

	readyCtx, cancel := context.WithTimeout(ctx, a.config.ReadyTimeout)
	defer cancel()
	if err := waitUntilReady(
		readyCtx,
		cluster.Client,
		appliedDeployments,
		resources.ExpectedSpecHashes,
		a.config.PollInterval,
	); err != nil {
		if parentErr := ctx.Err(); parentErr != nil {
			return provisioner.CreateWorkloadResult{}, a.failAfterNamespace(cluster.Client, createdNamespace, "OPERATION_CANCELLED", parentErr)
		}
		code := "RESOURCE_APPLY_FAILED"
		if readyCtx.Err() == context.DeadlineExceeded {
			code = "WORKLOAD_NOT_READY"
		}
		return provisioner.CreateWorkloadResult{}, a.failAfterNamespace(cluster.Client, createdNamespace, code, err)
	}
	return provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: resources.RuntimeWorkloadID,
		ServiceURL:        resources.ServiceURL,
		Endpoints:         append([]provisioner.WorkloadEndpoint(nil), resources.Endpoints...),
	}, nil
}

func ensureNamespace(ctx context.Context, client kubernetes.Interface, desired *corev1.Namespace) (*corev1.Namespace, error) {
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		existing, err := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
		if err == nil {
			if !hasOwnership(existing.Labels, desired.Labels) {
				return nil, newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
			}
			return nil, nil
		}
		if !apierrors.IsNotFound(err) {
			lastErr = err
			continue
		}

		created, createErr := client.CoreV1().Namespaces().Create(ctx, desired.DeepCopy(), metav1.CreateOptions{})
		if createErr == nil {
			if !hasOwnership(created.Labels, desired.Labels) {
				return nil, newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
			}
			return created.DeepCopy(), nil
		}
		lastErr = createErr
		readBack, readErr := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
		if readErr == nil {
			if !hasOwnership(readBack.Labels, desired.Labels) {
				return nil, newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
			}
			// A failed Create response cannot prove that this operation created the
			// Namespace. Treat the read-back as preexisting so rollback can never
			// delete a Namespace committed by another actor.
			return nil, nil
		}
		if !apierrors.IsNotFound(readErr) {
			lastErr = readErr
		}
	}
	return nil, newRuntimeError("RESOURCE_APPLY_FAILED", true, lastErr)
}

func applyResourceSet(ctx context.Context, client kubernetes.Interface, resources ResourceSet) ([]*appsv1.Deployment, error) {
	if err := applyProtectionResourceSet(ctx, client, resources); err != nil {
		return nil, err
	}
	appliedDeployments := make([]*appsv1.Deployment, 0, len(resources.Deployments))
	for _, deployment := range resources.Deployments {
		appliedDeployment, err := upsertDeployment(ctx, client, deployment)
		if err != nil {
			return nil, err
		}
		appliedDeployments = append(appliedDeployments, appliedDeployment.DeepCopy())
	}
	for _, service := range resources.Services {
		if err := upsertService(ctx, client, service); err != nil {
			return nil, err
		}
	}
	if err := upsertIngress(ctx, client, resources.Ingress); err != nil {
		return nil, err
	}
	return appliedDeployments, nil
}

func preflightResourceSet(ctx context.Context, client kubernetes.Interface, resources ResourceSet) error {
	if err := preflightOwnedResource(func() (metav1.Object, error) {
		return client.CoreV1().Namespaces().Get(ctx, resources.Namespace.Name, metav1.GetOptions{})
	}, resources.Namespace); err != nil {
		return err
	}
	if err := preflightOwnedResource(func() (metav1.Object, error) {
		return client.CoreV1().ServiceAccounts(resources.ServiceAccount.Namespace).Get(ctx, resources.ServiceAccount.Name, metav1.GetOptions{})
	}, resources.ServiceAccount); err != nil {
		return err
	}
	if err := preflightOwnedResource(func() (metav1.Object, error) {
		return client.CoreV1().ResourceQuotas(resources.ResourceQuota.Namespace).Get(ctx, resources.ResourceQuota.Name, metav1.GetOptions{})
	}, resources.ResourceQuota); err != nil {
		return err
	}
	if err := preflightOwnedResource(func() (metav1.Object, error) {
		return client.CoreV1().LimitRanges(resources.LimitRange.Namespace).Get(ctx, resources.LimitRange.Name, metav1.GetOptions{})
	}, resources.LimitRange); err != nil {
		return err
	}
	for _, desired := range resources.NetworkPolicies {
		if err := preflightOwnedResource(func() (metav1.Object, error) {
			return client.NetworkingV1().NetworkPolicies(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		}, desired); err != nil {
			return err
		}
	}
	for _, desired := range resources.Deployments {
		if err := preflightOwnedResource(func() (metav1.Object, error) {
			return client.AppsV1().Deployments(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		}, desired); err != nil {
			return err
		}
	}

	for _, desired := range resources.Services {
		if err := preflightOwnedResource(func() (metav1.Object, error) {
			return client.CoreV1().Services(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		}, desired); err != nil {
			return err
		}
	}

	return preflightOwnedResource(func() (metav1.Object, error) {
		return client.NetworkingV1().Ingresses(resources.Ingress.Namespace).Get(ctx, resources.Ingress.Name, metav1.GetOptions{})
	}, resources.Ingress)
}

func preflightOwnedResource(get func() (metav1.Object, error), desired metav1.Object) error {
	existing, err := get()
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return applyError(err)
	}
	if !hasOwnership(existing.GetLabels(), desired.GetLabels()) {
		return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
	}
	return nil
}

type protectionOperations struct {
	desired   runtime.Object
	get       func() (runtime.Object, error)
	create    func(runtime.Object) (runtime.Object, error)
	update    func(runtime.Object) (runtime.Object, error)
	reconcile func(runtime.Object, runtime.Object) runtime.Object
	sameSpec  func(runtime.Object, runtime.Object) bool
}

func prepareProtectionHashes(resources ResourceSet) error {
	protections := []struct {
		object metav1.Object
		spec   any
	}{
		{object: resources.ServiceAccount, spec: serviceAccountDesiredSpec(resources.ServiceAccount)},
		{object: resources.ResourceQuota, spec: resources.ResourceQuota.Spec},
		{object: resources.LimitRange, spec: resources.LimitRange.Spec},
	}
	for _, policy := range resources.NetworkPolicies {
		protections = append(protections, struct {
			object metav1.Object
			spec   any
		}{object: policy, spec: policy.Spec})
	}
	for _, protection := range protections {
		hash, err := desiredSpecHash(protection.spec)
		if err != nil {
			return err
		}
		annotations := copyStringMap(protection.object.GetAnnotations())
		annotations[specHashAnnotation] = hash
		protection.object.SetAnnotations(annotations)
	}
	return nil
}

func desiredSpecHash(spec any) (string, error) {
	encoded, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func serviceAccountDesiredSpec(account *corev1.ServiceAccount) any {
	return struct {
		AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`
	}{AutomountServiceAccountToken: account.AutomountServiceAccountToken}
}

func applyProtectionResourceSet(ctx context.Context, client kubernetes.Interface, resources ResourceSet) error {
	if err := upsertProtection(serviceAccountProtectionOperations(ctx, client, resources.ServiceAccount)); err != nil {
		return err
	}
	if err := upsertProtection(resourceQuotaProtectionOperations(ctx, client, resources.ResourceQuota)); err != nil {
		return err
	}
	if err := upsertProtection(limitRangeProtectionOperations(ctx, client, resources.LimitRange)); err != nil {
		return err
	}
	for _, policy := range resources.NetworkPolicies {
		if err := upsertProtection(networkPolicyProtectionOperations(ctx, client, policy)); err != nil {
			return err
		}
	}
	return nil
}

func upsertProtection(operations protectionOperations) error {
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		existing, err := operations.get()
		if apierrors.IsNotFound(err) {
			if _, createErr := operations.create(operations.desired.DeepCopyObject()); createErr == nil {
				return verifyProtectionReadback(operations)
			} else {
				lastErr = createErr
			}
			existing, err = operations.get()
		}
		if err != nil {
			if !apierrors.IsNotFound(err) {
				lastErr = err
			}
			continue
		}
		if err := verifyProtectionObject(existing, operations.desired, operations.sameSpec); err == nil {
			return nil
		} else if runtimeErrorCodeValue(err) == "RESOURCE_OWNERSHIP_CONFLICT" {
			return err
		}

		candidate := operations.reconcile(existing, operations.desired)
		if _, updateErr := operations.update(candidate); updateErr == nil {
			return verifyProtectionReadback(operations)
		} else {
			lastErr = updateErr
			if !apierrors.IsConflict(updateErr) {
				return applyError(updateErr)
			}
		}
	}
	return applyError(lastErr)
}

func verifyProtectionReadback(operations protectionOperations) error {
	readBack, err := operations.get()
	if err != nil {
		return applyError(err)
	}
	return verifyProtectionObject(readBack, operations.desired, operations.sameSpec)
}

func verifyProtectionObject(actual, desired runtime.Object, sameSpec func(runtime.Object, runtime.Object) bool) error {
	actualMetadata := actual.(metav1.Object)
	desiredMetadata := desired.(metav1.Object)
	if !hasOwnership(actualMetadata.GetLabels(), desiredMetadata.GetLabels()) {
		return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
	}
	if actualMetadata.GetAnnotations()[specHashAnnotation] != desiredMetadata.GetAnnotations()[specHashAnnotation] ||
		!sameSpec(actual, desired) {
		return applyError(errors.New("protection resource read-back verification failed"))
	}
	return nil
}

func runtimeErrorCodeValue(err error) string {
	var runtimeErr *RuntimeError
	if errors.As(err, &runtimeErr) {
		return runtimeErr.Code()
	}
	return ""
}

func serviceAccountProtectionOperations(ctx context.Context, client kubernetes.Interface, desired *corev1.ServiceAccount) protectionOperations {
	accounts := client.CoreV1().ServiceAccounts(desired.Namespace)
	return protectionOperations{
		desired: desired,
		get: func() (runtime.Object, error) {
			return accounts.Get(ctx, desired.Name, metav1.GetOptions{})
		},
		create: func(object runtime.Object) (runtime.Object, error) {
			return accounts.Create(ctx, object.(*corev1.ServiceAccount), metav1.CreateOptions{})
		},
		update: func(object runtime.Object) (runtime.Object, error) {
			return accounts.Update(ctx, object.(*corev1.ServiceAccount), metav1.UpdateOptions{})
		},
		reconcile: func(existing, wanted runtime.Object) runtime.Object {
			candidate := existing.(*corev1.ServiceAccount).DeepCopy()
			desiredAccount := wanted.(*corev1.ServiceAccount)
			reconcileProtectionMetadata(candidate, desiredAccount)
			candidate.AutomountServiceAccountToken = copyBoolPointer(desiredAccount.AutomountServiceAccountToken)
			return candidate
		},
		sameSpec: func(actual, wanted runtime.Object) bool {
			return apiequality.Semantic.DeepEqual(
				serviceAccountDesiredSpec(actual.(*corev1.ServiceAccount)),
				serviceAccountDesiredSpec(wanted.(*corev1.ServiceAccount)),
			)
		},
	}
}

func resourceQuotaProtectionOperations(ctx context.Context, client kubernetes.Interface, desired *corev1.ResourceQuota) protectionOperations {
	quotas := client.CoreV1().ResourceQuotas(desired.Namespace)
	return protectionOperations{
		desired: desired,
		get: func() (runtime.Object, error) {
			return quotas.Get(ctx, desired.Name, metav1.GetOptions{})
		},
		create: func(object runtime.Object) (runtime.Object, error) {
			return quotas.Create(ctx, object.(*corev1.ResourceQuota), metav1.CreateOptions{})
		},
		update: func(object runtime.Object) (runtime.Object, error) {
			return quotas.Update(ctx, object.(*corev1.ResourceQuota), metav1.UpdateOptions{})
		},
		reconcile: func(existing, wanted runtime.Object) runtime.Object {
			candidate := existing.(*corev1.ResourceQuota).DeepCopy()
			desiredQuota := wanted.(*corev1.ResourceQuota)
			reconcileProtectionMetadata(candidate, desiredQuota)
			candidate.Spec = *desiredQuota.Spec.DeepCopy()
			return candidate
		},
		sameSpec: func(actual, wanted runtime.Object) bool {
			return apiequality.Semantic.DeepEqual(actual.(*corev1.ResourceQuota).Spec, wanted.(*corev1.ResourceQuota).Spec)
		},
	}
}

func limitRangeProtectionOperations(ctx context.Context, client kubernetes.Interface, desired *corev1.LimitRange) protectionOperations {
	limitRanges := client.CoreV1().LimitRanges(desired.Namespace)
	return protectionOperations{
		desired: desired,
		get: func() (runtime.Object, error) {
			return limitRanges.Get(ctx, desired.Name, metav1.GetOptions{})
		},
		create: func(object runtime.Object) (runtime.Object, error) {
			return limitRanges.Create(ctx, object.(*corev1.LimitRange), metav1.CreateOptions{})
		},
		update: func(object runtime.Object) (runtime.Object, error) {
			return limitRanges.Update(ctx, object.(*corev1.LimitRange), metav1.UpdateOptions{})
		},
		reconcile: func(existing, wanted runtime.Object) runtime.Object {
			candidate := existing.(*corev1.LimitRange).DeepCopy()
			desiredLimitRange := wanted.(*corev1.LimitRange)
			reconcileProtectionMetadata(candidate, desiredLimitRange)
			candidate.Spec = *desiredLimitRange.Spec.DeepCopy()
			return candidate
		},
		sameSpec: func(actual, wanted runtime.Object) bool {
			return apiequality.Semantic.DeepEqual(actual.(*corev1.LimitRange).Spec, wanted.(*corev1.LimitRange).Spec)
		},
	}
}

func networkPolicyProtectionOperations(ctx context.Context, client kubernetes.Interface, desired *networkingv1.NetworkPolicy) protectionOperations {
	policies := client.NetworkingV1().NetworkPolicies(desired.Namespace)
	return protectionOperations{
		desired: desired,
		get: func() (runtime.Object, error) {
			return policies.Get(ctx, desired.Name, metav1.GetOptions{})
		},
		create: func(object runtime.Object) (runtime.Object, error) {
			return policies.Create(ctx, object.(*networkingv1.NetworkPolicy), metav1.CreateOptions{})
		},
		update: func(object runtime.Object) (runtime.Object, error) {
			return policies.Update(ctx, object.(*networkingv1.NetworkPolicy), metav1.UpdateOptions{})
		},
		reconcile: func(existing, wanted runtime.Object) runtime.Object {
			candidate := existing.(*networkingv1.NetworkPolicy).DeepCopy()
			desiredPolicy := wanted.(*networkingv1.NetworkPolicy)
			reconcileProtectionMetadata(candidate, desiredPolicy)
			candidate.Spec = *desiredPolicy.Spec.DeepCopy()
			return candidate
		},
		sameSpec: func(actual, wanted runtime.Object) bool {
			return apiequality.Semantic.DeepEqual(actual.(*networkingv1.NetworkPolicy).Spec, wanted.(*networkingv1.NetworkPolicy).Spec)
		},
	}
}

func reconcileProtectionMetadata(candidate, desired metav1.Object) {
	labels := copyStringMap(candidate.GetLabels())
	for key, value := range desired.GetLabels() {
		labels[key] = value
	}
	candidate.SetLabels(labels)
	annotations := copyStringMap(candidate.GetAnnotations())
	for key, value := range desired.GetAnnotations() {
		annotations[key] = value
	}
	candidate.SetAnnotations(annotations)
}

func copyStringMap(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source)+1)
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func copyBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func upsertDeployment(ctx context.Context, client kubernetes.Interface, desired *appsv1.Deployment) (*appsv1.Deployment, error) {
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		existing, err := client.AppsV1().Deployments(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			created, createErr := client.AppsV1().Deployments(desired.Namespace).Create(ctx, desired.DeepCopy(), metav1.CreateOptions{})
			if createErr == nil {
				return created, nil
			}
			lastErr = createErr
			existing, err = client.AppsV1().Deployments(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		}
		if err != nil {
			if !apierrors.IsNotFound(err) {
				lastErr = err
			}
			continue
		}
		if !hasOwnership(existing.Labels, desired.Labels) {
			return nil, newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		candidate := desired.DeepCopy()
		candidate.ResourceVersion = existing.ResourceVersion
		updated, updateErr := client.AppsV1().Deployments(desired.Namespace).Update(ctx, candidate, metav1.UpdateOptions{})
		if updateErr == nil {
			return updated, nil
		}
		lastErr = updateErr
		if !apierrors.IsConflict(updateErr) {
			return nil, applyError(updateErr)
		}
	}
	return nil, applyError(lastErr)
}

func upsertService(ctx context.Context, client kubernetes.Interface, desired *corev1.Service) error {
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		existing, err := client.CoreV1().Services(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, createErr := client.CoreV1().Services(desired.Namespace).Create(ctx, desired.DeepCopy(), metav1.CreateOptions{}); createErr == nil {
				return nil
			} else {
				lastErr = createErr
			}
			existing, err = client.CoreV1().Services(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		}
		if err != nil {
			if !apierrors.IsNotFound(err) {
				lastErr = err
			}
			continue
		}
		if !hasOwnership(existing.Labels, desired.Labels) {
			return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		candidate := desired.DeepCopy()
		preserveServiceAllocation(candidate, existing)
		candidate.ResourceVersion = existing.ResourceVersion
		if _, updateErr := client.CoreV1().Services(desired.Namespace).Update(ctx, candidate, metav1.UpdateOptions{}); updateErr == nil {
			return nil
		} else {
			lastErr = updateErr
			if !apierrors.IsConflict(updateErr) {
				return applyError(updateErr)
			}
		}
	}
	return applyError(lastErr)
}

func preserveServiceAllocation(desired, existing *corev1.Service) {
	desired.Spec.ClusterIP = existing.Spec.ClusterIP
	desired.Spec.ClusterIPs = append([]string(nil), existing.Spec.ClusterIPs...)
	desired.Spec.IPFamilies = append([]corev1.IPFamily(nil), existing.Spec.IPFamilies...)
	desired.Spec.IPFamilyPolicy = existing.Spec.IPFamilyPolicy
	desired.Spec.HealthCheckNodePort = existing.Spec.HealthCheckNodePort
}

func upsertIngress(ctx context.Context, client kubernetes.Interface, desired *networkingv1.Ingress) error {
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		existing, err := client.NetworkingV1().Ingresses(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, createErr := client.NetworkingV1().Ingresses(desired.Namespace).Create(ctx, desired.DeepCopy(), metav1.CreateOptions{}); createErr == nil {
				return nil
			} else {
				lastErr = createErr
			}
			existing, err = client.NetworkingV1().Ingresses(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		}
		if err != nil {
			if !apierrors.IsNotFound(err) {
				lastErr = err
			}
			continue
		}
		if !hasOwnership(existing.Labels, desired.Labels) {
			return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		candidate := desired.DeepCopy()
		candidate.ResourceVersion = existing.ResourceVersion
		if _, updateErr := client.NetworkingV1().Ingresses(desired.Namespace).Update(ctx, candidate, metav1.UpdateOptions{}); updateErr == nil {
			return nil
		} else {
			lastErr = updateErr
			if !apierrors.IsConflict(updateErr) {
				return applyError(updateErr)
			}
		}
	}
	return applyError(lastErr)
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

func failureWithoutRollback(code string, cause error) error {
	var runtimeErr *RuntimeError
	if errors.As(cause, &runtimeErr) {
		return runtimeErr
	}
	return newRuntimeError(code, code == "RESOURCE_APPLY_FAILED" || code == "WORKLOAD_NOT_READY" || code == "OPERATION_CANCELLED", cause)
}

func (a *Adapter) failAfterNamespace(
	client kubernetes.Interface,
	createdNamespace *corev1.Namespace,
	code string,
	cause error,
) error {
	if createdNamespace == nil {
		return failureWithoutRollback(code, cause)
	}
	return a.failWithRollback(client, createdNamespace, code, cause)
}

func (a *Adapter) failWithRollback(client kubernetes.Interface, namespace *corev1.Namespace, code string, cause error) error {
	var runtimeErr *RuntimeError
	if errors.As(cause, &runtimeErr) && runtimeErr.Code() == "RESOURCE_OWNERSHIP_CONFLICT" {
		return runtimeErr
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), a.config.RollbackTimeout)
	defer cancel()
	if err := rollbackNamespace(rollbackCtx, client, namespace, a.config.PollInterval); err != nil {
		return newRuntimeError("ROLLBACK_FAILED", true, errors.Join(cause, err))
	}
	return newRuntimeError(code, code == "RESOURCE_APPLY_FAILED" || code == "WORKLOAD_NOT_READY" || code == "OPERATION_CANCELLED", cause)
}

func rollbackNamespace(ctx context.Context, client kubernetes.Interface, desired *corev1.Namespace, pollInterval time.Duration) error {
	existing, err := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !hasOwnership(existing.Labels, desired.Labels) {
		return errors.New("namespace ownership cannot be confirmed")
	}
	if desired.UID != "" && existing.UID != desired.UID {
		return errors.New("namespace identity cannot be confirmed")
	}
	propagation := metav1.DeletePropagationBackground
	preconditions := &metav1.Preconditions{UID: &existing.UID, ResourceVersion: &existing.ResourceVersion}
	if err := client.CoreV1().Namespaces().Delete(ctx, desired.Name, metav1.DeleteOptions{
		PropagationPolicy: &propagation,
		Preconditions:     preconditions,
	}); err != nil {
		return err
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		current, getErr := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			return nil
		}
		if getErr != nil {
			return getErr
		}
		if current.UID != existing.UID || !hasOwnership(current.Labels, desired.Labels) {
			return errors.New("namespace ownership cannot be confirmed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func hasOwnership(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func waitUntilReady(
	ctx context.Context,
	client kubernetes.Interface,
	expectedDeployments []*appsv1.Deployment,
	expectedSpecHashes map[string]string,
	interval time.Duration,
) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		allReady := len(expectedDeployments) > 0
		for _, expectedDeployment := range expectedDeployments {
			expectedSpecHash := expectedSpecHashes[expectedDeployment.Name]
			deploymentReady, err := currentDeploymentReady(ctx, client, expectedDeployment, expectedSpecHash)
			if err != nil {
				return err
			}
			if !deploymentReady {
				allReady = false
				break
			}
			readyPods, podErr := readyPodsForSpec(
				ctx,
				client,
				expectedDeployment.Namespace,
				expectedDeployment.Spec.Selector.MatchLabels,
				expectedSpecHash,
			)
			if podErr != nil {
				return podErr
			}
			if len(readyPods) == 0 {
				allReady = false
				break
			}
			readyEndpoint, endpointErr := hasReadyEndpointForServicePods(
				ctx,
				client,
				expectedDeployment.Namespace,
				expectedDeployment.Name,
				readyPods,
			)
			if endpointErr != nil {
				return endpointErr
			}
			if !readyEndpoint {
				allReady = false
				break
			}
		}
		if allReady {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func currentDeploymentReady(ctx context.Context, client kubernetes.Interface, expected *appsv1.Deployment, expectedSpecHash string) (bool, error) {
	current, err := client.AppsV1().Deployments(expected.Namespace).Get(ctx, expected.Name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	return current.UID == expected.UID &&
		current.Generation == expected.Generation &&
		current.Annotations[specHashAnnotation] == expectedSpecHash &&
		current.Status.ObservedGeneration >= current.Generation &&
		current.Status.UpdatedReplicas >= 1 &&
		current.Status.AvailableReplicas >= 1, nil
}

func readyPodsForSpec(ctx context.Context, client kubernetes.Interface, namespace string, podLabels map[string]string, expectedSpecHash string) ([]corev1.Pod, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set(podLabels).String()})
	if err != nil {
		return nil, err
	}
	ready := make([]corev1.Pod, 0, len(pods.Items))
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp != nil || pod.Annotations[specHashAnnotation] != expectedSpecHash {
			continue
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				ready = append(ready, pod)
				break
			}
		}
	}
	return ready, nil
}

func hasReadyEndpointForPods(ctx context.Context, client kubernetes.Interface, namespace string, pods []corev1.Pod) (bool, error) {
	return hasReadyEndpointForServicePods(ctx, client, namespace, resourceName, pods)
}

func hasReadyEndpointForServicePods(
	ctx context.Context,
	client kubernetes.Interface,
	namespace string,
	serviceName string,
	pods []corev1.Pod,
) (bool, error) {
	endpointSlices, err := client.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{discoveryv1.LabelServiceName: serviceName}.String(),
	})
	if err != nil {
		return false, err
	}
	for _, endpointSlice := range endpointSlices.Items {
		for _, endpoint := range endpointSlice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			hasAddress := false
			for _, address := range endpoint.Addresses {
				if strings.TrimSpace(address) != "" {
					hasAddress = true
					break
				}
			}
			if !hasAddress {
				continue
			}
			for _, pod := range pods {
				if endpoint.TargetRef != nil && endpoint.TargetRef.UID != "" {
					if endpoint.TargetRef.UID == pod.UID {
						return true, nil
					}
					continue
				}
				if strings.TrimSpace(pod.Status.PodIP) == "" {
					continue
				}
				for _, address := range endpoint.Addresses {
					if address == pod.Status.PodIP {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
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
