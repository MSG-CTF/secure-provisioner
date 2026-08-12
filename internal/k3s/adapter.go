package k3s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
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

type appliedResourceSet struct {
	Deployments []*appsv1.Deployment
	Services    []*corev1.Service
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
			return provisioner.CreateWorkloadResult{}, a.failAfterNamespace(cluster.Client, createdNamespace, "OPERATION_CANCELLED", parentErr)
		}
		return provisioner.CreateWorkloadResult{}, a.failAfterNamespace(cluster.Client, createdNamespace, "RESOURCE_APPLY_FAILED", err)
	}
	applied, err := applyResourceSet(ctx, cluster.Client, resources)
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
		applied.Deployments,
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
	observedNamespace, err := verifyCreatedNamespace(ctx, cluster.Client, resources.Namespace, createdNamespace)
	if err != nil {
		if parentErr := ctx.Err(); parentErr != nil {
			return provisioner.CreateWorkloadResult{}, a.failAfterNamespace(cluster.Client, createdNamespace, "OPERATION_CANCELLED", parentErr)
		}
		return provisioner.CreateWorkloadResult{}, a.failAfterNamespace(cluster.Client, createdNamespace, "RESOURCE_APPLY_FAILED", err)
	}
	endpoints := append([]provisioner.WorkloadEndpoint(nil), resources.Endpoints...)
	serviceURL := resources.ServiceURL
	if cluster.Config.ExposureMode == ExposureModeNodePort {
		endpoints, err = BuildNodePortEndpoints(cluster.Config.PublicGateway, command.Policy.EndpointProtocol, applied.Services)
		if err != nil {
			return provisioner.CreateWorkloadResult{}, a.failWithRollback(cluster.Client, observedNamespace, "RESOURCE_APPLY_FAILED", err)
		}
		serviceURL = endpoints[0].ServiceURL
	}
	return provisioner.CreateWorkloadResult{
		RuntimeWorkloadID: resources.RuntimeWorkloadID,
		NamespaceUID:      string(observedNamespace.UID),
		ServiceURL:        serviceURL,
		Endpoints:         endpoints,
	}, nil
}

func ensureNamespace(ctx context.Context, client kubernetes.Interface, desired *corev1.Namespace) (*corev1.Namespace, error) {
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		_, err := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
		if err == nil {
			return nil, newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		if !apierrors.IsNotFound(err) {
			lastErr = err
			if !kubernetesErrorRetryable(err) {
				return nil, applyError(err)
			}
			continue
		}

		created, createErr := client.CoreV1().Namespaces().Create(ctx, desired.DeepCopy(), metav1.CreateOptions{})
		if createErr == nil {
			if !approvedSemanticMetadata(created, desired, false) {
				return created.DeepCopy(), applyError(errors.New("namespace read-back verification failed"))
			}
			return created.DeepCopy(), nil
		}
		// A failed Create response can never prove that this invocation created
		// the Namespace. Do not adopt a later GET result or write children; an
		// independent retry will preflight the now-current Namespace.
		return nil, applyError(createErr)
	}
	return nil, applyError(lastErr)
}

func verifyCreatedNamespace(
	ctx context.Context,
	client kubernetes.Interface,
	desired *corev1.Namespace,
	created *corev1.Namespace,
) (*corev1.Namespace, error) {
	if created == nil || created.UID == "" {
		return nil, newRuntimeError("RUNTIME_IDENTITY_MISMATCH", false, nil)
	}
	observed, err := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
	if err != nil {
		return nil, applyError(err)
	}
	if observed.UID == "" || observed.UID != created.UID {
		return nil, newRuntimeError("RUNTIME_IDENTITY_MISMATCH", false, nil)
	}
	if observed.DeletionTimestamp != nil || !approvedSemanticMetadata(observed, desired, false) {
		return nil, newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
	}
	return observed.DeepCopy(), nil
}

func applyResourceSet(ctx context.Context, client kubernetes.Interface, resources ResourceSet) (appliedResourceSet, error) {
	if err := applyProtectionResourceSet(ctx, client, resources); err != nil {
		return appliedResourceSet{}, err
	}
	applied := appliedResourceSet{
		Deployments: make([]*appsv1.Deployment, 0, len(resources.Deployments)),
		Services:    make([]*corev1.Service, 0, len(resources.Services)),
	}
	for _, deployment := range resources.Deployments {
		appliedDeployment, err := upsertDeployment(ctx, client, deployment)
		if err != nil {
			return appliedResourceSet{}, err
		}
		applied.Deployments = append(applied.Deployments, appliedDeployment.DeepCopy())
	}
	for _, service := range resources.Services {
		appliedService, err := upsertService(ctx, client, service)
		if err != nil {
			return appliedResourceSet{}, err
		}
		applied.Services = append(applied.Services, appliedService.DeepCopy())
	}
	if resources.Ingress != nil {
		if err := upsertIngress(ctx, client, resources.Ingress); err != nil {
			return appliedResourceSet{}, err
		}
	}
	return applied, nil
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
	if resources.Ingress == nil {
		return nil
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
	if !approvedSemanticMetadata(existing, desired, true) {
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
		annotations := copyStringMap(protection.object.GetAnnotations())
		delete(annotations, specHashAnnotation)
		hash, err := desiredSpecHash(struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
			Spec        any               `json:"spec"`
		}{
			Labels:      copyStringMap(protection.object.GetLabels()),
			Annotations: annotations,
			Spec:        protection.spec,
		})
		if err != nil {
			return err
		}
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
				if !kubernetesErrorRetryable(createErr) {
					return applyError(createErr)
				}
			}
			existing, err = operations.get()
		}
		if err != nil {
			if !apierrors.IsNotFound(err) {
				lastErr = err
				if !kubernetesErrorRetryable(err) {
					return applyError(err)
				}
			}
			continue
		}
		actualMetadata := existing.(metav1.Object)
		desiredMetadata := operations.desired.(metav1.Object)
		if !approvedSemanticMetadata(actualMetadata, desiredMetadata, true) {
			return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
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
	if !hasOwnership(actualMetadata.GetLabels(), desiredMetadata.GetLabels()) ||
		!approvedStructuralMetadata(actualMetadata, desiredMetadata) {
		return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
	}
	if !approvedSemanticMetadata(actualMetadata, desiredMetadata, false) ||
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
	candidate.SetLabels(copyStringMap(desired.GetLabels()))
	candidate.SetAnnotations(copyStringMap(desired.GetAnnotations()))
}

// approvedSemanticMetadata rejects admission/controller metadata with workload
// semantics. Kubernetes' namespace-name label and the Deployment controller's
// positive decimal revision are the only server-managed semantic metadata this
// provisioner accepts. UID, resourceVersion, generation, timestamps, and
// managedFields remain ordinary server fields on a deep-copied object.
func approvedSemanticMetadata(actual, desired metav1.Object, allowStaleSpecHash bool) bool {
	if !approvedStructuralMetadata(actual, desired) {
		return false
	}

	allowedLabels := copyStringMap(desired.GetLabels())
	if namespace, ok := actual.(*corev1.Namespace); ok {
		allowedLabels[corev1.LabelMetadataName] = namespace.Name
	}
	if !equalStringMap(actual.GetLabels(), allowedLabels) && !equalStringMap(actual.GetLabels(), desired.GetLabels()) {
		return false
	}

	for key, value := range desired.GetAnnotations() {
		if allowStaleSpecHash && key == specHashAnnotation {
			continue
		}
		if actual.GetAnnotations()[key] != value {
			return false
		}
	}
	for key, value := range actual.GetAnnotations() {
		if _, ok := desired.GetAnnotations()[key]; ok {
			continue
		}
		if _, ok := actual.(*appsv1.Deployment); ok && key == "deployment.kubernetes.io/revision" && positiveDecimal(value) {
			continue
		}
		return false
	}
	return true
}

func approvedStructuralMetadata(actual, desired metav1.Object) bool {
	return actual.GetDeletionTimestamp() == nil &&
		equalOwnerReferences(actual.GetOwnerReferences(), desired.GetOwnerReferences()) &&
		equalStringSlice(actual.GetFinalizers(), desired.GetFinalizers())
}

func equalOwnerReferences(left, right []metav1.OwnerReference) bool {
	return len(left) == len(right) && (len(left) == 0 || apiequality.Semantic.DeepEqual(left, right))
}

func equalStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func positiveDecimal(value string) bool {
	revision, err := strconv.ParseUint(value, 10, 64)
	return err == nil && revision > 0
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
	deployments := client.AppsV1().Deployments(desired.Namespace)
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		existing, err := deployments.Get(ctx, desired.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, createErr := deployments.Create(ctx, desired.DeepCopy(), metav1.CreateOptions{})
			if createErr == nil {
				return verifiedDeploymentReadback(ctx, deployments, desired)
			}
			lastErr = createErr
			if !kubernetesErrorRetryable(createErr) {
				return nil, applyError(createErr)
			}
			existing, err = deployments.Get(ctx, desired.Name, metav1.GetOptions{})
		}
		if err != nil {
			if !apierrors.IsNotFound(err) {
				lastErr = err
				if !kubernetesErrorRetryable(err) {
					return nil, applyError(err)
				}
			}
			continue
		}
		if !approvedSemanticMetadata(existing, desired, true) {
			return nil, newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		candidate := existing.DeepCopy()
		reconcileWorkloadMetadata(candidate, desired)
		candidate.Spec = *desired.Spec.DeepCopy()
		_, updateErr := deployments.Update(ctx, candidate, metav1.UpdateOptions{})
		if updateErr == nil {
			return verifiedDeploymentReadback(ctx, deployments, desired)
		}
		lastErr = updateErr
		if !apierrors.IsConflict(updateErr) {
			return nil, applyError(updateErr)
		}
	}
	return nil, applyError(lastErr)
}

type deploymentGetter interface {
	Get(context.Context, string, metav1.GetOptions) (*appsv1.Deployment, error)
}

func verifiedDeploymentReadback(ctx context.Context, deployments deploymentGetter, desired *appsv1.Deployment) (*appsv1.Deployment, error) {
	actual, err := deployments.Get(ctx, desired.Name, metav1.GetOptions{})
	if err != nil {
		return nil, applyError(err)
	}
	if !approvedSemanticMetadata(actual, desired, false) || !sameDeploymentSpec(actual, desired) {
		return nil, applyError(errors.New("deployment read-back verification failed"))
	}
	expected := desired.DeepCopy()
	expected.UID = actual.UID
	expected.ResourceVersion = actual.ResourceVersion
	expected.Generation = actual.Generation
	return expected, nil
}

func sameDeploymentSpec(actual, desired *appsv1.Deployment) bool {
	actualCopy := actual.DeepCopy()
	desiredCopy := desired.DeepCopy()
	normalizeDeploymentAPIDefaults(actualCopy)
	normalizeDeploymentAPIDefaults(desiredCopy)
	return apiequality.Semantic.DeepEqual(actualCopy.Spec, desiredCopy.Spec)
}

func normalizeDeploymentAPIDefaults(deployment *appsv1.Deployment) {
	if deployment.Spec.ProgressDeadlineSeconds == nil {
		deployment.Spec.ProgressDeadlineSeconds = int32Pointer(600)
	}
	podSpec := &deployment.Spec.Template.Spec
	if podSpec.RestartPolicy == "" {
		podSpec.RestartPolicy = corev1.RestartPolicyAlways
	}
	if podSpec.DNSPolicy == "" {
		podSpec.DNSPolicy = corev1.DNSClusterFirst
	}
	if podSpec.SchedulerName == "" {
		podSpec.SchedulerName = corev1.DefaultSchedulerName
	}
	if podSpec.DeprecatedServiceAccount == "" {
		podSpec.DeprecatedServiceAccount = podSpec.ServiceAccountName
	}
	if podSpec.TerminationGracePeriodSeconds == nil {
		value := int64(corev1.DefaultTerminationGracePeriodSeconds)
		podSpec.TerminationGracePeriodSeconds = &value
	}
	for index := range podSpec.Containers {
		normalizeContainerAPIDefaults(&podSpec.Containers[index])
	}
	for index := range podSpec.InitContainers {
		normalizeContainerAPIDefaults(&podSpec.InitContainers[index])
	}
}

func normalizeContainerAPIDefaults(container *corev1.Container) {
	if container.TerminationMessagePath == "" {
		container.TerminationMessagePath = corev1.TerminationMessagePathDefault
	}
	if container.TerminationMessagePolicy == "" {
		container.TerminationMessagePolicy = corev1.TerminationMessageReadFile
	}
	if container.ImagePullPolicy == "" {
		container.ImagePullPolicy = corev1.PullIfNotPresent
	}
	for index := range container.Ports {
		if container.Ports[index].Protocol == "" {
			container.Ports[index].Protocol = corev1.ProtocolTCP
		}
	}
}

func reconcileWorkloadMetadata(candidate, desired metav1.Object) {
	labels := copyStringMap(desired.GetLabels())
	annotations := copyStringMap(desired.GetAnnotations())
	if _, ok := candidate.(*appsv1.Deployment); ok {
		if revision := candidate.GetAnnotations()["deployment.kubernetes.io/revision"]; positiveDecimal(revision) {
			annotations["deployment.kubernetes.io/revision"] = revision
		}
	}
	candidate.SetLabels(labels)
	candidate.SetAnnotations(annotations)
}

func upsertService(ctx context.Context, client kubernetes.Interface, desired *corev1.Service) (*corev1.Service, error) {
	services := client.CoreV1().Services(desired.Namespace)
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		existing, err := services.Get(ctx, desired.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, createErr := services.Create(ctx, desired.DeepCopy(), metav1.CreateOptions{}); createErr == nil {
				return verifyServiceReadback(ctx, services, desired)
			} else {
				lastErr = createErr
				if !kubernetesErrorRetryable(createErr) {
					return nil, applyError(createErr)
				}
			}
			existing, err = services.Get(ctx, desired.Name, metav1.GetOptions{})
		}
		if err != nil {
			if !apierrors.IsNotFound(err) {
				lastErr = err
				if !kubernetesErrorRetryable(err) {
					return nil, applyError(err)
				}
			}
			continue
		}
		if !approvedSemanticMetadata(existing, desired, true) {
			return nil, newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		candidate := existing.DeepCopy()
		reconcileWorkloadMetadata(candidate, desired)
		candidate.Spec = *desired.Spec.DeepCopy()
		preserveServiceAllocation(candidate, existing)
		if _, updateErr := services.Update(ctx, candidate, metav1.UpdateOptions{}); updateErr == nil {
			return verifyServiceReadback(ctx, services, desired)
		} else {
			lastErr = updateErr
			if !apierrors.IsConflict(updateErr) {
				return nil, applyError(updateErr)
			}
		}
	}
	return nil, applyError(lastErr)
}

type serviceGetter interface {
	Get(context.Context, string, metav1.GetOptions) (*corev1.Service, error)
}

func verifyServiceReadback(ctx context.Context, services serviceGetter, desired *corev1.Service) (*corev1.Service, error) {
	actual, err := services.Get(ctx, desired.Name, metav1.GetOptions{})
	if err != nil {
		return nil, applyError(err)
	}
	if !approvedSemanticMetadata(actual, desired, false) || !sameServiceSpec(actual, desired) {
		return nil, applyError(errors.New("service read-back verification failed"))
	}
	return actual.DeepCopy(), nil
}

func sameServiceSpec(actual, desired *corev1.Service) bool {
	actualCopy := actual.DeepCopy()
	desiredCopy := desired.DeepCopy()
	preserveServiceAllocation(desiredCopy, actualCopy)
	normalizeServiceAPIDefaults(actualCopy)
	normalizeServiceAPIDefaults(desiredCopy)
	return apiequality.Semantic.DeepEqual(actualCopy.Spec, desiredCopy.Spec)
}

func normalizeServiceAPIDefaults(service *corev1.Service) {
	if service.Spec.SessionAffinity == "" {
		service.Spec.SessionAffinity = corev1.ServiceAffinityNone
	}
	if service.Spec.InternalTrafficPolicy == nil {
		value := corev1.ServiceInternalTrafficPolicyCluster
		service.Spec.InternalTrafficPolicy = &value
	}
	for index := range service.Spec.Ports {
		if service.Spec.Ports[index].Protocol == "" {
			service.Spec.Ports[index].Protocol = corev1.ProtocolTCP
		}
	}
}

func preserveServiceAllocation(desired, existing *corev1.Service) {
	desired.Spec.ClusterIP = existing.Spec.ClusterIP
	desired.Spec.ClusterIPs = append([]string(nil), existing.Spec.ClusterIPs...)
	desired.Spec.IPFamilies = append([]corev1.IPFamily(nil), existing.Spec.IPFamilies...)
	desired.Spec.IPFamilyPolicy = existing.Spec.IPFamilyPolicy
	desired.Spec.HealthCheckNodePort = existing.Spec.HealthCheckNodePort
	for desiredIndex := range desired.Spec.Ports {
		if desired.Spec.Ports[desiredIndex].NodePort != 0 {
			continue
		}
		for _, existingPort := range existing.Spec.Ports {
			if desired.Spec.Ports[desiredIndex].Name == existingPort.Name ||
				(desired.Spec.Ports[desiredIndex].Name == "" && desired.Spec.Ports[desiredIndex].Port == existingPort.Port && desired.Spec.Ports[desiredIndex].Protocol == existingPort.Protocol) {
				desired.Spec.Ports[desiredIndex].NodePort = existingPort.NodePort
				break
			}
		}
	}
}

func upsertIngress(ctx context.Context, client kubernetes.Interface, desired *networkingv1.Ingress) error {
	ingresses := client.NetworkingV1().Ingresses(desired.Namespace)
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		existing, err := ingresses.Get(ctx, desired.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, createErr := ingresses.Create(ctx, desired.DeepCopy(), metav1.CreateOptions{}); createErr == nil {
				return verifyIngressReadback(ctx, ingresses, desired)
			} else {
				lastErr = createErr
				if !kubernetesErrorRetryable(createErr) {
					return applyError(createErr)
				}
			}
			existing, err = ingresses.Get(ctx, desired.Name, metav1.GetOptions{})
		}
		if err != nil {
			if !apierrors.IsNotFound(err) {
				lastErr = err
				if !kubernetesErrorRetryable(err) {
					return applyError(err)
				}
			}
			continue
		}
		if !approvedSemanticMetadata(existing, desired, true) {
			return newRuntimeError("RESOURCE_OWNERSHIP_CONFLICT", false, nil)
		}
		candidate := existing.DeepCopy()
		reconcileWorkloadMetadata(candidate, desired)
		candidate.Spec = *desired.Spec.DeepCopy()
		if _, updateErr := ingresses.Update(ctx, candidate, metav1.UpdateOptions{}); updateErr == nil {
			return verifyIngressReadback(ctx, ingresses, desired)
		} else {
			lastErr = updateErr
			if !apierrors.IsConflict(updateErr) {
				return applyError(updateErr)
			}
		}
	}
	return applyError(lastErr)
}

type ingressGetter interface {
	Get(context.Context, string, metav1.GetOptions) (*networkingv1.Ingress, error)
}

func verifyIngressReadback(ctx context.Context, ingresses ingressGetter, desired *networkingv1.Ingress) error {
	actual, err := ingresses.Get(ctx, desired.Name, metav1.GetOptions{})
	if err != nil {
		return applyError(err)
	}
	actualCopy := actual.DeepCopy()
	desiredCopy := desired.DeepCopy()
	if !approvedSemanticMetadata(actual, desired, false) || !apiequality.Semantic.DeepEqual(actualCopy.Spec, desiredCopy.Spec) {
		return applyError(errors.New("ingress read-back verification failed"))
	}
	return nil
}

func applyError(err error) error {
	if err == nil {
		return nil
	}
	var runtimeErr *RuntimeError
	if errors.As(err, &runtimeErr) {
		return err
	}
	return newRuntimeError("RESOURCE_APPLY_FAILED", kubernetesErrorRetryable(err), err)
}

func kubernetesErrorRetryable(err error) bool {
	if err == nil {
		return false
	}
	var runtimeErr *RuntimeError
	if errors.As(err, &runtimeErr) {
		return runtimeErr.Retryable()
	}
	if apierrors.IsInvalid(err) || apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || apierrors.IsBadRequest(err) {
		return false
	}
	// Admission implementations do not always return StatusReasonInvalid for
	// immutable-field rejection. Keep this narrow and case-insensitive.
	return !strings.Contains(strings.ToLower(err.Error()), "field is immutable")
}

func operationCancelledError(cause error) error {
	return newRuntimeError("OPERATION_CANCELLED", true, cause)
}

func failureWithoutRollback(code string, cause error) error {
	var runtimeErr *RuntimeError
	if errors.As(cause, &runtimeErr) {
		return runtimeErr
	}
	retryable := code == "WORKLOAD_NOT_READY" || code == "OPERATION_CANCELLED"
	if code == "RESOURCE_APPLY_FAILED" {
		retryable = kubernetesErrorRetryable(cause)
	}
	return newRuntimeError(code, retryable, cause)
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
	if errors.As(cause, &runtimeErr) &&
		(runtimeErr.Code() == "RESOURCE_OWNERSHIP_CONFLICT" || runtimeErr.Code() == "RUNTIME_IDENTITY_MISMATCH") {
		return runtimeErr
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), a.config.RollbackTimeout)
	defer cancel()
	if err := rollbackNamespace(rollbackCtx, client, namespace, a.config.PollInterval); err != nil {
		return newRuntimeError("ROLLBACK_FAILED", rollbackErrorRetryable(err), errors.Join(cause, err))
	}
	return failureWithoutRollback(code, cause)
}

func rollbackNamespace(ctx context.Context, client kubernetes.Interface, desired *corev1.Namespace, pollInterval time.Duration) error {
	expectedUID := desired.UID
	deleteAccepted := false
	var lastErr error
	for attempt := 0; attempt < maxReconcileAttempts; attempt++ {
		existing, err := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			lastErr = err
			if !kubernetesErrorRetryable(err) {
				return err
			}
			continue
		}
		if !hasOwnership(existing.Labels, desired.Labels) {
			return errNamespaceOwnership
		}
		if expectedUID == "" {
			expectedUID = existing.UID
		}
		if existing.UID != expectedUID {
			return errNamespaceIdentity
		}
		if existing.DeletionTimestamp != nil {
			deleteAccepted = true
			break
		}

		propagation := metav1.DeletePropagationBackground
		preconditions := &metav1.Preconditions{UID: &expectedUID, ResourceVersion: &existing.ResourceVersion}
		err = client.CoreV1().Namespaces().Delete(ctx, desired.Name, metav1.DeleteOptions{
			PropagationPolicy: &propagation,
			Preconditions:     preconditions,
		})
		if err == nil || apierrors.IsNotFound(err) {
			deleteAccepted = true
			break
		}
		lastErr = err
		if !kubernetesErrorRetryable(err) {
			return err
		}
	}
	if !deleteAccepted {
		return lastErr
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		current, getErr := client.CoreV1().Namespaces().Get(ctx, desired.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			return nil
		}
		if getErr != nil {
			if !kubernetesErrorRetryable(getErr) {
				return getErr
			}
		} else if current.UID != expectedUID {
			return errNamespaceIdentity
		} else if !hasOwnership(current.Labels, desired.Labels) {
			return errNamespaceOwnership
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

var (
	errNamespaceOwnership = errors.New("namespace ownership cannot be confirmed")
	errNamespaceIdentity  = errors.New("namespace identity cannot be confirmed")
)

func rollbackErrorRetryable(err error) bool {
	if errors.Is(err, errNamespaceOwnership) || errors.Is(err, errNamespaceIdentity) {
		return false
	}
	return kubernetesErrorRetryable(err)
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
	if current.UID != expected.UID || current.Generation != expected.Generation ||
		current.Annotations[specHashAnnotation] != expectedSpecHash {
		return false, nil
	}
	if !approvedSemanticMetadata(current, expected, false) || !sameDeploymentSpec(current, expected) {
		return false, applyError(errors.New("deployment readiness verification failed"))
	}
	return current.Status.ObservedGeneration >= current.Generation &&
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
