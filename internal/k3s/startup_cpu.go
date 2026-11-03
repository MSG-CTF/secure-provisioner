package k3s

import (
	"context"
	"errors"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

func (a *Adapter) validateStartupCPU(cluster Cluster, command provisioner.CreateWorkloadCommand) error {
	if command.SteadyCPUMillicores == 0 {
		return nil
	}
	if command.RuntimeType != provisioner.RuntimeTypeKubernetes ||
		command.PolicyRequest.WorkloadProfile != isolation.WorkloadProfileWeb ||
		cluster.Config.ExposureMode != ExposureModeNodePort || len(command.Containers) != 1 {
		return newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}
	profile, ok := a.config.StartupCPUProfiles[command.Containers[0].Image]
	if !ok || profile.Steady < 1 || profile.Steady != command.SteadyCPUMillicores ||
		profile.Peak != command.ResourceLimits.CPUMillicores || profile.Peak <= profile.Steady {
		return newRuntimeError("INVALID_CREATE_COMMAND", false, nil)
	}
	return nil
}

// The immutable Deployment template always contains steady CPU. Only the live
// owned Pod is resized, while the Scheduler still holds the peak reservation.
// An interrupted create uses the existing namespace rollback and never commits
// a smaller reservation. A later replacement Pod starts at steady CPU.
func prepareStartupCPU(ctx context.Context, client kubernetes.Interface, deployments []*appsv1.Deployment,
	hashes map[string]string, command provisioner.CreateWorkloadCommand, interval time.Duration) error {
	if len(deployments) != 1 {
		return errors.New("startup CPU requires exactly one deployment")
	}
	expected := deployments[0]
	settling := make(map[types.UID]bool)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := client.AppsV1().Deployments(expected.Namespace).Get(ctx, expected.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if current.UID != expected.UID || current.Generation != expected.Generation ||
			!approvedSemanticMetadata(current, expected, false) || !sameDeploymentSpec(current, expected) {
			return errors.New("startup deployment identity or spec changed")
		}
		pods, err := client.CoreV1().Pods(expected.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: labels.Set(expected.Spec.Selector.MatchLabels).String(),
		})
		if err != nil {
			return err
		}
		if len(pods.Items) > 1 {
			return errors.New("startup CPU pod identity is ambiguous")
		}
		if len(pods.Items) == 1 {
			pod := &pods.Items[0]
			if err := validateStartupPod(ctx, client, pod, expected, hashes[expected.Name], command); err != nil {
				return err
			}
			if pod.Status.Phase == corev1.PodRunning {
				ready := startupPodReady(pod)
				if ready {
					settling[pod.UID] = true
				}
				cpu := pod.Spec.Containers[0].Resources.Limits.Cpu().MilliValue()
				desired := command.ResourceLimits.CPUMillicores
				if settling[pod.UID] {
					desired = command.SteadyCPUMillicores
				}
				if cpu != int64(desired) {
					candidate := pod.DeepCopy()
					quantity := *resource.NewMilliQuantity(int64(desired), resource.DecimalSI)
					candidate.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] = quantity
					candidate.Spec.Containers[0].Resources.Limits[corev1.ResourceCPU] = quantity
					// UID and resourceVersion are retained for a fenced update. Do not
					// retry this object against a replacement Pod with the same name.
					_, err = client.CoreV1().Pods(pod.Namespace).UpdateResize(ctx, pod.Name, candidate, metav1.UpdateOptions{})
					if err != nil && !apierrors.IsConflict(err) && !apierrors.IsNotFound(err) && !kubernetesErrorRetryable(err) {
						return err
					}
				} else if settling[pod.UID] && ready && steadyCPUObserved(pod, command.SteadyCPUMillicores) {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func validateStartupPod(ctx context.Context, client kubernetes.Interface, pod *corev1.Pod,
	expected *appsv1.Deployment, hash string, command provisioner.CreateWorkloadCommand) error {
	if pod.UID == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil ||
		pod.Namespace != expected.Namespace || pod.Annotations[specHashAnnotation] != hash ||
		!hasOwnership(pod.Labels, expected.Spec.Template.Labels) || len(pod.Spec.Containers) != 1 ||
		len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 ||
		pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC ||
		pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken ||
		(pod.Spec.ShareProcessNamespace != nil && *pod.Spec.ShareProcessNamespace) ||
		pod.Spec.ServiceAccountName != expected.Spec.Template.Spec.ServiceAccountName ||
		!apiequality.Semantic.DeepEqual(pod.Spec.SecurityContext, expected.Spec.Template.Spec.SecurityContext) ||
		!apiequality.Semantic.DeepEqual(pod.Spec.Volumes, expected.Spec.Template.Spec.Volumes) {
		return errors.New("startup pod ownership or spec mismatch")
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" {
		return errors.New("startup pod has no owned ReplicaSet")
	}
	rs, err := client.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	parent := metav1.GetControllerOf(rs)
	if rs.UID != owner.UID || parent == nil || parent.Kind != "Deployment" || parent.UID != expected.UID || parent.Name != expected.Name {
		return errors.New("startup pod controller ownership mismatch")
	}
	actual := pod.Spec.Containers[0].DeepCopy()
	wanted := expected.Spec.Template.Spec.Containers[0].DeepCopy()
	cpu := actual.Resources.Limits.Cpu().MilliValue()
	if cpu != actual.Resources.Requests.Cpu().MilliValue() || (cpu != int64(command.SteadyCPUMillicores) && cpu != int64(command.ResourceLimits.CPUMillicores)) {
		return errors.New("startup pod has unapproved CPU")
	}
	actual.Resources.Requests[corev1.ResourceCPU] = wanted.Resources.Requests[corev1.ResourceCPU]
	actual.Resources.Limits[corev1.ResourceCPU] = wanted.Resources.Limits[corev1.ResourceCPU]
	for _, policy := range actual.ResizePolicy {
		if policy.RestartPolicy != corev1.NotRequired {
			return errors.New("startup CPU must not restart the container")
		}
	}
	actual.ResizePolicy, wanted.ResizePolicy = nil, nil
	normalizeContainerAPIDefaults(actual)
	normalizeContainerAPIDefaults(wanted)
	if !apiequality.Semantic.DeepEqual(actual, wanted) {
		return errors.New("startup container changed outside the approved CPU override")
	}
	return nil
}

func startupPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func steadyCPUObserved(pod *corev1.Pod, steady int) bool {
	if pod.Status.ObservedGeneration < pod.Generation || len(pod.Status.ContainerStatuses) != 1 {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if (condition.Type == corev1.PodResizePending || condition.Type == corev1.PodResizeInProgress) && condition.Status == corev1.ConditionTrue {
			return false
		}
	}
	status := pod.Status.ContainerStatuses[0]
	if status.Name != pod.Spec.Containers[0].Name || status.Resources == nil ||
		status.Resources.Limits.Cpu().MilliValue() != int64(steady) || status.Resources.Requests.Cpu().MilliValue() != int64(steady) {
		return false
	}
	if value, ok := status.AllocatedResources[corev1.ResourceCPU]; ok && value.MilliValue() != int64(steady) {
		return false
	}
	return true
}
