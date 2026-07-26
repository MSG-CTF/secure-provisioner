package k3s

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
)

type ResourceValues struct {
	CPUMillicores       int64
	MemoryMiB           int64
	EphemeralStorageMiB int64
}

type ResourceUsage struct {
	CPUMillicores int64
	MemoryMiB     int64
}

type ContainerRuntimeStatus struct {
	PodName      string
	Name         string
	State        string
	Ready        bool
	RestartCount int32
	Reason       string
	ExitCode     int32
	StartedAt    *time.Time
	FinishedAt   *time.Time
	Requests     ResourceValues
	Limits       ResourceValues
	Usage        *ResourceUsage
}

type RuntimeStatus struct {
	InstanceID        string
	TargetID          string
	RuntimeWorkloadID string
	Phase             string
	EndpointReady     bool
	MetricsAvailable  bool
	ObservedAt        time.Time
	Containers        []ContainerRuntimeStatus
}

type StatusReader struct {
	registry *Registry
	now      func() time.Time
}

func NewStatusReader(registry *Registry) (*StatusReader, error) {
	if registry == nil {
		return nil, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	return &StatusReader{registry: registry, now: time.Now}, nil
}

func (r *StatusReader) Get(ctx context.Context, binding runtimebinding.Binding) (RuntimeStatus, error) {
	cluster, err := r.registry.LookupForMaintenance(binding.TargetID)
	if err != nil {
		return RuntimeStatus{}, err
	}
	namespace, err := cluster.Client.CoreV1().Namespaces().Get(ctx, binding.Namespace, metav1.GetOptions{})
	if err != nil {
		return RuntimeStatus{}, newRuntimeError("TARGET_TEMPORARILY_UNAVAILABLE", true, err)
	}
	if namespace.Labels["msgctf.io/instance-id"] != binding.InstanceID ||
		namespace.Labels["msgctf.io/team-id"] != strconv.FormatInt(binding.TeamID, 10) ||
		namespace.Labels["app.kubernetes.io/managed-by"] != "secure-provisioner" {
		return RuntimeStatus{}, newRuntimeError("RUNTIME_OWNERSHIP_MISMATCH", false, nil)
	}

	selector := labels.Set{
		"app.kubernetes.io/managed-by": "secure-provisioner",
		"msgctf.io/instance-id":        binding.InstanceID,
	}.String()
	pods, err := cluster.Client.CoreV1().Pods(binding.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return RuntimeStatus{}, newRuntimeError("TARGET_TEMPORARILY_UNAVAILABLE", true, err)
	}
	sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })

	metricsByPod := make(map[string]metricsv1beta1.PodMetrics)
	if cluster.Metrics != nil {
		metrics, metricsErr := cluster.Metrics.MetricsV1beta1().PodMetricses(binding.Namespace).List(ctx, metav1.ListOptions{})
		if metricsErr == nil {
			for _, metric := range metrics.Items {
				metricsByPod[metric.Name] = metric
			}
		}
	}

	status := RuntimeStatus{
		InstanceID:        binding.InstanceID,
		TargetID:          binding.TargetID,
		RuntimeWorkloadID: binding.RuntimeWorkloadID,
		ObservedAt:        r.now().UTC(),
		Containers:        make([]ContainerRuntimeStatus, 0),
	}
	for index := range pods.Items {
		pod := &pods.Items[index]
		podMetrics, hasMetrics := metricsByPod[pod.Name]
		usageByContainer := make(map[string]corev1.ResourceList)
		if hasMetrics {
			for _, container := range podMetrics.Containers {
				usageByContainer[container.Name] = container.Usage
			}
		}
		containerStatuses := make(map[string]corev1.ContainerStatus, len(pod.Status.ContainerStatuses))
		for _, containerStatus := range pod.Status.ContainerStatuses {
			containerStatuses[containerStatus.Name] = containerStatus
		}
		for _, container := range pod.Spec.Containers {
			observed := mapContainerStatus(pod.Name, container, containerStatuses[container.Name])
			if usage, found := usageByContainer[container.Name]; found {
				observed.Usage = &ResourceUsage{
					CPUMillicores: resourceMilliValue(usage, corev1.ResourceCPU),
					MemoryMiB:     resourceMiBValue(usage, corev1.ResourceMemory),
				}
				status.MetricsAvailable = true
			}
			status.Containers = append(status.Containers, observed)
		}
	}

	status.EndpointReady, err = hasReadyEndpoint(ctx, cluster.Client, binding.Namespace)
	if err != nil {
		return RuntimeStatus{}, newRuntimeError("TARGET_TEMPORARILY_UNAVAILABLE", true, err)
	}
	status.Phase = deriveRuntimePhase(binding.State, status.Containers, status.EndpointReady)
	return status, nil
}

func mapContainerStatus(podName string, container corev1.Container, observed corev1.ContainerStatus) ContainerRuntimeStatus {
	status := ContainerRuntimeStatus{
		PodName:      podName,
		Name:         container.Name,
		State:        "UNKNOWN",
		Ready:        observed.Ready,
		RestartCount: observed.RestartCount,
		Requests:     resourceValues(container.Resources.Requests),
		Limits:       resourceValues(container.Resources.Limits),
	}
	switch {
	case observed.State.Running != nil:
		status.State = "RUNNING"
		status.StartedAt = timePointer(observed.State.Running.StartedAt)
	case observed.State.Waiting != nil:
		status.State = "WAITING"
		status.Reason = observed.State.Waiting.Reason
	case observed.State.Terminated != nil:
		status.State = "TERMINATED"
		status.Reason = observed.State.Terminated.Reason
		status.ExitCode = observed.State.Terminated.ExitCode
		status.StartedAt = timePointer(observed.State.Terminated.StartedAt)
		status.FinishedAt = timePointer(observed.State.Terminated.FinishedAt)
	}
	return status
}

func resourceValues(values corev1.ResourceList) ResourceValues {
	return ResourceValues{
		CPUMillicores:       resourceMilliValue(values, corev1.ResourceCPU),
		MemoryMiB:           resourceMiBValue(values, corev1.ResourceMemory),
		EphemeralStorageMiB: resourceMiBValue(values, corev1.ResourceEphemeralStorage),
	}
}

func resourceMilliValue(values corev1.ResourceList, name corev1.ResourceName) int64 {
	quantity, found := values[name]
	if !found {
		return 0
	}
	return quantity.MilliValue()
}

func resourceMiBValue(values corev1.ResourceList, name corev1.ResourceName) int64 {
	quantity, found := values[name]
	if !found {
		return 0
	}
	return quantity.Value() / (1024 * 1024)
}

func timePointer(value metav1.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	timestamp := value.Time
	return &timestamp
}

func deriveRuntimePhase(bindingState runtimebinding.State, containers []ContainerRuntimeStatus, endpointReady bool) string {
	switch bindingState {
	case runtimebinding.StateDeleting:
		return "TERMINATING"
	case runtimebinding.StateDeleted:
		return "TERMINATED"
	}
	if len(containers) == 0 {
		return "PROVISIONING"
	}
	allReady := endpointReady
	for _, container := range containers {
		if container.State != "RUNNING" || !container.Ready {
			allReady = false
			break
		}
	}
	if allReady {
		return "READY"
	}
	return "DEGRADED"
}
