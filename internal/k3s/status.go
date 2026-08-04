package k3s

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
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

type NodeRuntimeStatus struct {
	Ready          bool
	MemoryPressure bool
	DiskPressure   bool
	PIDPressure    bool
	Capacity       ResourceValues
	Allocatable    ResourceValues
	Requested      ResourceValues
	Schedulable    ResourceValues
	Usage          *ResourceUsage
}

type RuntimeStatus struct {
	InstanceID        string
	TargetID          string
	RuntimeWorkloadID string
	Phase             string
	EndpointReady     bool
	MetricsAvailable  bool
	ObservedAt        time.Time
	Node              NodeRuntimeStatus
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
	nodes, err := cluster.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return RuntimeStatus{}, newRuntimeError("TARGET_TEMPORARILY_UNAVAILABLE", true, err)
	}
	if len(nodes.Items) != 1 {
		return RuntimeStatus{}, newRuntimeError("TARGET_TOPOLOGY_INVALID", false, nil)
	}
	node := &nodes.Items[0]

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

	allPods, err := cluster.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return RuntimeStatus{}, newRuntimeError("TARGET_TEMPORARILY_UNAVAILABLE", true, err)
	}

	metricsByPod := make(map[string]metricsv1beta1.PodMetrics)
	var nodeUsage *ResourceUsage
	metricsAvailable := false
	if cluster.Metrics != nil {
		metrics, podMetricsErr := cluster.Metrics.MetricsV1beta1().PodMetricses(binding.Namespace).List(ctx, metav1.ListOptions{})
		nodeMetrics, nodeMetricsErr := cluster.Metrics.MetricsV1beta1().NodeMetricses().Get(ctx, node.Name, metav1.GetOptions{})
		if podMetricsErr == nil && nodeMetricsErr == nil {
			metricsAvailable = true
			for _, metric := range metrics.Items {
				metricsByPod[metric.Name] = metric
			}
			nodeUsage = &ResourceUsage{
				CPUMillicores: resourceMilliValue(nodeMetrics.Usage, corev1.ResourceCPU),
				MemoryMiB:     resourceMiBValue(nodeMetrics.Usage, corev1.ResourceMemory),
			}
		}
	}

	status := RuntimeStatus{
		InstanceID:        binding.InstanceID,
		TargetID:          binding.TargetID,
		RuntimeWorkloadID: binding.RuntimeWorkloadID,
		MetricsAvailable:  metricsAvailable,
		ObservedAt:        r.now().UTC(),
		Node:              mapNodeRuntimeStatus(*node, allPods.Items, nodeUsage),
		Containers:        make([]ContainerRuntimeStatus, 0),
	}
	for index := range pods.Items {
		pod := &pods.Items[index]
		podMetrics, hasMetrics := metricsByPod[pod.Name]
		usageByContainer := make(map[string]corev1.ResourceList)
		if metricsAvailable && hasMetrics {
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
			}
			status.Containers = append(status.Containers, observed)
		}
	}

	if len(status.Containers) > 0 {
		if cluster.Config.ExposureMode == ExposureModeNodePort {
			status.EndpointReady, err = hasReadyNodePortEndpoints(ctx, cluster.Client, binding.Namespace, binding.InstanceID)
		} else {
			status.EndpointReady, err = hasReadyIngressEndpoints(ctx, cluster.Client, binding.Namespace)
		}
		if err != nil {
			return RuntimeStatus{}, newRuntimeError("TARGET_TEMPORARILY_UNAVAILABLE", true, err)
		}
	}
	status.Phase = deriveRuntimePhase(binding.State, status.Containers, status.EndpointReady)
	return status, nil
}

func hasReadyIngressEndpoints(ctx context.Context, client kubernetes.Interface, namespace string) (bool, error) {
	ingress, err := client.NetworkingV1().Ingresses(namespace).Get(ctx, resourceName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	serviceNames := make(map[string]struct{})
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil && strings.TrimSpace(path.Backend.Service.Name) != "" {
				serviceNames[path.Backend.Service.Name] = struct{}{}
			}
		}
	}
	if len(serviceNames) == 0 {
		return false, nil
	}
	for serviceName := range serviceNames {
		serviceReady, listErr := hasReadyServiceEndpoints(ctx, client, namespace, serviceName)
		if listErr != nil {
			return false, listErr
		}
		if !serviceReady {
			return false, nil
		}
	}
	return true, nil
}

func hasReadyNodePortEndpoints(ctx context.Context, client kubernetes.Interface, namespace, instanceID string) (bool, error) {
	services, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{
		"app.kubernetes.io/managed-by": "secure-provisioner",
		"msgctf.io/instance-id":        instanceID,
	}.String()})
	if err != nil {
		return false, err
	}
	found := false
	for _, service := range services.Items {
		if service.Spec.Type != corev1.ServiceTypeNodePort {
			continue
		}
		found = true
		ready, endpointErr := hasReadyServiceEndpoints(ctx, client, namespace, service.Name)
		if endpointErr != nil {
			return false, endpointErr
		}
		if !ready {
			return false, nil
		}
	}
	return found, nil
}

func hasReadyServiceEndpoints(ctx context.Context, client kubernetes.Interface, namespace, serviceName string) (bool, error) {
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
			for _, address := range endpoint.Addresses {
				if strings.TrimSpace(address) != "" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func mapNodeRuntimeStatus(node corev1.Node, pods []corev1.Pod, usage *ResourceUsage) NodeRuntimeStatus {
	requested := ResourceValues{}
	for index := range pods {
		pod := &pods[index]
		if pod.Spec.NodeName != node.Name || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		requested = addResourceValues(requested, podRequestedResources(*pod))
	}
	allocatable := resourceValues(node.Status.Allocatable)
	return NodeRuntimeStatus{
		Ready:          nodeConditionTrue(node.Status.Conditions, corev1.NodeReady),
		MemoryPressure: nodeConditionTrue(node.Status.Conditions, corev1.NodeMemoryPressure),
		DiskPressure:   nodeConditionTrue(node.Status.Conditions, corev1.NodeDiskPressure),
		PIDPressure:    nodeConditionTrue(node.Status.Conditions, corev1.NodePIDPressure),
		Capacity:       resourceValues(node.Status.Capacity),
		Allocatable:    allocatable,
		Requested:      requested,
		Schedulable:    subtractResourceValuesWithFloor(allocatable, requested),
		Usage:          usage,
	}
}

func nodeConditionTrue(conditions []corev1.NodeCondition, conditionType corev1.NodeConditionType) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func podRequestedResources(pod corev1.Pod) ResourceValues {
	regular := ResourceValues{}
	for _, container := range pod.Spec.Containers {
		regular = addResourceValues(regular, resourceValues(container.Resources.Requests))
	}

	restartableInit := ResourceValues{}
	initMaximum := ResourceValues{}
	for _, container := range pod.Spec.InitContainers {
		requests := resourceValues(container.Resources.Requests)
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			regular = addResourceValues(regular, requests)
			restartableInit = addResourceValues(restartableInit, requests)
			initMaximum = maxResourceValues(initMaximum, restartableInit)
			continue
		}
		initMaximum = maxResourceValues(initMaximum, addResourceValues(restartableInit, requests))
	}

	requested := maxResourceValues(regular, initMaximum)
	return addResourceValues(requested, resourceValues(pod.Spec.Overhead))
}

func addResourceValues(first, second ResourceValues) ResourceValues {
	return ResourceValues{
		CPUMillicores:       first.CPUMillicores + second.CPUMillicores,
		MemoryMiB:           first.MemoryMiB + second.MemoryMiB,
		EphemeralStorageMiB: first.EphemeralStorageMiB + second.EphemeralStorageMiB,
	}
}

func maxResourceValues(first, second ResourceValues) ResourceValues {
	return ResourceValues{
		CPUMillicores:       max(first.CPUMillicores, second.CPUMillicores),
		MemoryMiB:           max(first.MemoryMiB, second.MemoryMiB),
		EphemeralStorageMiB: max(first.EphemeralStorageMiB, second.EphemeralStorageMiB),
	}
}

func subtractResourceValuesWithFloor(first, second ResourceValues) ResourceValues {
	return ResourceValues{
		CPUMillicores:       max(first.CPUMillicores-second.CPUMillicores, 0),
		MemoryMiB:           max(first.MemoryMiB-second.MemoryMiB, 0),
		EphemeralStorageMiB: max(first.EphemeralStorageMiB-second.EphemeralStorageMiB, 0),
	}
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
