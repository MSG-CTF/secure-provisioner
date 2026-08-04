package k3s

import (
	"context"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
	metricsfake "k8s.io/metrics/pkg/client/clientset/versioned/fake"
)

func TestStatusReaderRoutesOnlyToBindingTarget(t *testing.T) {
	binding, objects, metric := statusFixture(t)
	awsClient := fake.NewSimpleClientset(objects...)
	gcpClient := fake.NewSimpleClientset()
	registry, err := NewRegistry([]ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
		validClusterConfig("gcp-dev", ProviderGCP, "gcp-kubeconfig"),
	}, &sequenceFactory{
		clients: []kubernetes.Interface{awsClient, gcpClient},
		metrics: []metricsclient.Interface{metricsfake.NewSimpleClientset(metric), metricsfake.NewSimpleClientset()},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewStatusReader(registry)
	if err != nil {
		t.Fatal(err)
	}

	status, err := reader.Get(context.Background(), binding)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if status.TargetID != "aws-dev" || len(status.Containers) != 1 {
		t.Fatalf("Get() = %#v", status)
	}
	if len(gcpClient.Actions()) != 0 {
		t.Fatalf("gcp client actions = %#v, want none", gcpClient.Actions())
	}
}

func TestStatusReaderMapsRunningContainerAndResources(t *testing.T) {
	binding, objects, metric := statusFixture(t)
	registry := statusRegistry(t, objects, metric)
	reader, _ := NewStatusReader(registry)
	reader.now = func() time.Time { return time.Date(2026, 7, 26, 12, 34, 56, 0, time.UTC) }

	status, err := reader.Get(context.Background(), binding)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if status.Phase != "READY" || !status.EndpointReady || !status.MetricsAvailable {
		t.Fatalf("summary = %#v", status)
	}
	if !status.ObservedAt.Equal(time.Date(2026, 7, 26, 12, 34, 56, 0, time.UTC)) {
		t.Fatalf("ObservedAt = %v", status.ObservedAt)
	}
	container := status.Containers[0]
	if container.PodName != "challenge-pod" || container.Name != "challenge" || container.State != "RUNNING" || !container.Ready || container.RestartCount != 2 {
		t.Fatalf("container status = %#v", container)
	}
	if container.Requests.CPUMillicores != 500 || container.Requests.MemoryMiB != 512 || container.Requests.EphemeralStorageMiB != 1024 {
		t.Fatalf("requests = %#v", container.Requests)
	}
	if container.Usage == nil || container.Usage.CPUMillicores != 12 || container.Usage.MemoryMiB != 34 {
		t.Fatalf("usage = %#v", container.Usage)
	}
}

func TestStatusReaderRequiresReadyEndpointForIngressService(t *testing.T) {
	binding, objects, _ := statusFixture(t)
	endpoint := objects[3].(*discoveryv1.EndpointSlice)
	endpoint.Labels[discoveryv1.LabelServiceName] = "internal"
	reader, _ := NewStatusReader(statusRegistry(t, objects, nil))

	status, err := reader.Get(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if status.EndpointReady || status.Phase != "DEGRADED" {
		t.Fatalf("status = %#v, want public endpoint not ready", status)
	}
}

func TestStatusReaderSupportsExposedServiceNamedForContainer(t *testing.T) {
	binding, objects, _ := statusFixture(t)
	endpoint := objects[3].(*discoveryv1.EndpointSlice)
	endpoint.Labels[discoveryv1.LabelServiceName] = "web"
	ingress := objects[5].(*networkingv1.Ingress)
	ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name = "web"
	reader, _ := NewStatusReader(statusRegistry(t, objects, nil))

	status, err := reader.Get(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if !status.EndpointReady || status.Phase != "READY" {
		t.Fatalf("status = %#v, want public web endpoint ready", status)
	}
}

func TestStatusReaderCalculatesSingleNodeResources(t *testing.T) {
	binding, objects, metric := statusFixture(t)
	objects = append(objects,
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "active-system-pod"},
			Spec: corev1.PodSpec{
				NodeName: "node-1",
				Containers: []corev1.Container{
					{Resources: corev1.ResourceRequirements{Requests: testResourceList("200m", "100Mi", "20Mi")}},
					{Resources: corev1.ResourceRequirements{Requests: testResourceList("100m", "50Mi", "10Mi")}},
				},
				InitContainers: []corev1.Container{
					{Resources: corev1.ResourceRequirements{Requests: testResourceList("800m", "64Mi", "5Mi")}},
					{Resources: corev1.ResourceRequirements{Requests: testResourceList("400m", "256Mi", "40Mi")}},
				},
				Overhead: testResourceList("50m", "10Mi", "0"),
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "completed-pod"},
			Spec: corev1.PodSpec{
				NodeName:   "node-1",
				Containers: []corev1.Container{{Resources: corev1.ResourceRequirements{Requests: testResourceList("10", "10Gi", "10Gi")}}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "other-node-pod"},
			Spec: corev1.PodSpec{
				NodeName:   "node-2",
				Containers: []corev1.Container{{Resources: corev1.ResourceRequirements{Requests: testResourceList("10", "10Gi", "10Gi")}}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)
	reader, _ := NewStatusReader(statusRegistry(t, objects, metric))

	status, err := reader.Get(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	node := status.Node
	if !node.Ready || node.MemoryPressure || node.DiskPressure || node.PIDPressure {
		t.Fatalf("conditions = %#v", node)
	}
	if node.Capacity != (ResourceValues{CPUMillicores: 2000, MemoryMiB: 4096, EphemeralStorageMiB: 20480}) {
		t.Fatalf("capacity = %#v", node.Capacity)
	}
	if node.Allocatable != (ResourceValues{CPUMillicores: 1800, MemoryMiB: 3584, EphemeralStorageMiB: 18432}) {
		t.Fatalf("allocatable = %#v", node.Allocatable)
	}
	if node.Requested != (ResourceValues{CPUMillicores: 1350, MemoryMiB: 778, EphemeralStorageMiB: 1064}) {
		t.Fatalf("requested = %#v", node.Requested)
	}
	if node.Schedulable != (ResourceValues{CPUMillicores: 450, MemoryMiB: 2806, EphemeralStorageMiB: 17368}) {
		t.Fatalf("schedulable = %#v", node.Schedulable)
	}
	if node.Usage == nil || *node.Usage != (ResourceUsage{CPUMillicores: 600, MemoryMiB: 1024}) {
		t.Fatalf("usage = %#v", node.Usage)
	}
}

func TestStatusReaderClampsNegativeSchedulableResourcesToZero(t *testing.T) {
	binding, objects, metric := statusFixture(t)
	node := objects[4].(*corev1.Node)
	node.Status.Allocatable = testResourceList("100m", "100Mi", "100Mi")
	reader, _ := NewStatusReader(statusRegistry(t, objects, metric))

	status, err := reader.Get(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if status.Node.Schedulable != (ResourceValues{}) {
		t.Fatalf("schedulable = %#v", status.Node.Schedulable)
	}
}

func TestStatusReaderRejectsTargetsWithoutExactlyOneNode(t *testing.T) {
	for _, test := range []struct {
		name    string
		objects func([]runtime.Object) []runtime.Object
	}{
		{
			name: "no nodes",
			objects: func(objects []runtime.Object) []runtime.Object {
				return objects[:4]
			},
		},
		{
			name: "multiple nodes",
			objects: func(objects []runtime.Object) []runtime.Object {
				return append(objects, testNode("node-2"))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding, objects, metric := statusFixture(t)
			reader, _ := NewStatusReader(statusRegistry(t, test.objects(objects), metric))

			_, err := reader.Get(context.Background(), binding)
			if runtimeErrorCode(t, err) != "TARGET_TOPOLOGY_INVALID" {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestStatusReaderMapsWaitingAndTerminatedReasons(t *testing.T) {
	binding, objects, _ := statusFixture(t)
	pod := objects[2].(*corev1.Pod)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{
		{
			Name:         "challenge",
			RestartCount: 4,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
				Reason: "CrashLoopBackOff",
			}},
		},
	}
	sidecarResources := corev1.ResourceRequirements{Requests: corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("25m"),
		corev1.ResourceMemory: resource.MustParse("32Mi"),
	}}
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar", Resources: sidecarResources})
	pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
		Name: "sidecar",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			Reason:   "OOMKilled",
			ExitCode: 137,
		}},
	})
	registry := statusRegistry(t, objects, nil)
	reader, _ := NewStatusReader(registry)

	status, err := reader.Get(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Containers) != 2 {
		t.Fatalf("containers = %#v", status.Containers)
	}
	if status.Containers[0].State != "WAITING" || status.Containers[0].Reason != "CrashLoopBackOff" {
		t.Fatalf("waiting = %#v", status.Containers[0])
	}
	if status.Containers[1].State != "TERMINATED" || status.Containers[1].Reason != "OOMKilled" || status.Containers[1].ExitCode != 137 {
		t.Fatalf("terminated = %#v", status.Containers[1])
	}
}

func TestStatusReaderReturnsPartialSuccessWhenMetricsAreMissing(t *testing.T) {
	binding, objects, _ := statusFixture(t)
	reader, _ := NewStatusReader(statusRegistry(t, objects, nil))

	status, err := reader.Get(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if status.MetricsAvailable || status.Containers[0].Usage != nil {
		t.Fatalf("metrics fields = %#v", status)
	}
	if status.Node.Usage != nil {
		t.Fatalf("node usage = %#v", status.Node.Usage)
	}
	if status.Containers[0].State != "RUNNING" {
		t.Fatalf("container state = %#v", status.Containers[0])
	}
}

func TestStatusReaderRejectsNamespaceOwnershipMismatch(t *testing.T) {
	binding, objects, metric := statusFixture(t)
	objects[0].(*corev1.Namespace).Labels["msgctf.io/instance-id"] = "foreign-instance"
	reader, _ := NewStatusReader(statusRegistry(t, objects, metric))

	_, err := reader.Get(context.Background(), binding)
	if runtimeErrorCode(t, err) != "RUNTIME_OWNERSHIP_MISMATCH" {
		t.Fatalf("error = %v", err)
	}
}

func TestStatusReaderRejectsNamespaceUIDMismatch(t *testing.T) {
	binding, objects, metric := statusFixture(t)
	objects[0].(*corev1.Namespace).UID = "replacement-namespace-uid"
	reader, _ := NewStatusReader(statusRegistry(t, objects, metric))

	_, err := reader.Get(context.Background(), binding)
	if runtimeErrorCode(t, err) != "RUNTIME_IDENTITY_MISMATCH" {
		t.Fatalf("error = %v, want RUNTIME_IDENTITY_MISMATCH", err)
	}
}

func TestStatusReaderReturnsProvisioningWhenNoPodsExist(t *testing.T) {
	binding, objects, _ := statusFixture(t)
	objects = []runtime.Object{objects[0], objects[1], objects[4]}
	reader, _ := NewStatusReader(statusRegistry(t, objects, nil))

	status, err := reader.Get(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != "PROVISIONING" || len(status.Containers) != 0 {
		t.Fatalf("status = %#v", status)
	}
}

func statusFixture(t *testing.T) (runtimebinding.Binding, []runtime.Object, *metricsv1beta1.PodMetrics) {
	t.Helper()
	command := validCreateCommand("aws-dev")
	cluster := validCluster("aws-dev")
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Deployment.Status = appsv1.DeploymentStatus{
		ObservedGeneration: 1,
		AvailableReplicas:  1,
		UpdatedReplicas:    1,
	}
	resources.Deployment.Generation = 1
	startedAt := metav1.NewTime(time.Date(2026, 7, 26, 12, 30, 0, 0, time.UTC))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: resources.Namespace.Name,
			Name:      "challenge-pod",
			UID:       "pod-uid",
			Labels:    copyLabels(resources.Deployment.Spec.Template.Labels),
		},
		Spec: resources.Deployment.Spec.Template.Spec,
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.0.0.8",
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         "challenge",
				Ready:        true,
				RestartCount: 2,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{
					StartedAt: startedAt,
				}},
			}},
		},
	}
	pod.Spec.NodeName = "node-1"
	ready := true
	endpoint := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: resources.Namespace.Name,
			Name:      "challenge",
			Labels:    map[string]string{discoveryv1.LabelServiceName: resourceName},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.8"},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
	}
	metric := &metricsv1beta1.PodMetrics{
		TypeMeta:   metav1.TypeMeta{APIVersion: "metrics.k8s.io/v1beta1", Kind: "PodMetrics"},
		ObjectMeta: metav1.ObjectMeta{Namespace: resources.Namespace.Name, Name: pod.Name},
		Timestamp:  metav1.NewTime(time.Date(2026, 7, 26, 12, 34, 55, 0, time.UTC)),
		Window:     metav1.Duration{Duration: 30 * time.Second},
		Containers: []metricsv1beta1.ContainerMetrics{{
			Name: "challenge",
			Usage: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("12m"),
				corev1.ResourceMemory: resource.MustParse("34Mi"),
			},
		}},
	}
	binding := runtimebinding.Binding{
		InstanceID:        command.InstanceID,
		TeamID:            command.TeamID,
		TargetID:          command.TargetID,
		Namespace:         resources.Namespace.Name,
		NamespaceUID:      "namespace-uid-01",
		RuntimeWorkloadID: resources.RuntimeWorkloadID,
		State:             runtimebinding.StateCreated,
		CreatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	}
	resources.Namespace.UID = "namespace-uid-01"
	return binding, []runtime.Object{
		resources.Namespace,
		resources.Deployment,
		pod,
		endpoint,
		testNode("node-1"),
		resources.Ingress,
	}, metric
}

func statusRegistry(t *testing.T, objects []runtime.Object, metric *metricsv1beta1.PodMetrics) *Registry {
	t.Helper()
	kubeClient := fake.NewSimpleClientset(objects...)
	metricsClient := metricsfake.NewSimpleClientset()
	if metric != nil {
		nodeMetric := &metricsv1beta1.NodeMetrics{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Usage: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("600m"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
		}
		metricsClient.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, &metricsv1beta1.PodMetricsList{Items: []metricsv1beta1.PodMetrics{*metric}}, nil
		})
		metricsClient.PrependReactor("get", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nodeMetric, nil
		})
	}
	registry, err := NewRegistry(
		[]ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")},
		&sequenceFactory{
			clients: []kubernetes.Interface{kubeClient},
			metrics: []metricsclient.Interface{metricsClient},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func testNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Capacity:    testResourceList("2", "4Gi", "20Gi"),
			Allocatable: testResourceList("1800m", "3584Mi", "18Gi"),
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
				{Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse},
				{Type: corev1.NodePIDPressure, Status: corev1.ConditionFalse},
			},
		},
	}
}

func testResourceList(cpu, memory, ephemeral string) corev1.ResourceList {
	return corev1.ResourceList{
		corev1.ResourceCPU:              resource.MustParse(cpu),
		corev1.ResourceMemory:           resource.MustParse(memory),
		corev1.ResourceEphemeralStorage: resource.MustParse(ephemeral),
	}
}
