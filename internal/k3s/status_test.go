package k3s

import (
	"context"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
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

func TestStatusReaderReturnsProvisioningWhenNoPodsExist(t *testing.T) {
	binding, objects, _ := statusFixture(t)
	objects = objects[:2]
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
		RuntimeWorkloadID: resources.RuntimeWorkloadID,
		State:             runtimebinding.StateCreated,
		CreatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	}
	return binding, []runtime.Object{resources.Namespace, resources.Deployment, pod, endpoint}, metric
}

func statusRegistry(t *testing.T, objects []runtime.Object, metric *metricsv1beta1.PodMetrics) *Registry {
	t.Helper()
	kubeClient := fake.NewSimpleClientset(objects...)
	metricsClient := metricsfake.NewSimpleClientset()
	if metric != nil {
		metricsClient.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, &metricsv1beta1.PodMetricsList{Items: []metricsv1beta1.PodMetrics{*metric}}, nil
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
