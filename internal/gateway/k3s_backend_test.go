package gateway

import (
	"context"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	metricsfake "k8s.io/metrics/pkg/client/clientset/versioned/fake"
	"testing"
)

type gatewayFactory struct{ client *fake.Clientset }

func (f gatewayFactory) FromKubeconfig(string) (k3s.ClientSet, error) {
	return k3s.ClientSet{Kubernetes: f.client, Metrics: metricsfake.NewSimpleClientset()}, nil
}
func TestKubernetesBackendReadsActualNodePortAndQuiescesWithoutDeletingService(t *testing.T) {
	ctx := context.Background()
	command := provisioner.CreateWorkloadCommand{InstanceID: "00000000-0000-4000-8000-000000000001", TeamID: "00000000-0000-4000-8000-000000000002", TargetID: "target"}
	namespace, _ := k3s.NamespaceForInstance(command.InstanceID)
	labels := map[string]string{"msgctf.io/instance-id": command.InstanceID, "msgctf.io/team-id": string(command.TeamID), "msgctf.io/container-name": "web", "app.kubernetes.io/managed-by": "secure-provisioner"}
	one := int32(1)
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: namespace, UID: types.UID("svc1"), Labels: labels}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Ports: []corev1.ServicePort{{Port: 8080, NodePort: 31042}}}}
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: namespace, Labels: labels}, Spec: appsv1.DeploymentSpec{Replicas: &one}}
	client := fake.NewSimpleClientset(service, deployment, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, UID: types.UID("ns1"), Labels: labels}})
	cfg := k3s.ClusterConfig{TargetID: "target", Provider: k3s.ProviderLocal, Region: "local", Architecture: "amd64", KubeconfigPath: "unused", PublicGateway: "http://8.8.8.8", ExposureMode: k3s.ExposureModeNodePort, Enabled: true, Gateway: &k3s.GatewayConfig{Enabled: true, UpstreamIP: "8.8.8.8"}, SecurityCapabilities: k3s.SecurityCapabilities{NetworkPolicyProvider: "test", DNSNamespace: "kube-system", DNSPodSelector: map[string]string{"app": "dns"}, NetworkPolicyEnforced: true, SupplementalGroupsPolicyStrict: true, PodPIDLimitEnforced: true}}
	registry, err := k3s.NewRegistry([]k3s.ClusterConfig{cfg}, gatewayFactory{client})
	if err != nil {
		t.Fatal(err)
	}
	backend := &KubernetesBackend{Registry: registry}
	result := provisioner.CreateWorkloadResult{NamespaceUID: "ns1", RuntimeWorkloadID: k3s.RuntimeWorkloadID("target", namespace), Endpoints: []provisioner.WorkloadEndpoint{{ContainerName: "web", Port: 8080, Protocol: "HTTP"}}}
	destination, uid, err := backend.Destination(ctx, command, result)
	if err != nil || destination.TargetPort != 31042 || uid != "svc1" {
		t.Fatal(destination, uid, err)
	}
	record := Record{Command: command, Result: result, Destination: destination, ServiceUID: uid}
	if err = backend.Verify(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err = backend.Quiesce(ctx, record); err != nil {
		t.Fatal(err)
	}
	got, err := client.AppsV1().Deployments(namespace).Get(ctx, "web", metav1.GetOptions{})
	if err != nil || *got.Spec.Replicas != 0 {
		t.Fatal(got, err)
	}
	retained, err := client.CoreV1().Services(namespace).Get(ctx, "web", metav1.GetOptions{})
	if err != nil || retained.Spec.Ports[0].NodePort != 31042 {
		t.Fatal("NodePort released", err)
	}
	record.ServiceUID = "replacement"
	if backend.Verify(ctx, record) == nil {
		t.Fatal("replacement generation accepted")
	}
}

func TestGatewayReplayRequiresEveryPrivateSidecarReady(t *testing.T) {
	c := provisioner.CreateWorkloadCommand{TeamID: "team", Containers: []provisioner.WorkloadContainer{{Name: "web", Image: "web-digest"}, {Name: "db", Image: "db-digest"}}}
	readyPod := func(name, image string) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"msgctf.io/team-id": "team", "app.kubernetes.io/managed-by": "secure-provisioner"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: name, Image: image}}}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: name, Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	}
	pods := []corev1.Pod{readyPod("web", "web-digest")}
	if containersReady(c, pods) == nil {
		t.Fatal("missing private sidecar accepted")
	}
	pods = append(pods, readyPod("db", "db-digest"))
	if err := containersReady(c, pods); err != nil {
		t.Fatal(err)
	}
	pods[1].Status.ContainerStatuses[0].Ready = false
	if containersReady(c, pods) == nil {
		t.Fatal("unready private sidecar accepted")
	}
}
