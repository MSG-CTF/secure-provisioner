package k3s

import (
	"context"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
)

func TestKubernetesImageAgentRequiresPinnedReadyPodOnExpectedNode(t *testing.T) {
	const image = "ghcr.io/msg-ctf/runtime-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	n := imageprep.Node{Name: "node-a", UID: "uid-a", MachineID: "machine", BootID: "boot", Architecture: "AMD64"}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n.Name, UID: types.UID(n.UID)}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{MachineID: n.MachineID, BootID: n.BootID, OperatingSystem: "linux", Architecture: "amd64"}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "agent-a", Namespace: "runtime-system", UID: "pod-uid", Labels: map[string]string{"app.kubernetes.io/name": "runtime-image-agent"}}, Spec: corev1.PodSpec{NodeName: n.Name, Containers: []corev1.Container{{Name: "agent", Image: image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	client := fake.NewSimpleClientset(node, pod)
	target := imageprep.AgentTarget{Namespace: "runtime-system", AgentImage: image}
	if _, err := selectImageAgent(context.Background(), client, target, n); err != nil {
		t.Fatal(err)
	}
	pod.Spec.Containers[0].Image = "mutable:latest"
	_, _ = client.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
	if _, err := selectImageAgent(context.Background(), client, target, n); err == nil {
		t.Fatal("unpinned agent accepted")
	}
	pod.Spec.Containers[0].Image = image
	pod.Spec.NodeName = "other-node"
	_, _ = client.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
	if _, err := selectImageAgent(context.Background(), client, target, n); err == nil {
		t.Fatal("wrong node accepted")
	}
}
