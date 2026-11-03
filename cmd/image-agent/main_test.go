package main

import (
	"context"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
)

func TestAgentKubernetesIdentityUsesCurrentNodeAndActualHostIDs(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: "uid-current"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{MachineID: "machine", BootID: "boot", OperatingSystem: "linux", Architecture: "amd64"}}}
	client := fake.NewSimpleClientset(node)
	actual := imageprep.AgentIdentity{MachineID: "machine", BootID: "boot", OS: "linux", Architecture: "AMD64"}
	got, err := kubernetesIdentity(context.Background(), client, "node-a", actual)
	if err != nil || got.NodeUID != "uid-current" {
		t.Fatalf("identity=%+v %v", got, err)
	}
	actual.BootID = "wrong-host"
	if _, err := kubernetesIdentity(context.Background(), client, "node-a", actual); err == nil {
		t.Fatal("wrong physical host accepted")
	}
}
