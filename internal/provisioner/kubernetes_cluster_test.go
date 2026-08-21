package provisioner

import (
	"testing"
)

func TestRuntimeObjectsApplyIsolationBaseline(t *testing.T) {
	cluster := &kubernetesCluster{}
	instance := Instance{
		InstanceID:  "inst-test",
		TeamID:      101,
		ChallengeID: "xss-101",
	}
	challenge := Challenge{
		ChallengeID:   "xss-101",
		Image:         "registry.example/xss@sha256:778b934e7129d7961f8309d73f3720d465a701704dd63897251f085a67d5e22a",
		ContainerPort: 8080,
		Command:       []string{"/xss-challenge"},
		RuntimeClass:  "runc",
	}
	reservation := Reservation{
		CPUMillicores:       500,
		MemoryMiB:           256,
		EphemeralStorageMiB: 256,
	}
	labels := map[string]string{instanceKey: stableLabel(instance.InstanceID)}

	objects := cluster.runtimeObjects("ctf-test", labels, instance, challenge, reservation)
	podSpec := objects.deployment.Spec.Template.Spec
	container := podSpec.Containers[0]

	if podSpec.AutomountServiceAccountToken == nil || *podSpec.AutomountServiceAccountToken {
		t.Fatal("service account token automount must be disabled")
	}
	if podSpec.SecurityContext == nil || podSpec.SecurityContext.RunAsNonRoot == nil || !*podSpec.SecurityContext.RunAsNonRoot {
		t.Fatal("pod must run as a non-root user")
	}
	if podSpec.SecurityContext.SeccompProfile == nil || string(podSpec.SecurityContext.SeccompProfile.Type) != "RuntimeDefault" {
		t.Fatal("pod must use the RuntimeDefault seccomp profile")
	}
	if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
		t.Fatal("privilege escalation must be disabled")
	}
	if container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatal("root filesystem must be read-only")
	}
	if len(container.SecurityContext.Capabilities.Drop) != 1 || container.SecurityContext.Capabilities.Drop[0] != "ALL" {
		t.Fatal("all Linux capabilities must be dropped")
	}
	if objects.service.Spec.Type != "NodePort" || objects.service.Spec.Ports[0].NodePort != 0 {
		t.Fatal("Kubernetes must allocate the external NodePort")
	}
	if len(objects.defaultDeny.Spec.PolicyTypes) != 2 || len(objects.allowIngress.Spec.Ingress) != 1 {
		t.Fatal("default-deny and explicit challenge ingress policies are required")
	}
}

func TestHTTPEndpoint(t *testing.T) {
	if endpoint := httpEndpoint("3.38.101.0", 32739, "/"); endpoint != "http://3.38.101.0:32739/" {
		t.Fatalf("unexpected endpoint: %s", endpoint)
	}
	if endpoint := httpEndpoint("https://ctf.example.com", 30443, "/health"); endpoint != "https://ctf.example.com:30443/health" {
		t.Fatalf("unexpected URL endpoint: %s", endpoint)
	}
}
