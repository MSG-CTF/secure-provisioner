package k3s

import (
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestBuildResourceSetCreatesOwnedKubernetesResources(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	const namespace = "ctf-018f3f1e21b87a91a30b63b3400fd001"
	if resources.Namespace.Name != namespace {
		t.Fatalf("namespace = %q, want %q", resources.Namespace.Name, namespace)
	}
	if resources.Deployment.Namespace != namespace || resources.Service.Namespace != namespace || resources.Ingress.Namespace != namespace {
		t.Fatal("resources are not all placed in the instance namespace")
	}
	if resources.Deployment.Name != resourceName || resources.Service.Name != resourceName || resources.Ingress.Name != resourceName {
		t.Fatal("resources do not have deterministic names")
	}

	wantOwnerLabels := map[string]string{
		"managed-by":  "secure-provisioner",
		"instance-id": command.InstanceID,
		"team-id":     "42",
	}
	for resource, labels := range map[string]map[string]string{
		"namespace":  resources.Namespace.Labels,
		"deployment": resources.Deployment.Labels,
		"service":    resources.Service.Labels,
		"ingress":    resources.Ingress.Labels,
	} {
		for key, want := range wantOwnerLabels {
			if got := labels[key]; got != want {
				t.Fatalf("%s label %q = %q, want %q", resource, key, got, want)
			}
		}
	}

	container := resources.Deployment.Spec.Template.Spec.Containers[0]
	if container.Image != command.Image {
		t.Fatalf("image = %q, want %q", container.Image, command.Image)
	}
	if container.Ports[0].ContainerPort != int32(command.ContainerPort) {
		t.Fatalf("container port = %d, want %d", container.Ports[0].ContainerPort, command.ContainerPort)
	}
	if resources.Service.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Fatalf("service type = %s, want ClusterIP", resources.Service.Spec.Type)
	}
	for resource, selector := range map[string]map[string]string{
		"deployment": resources.Deployment.Spec.Selector.MatchLabels,
		"service":    resources.Service.Spec.Selector,
	} {
		if !reflect.DeepEqual(selector, resources.Deployment.Spec.Template.Labels) {
			t.Fatalf("%s selector = %#v, pod labels = %#v", resource, selector, resources.Deployment.Spec.Template.Labels)
		}
	}

	path := resources.Ingress.Spec.Rules[0].HTTP.Paths[0]
	if path.Path != "/instances/"+command.InstanceID {
		t.Fatalf("path = %q, want instance path", path.Path)
	}
	if path.Backend.Service.Name != resourceName || path.Backend.Service.Port.Number != int32(command.ContainerPort) {
		t.Fatalf("ingress backend = %#v, want challenge:%d", path.Backend.Service, command.ContainerPort)
	}
}

func TestBuildResourceSetSetsCPUAndMemoryAndEphemeralStorageRequestsAndLimits(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	limits := resources.Deployment.Spec.Template.Spec.Containers[0].Resources
	for name, want := range (corev1.ResourceList{
		corev1.ResourceCPU:              *resourceQuantityMilli(command.ResourceLimits.CPUMillicores),
		corev1.ResourceMemory:           *resourceQuantityBytes(command.ResourceLimits.MemoryMiB),
		corev1.ResourceEphemeralStorage: *resourceQuantityBytes(command.ResourceLimits.EphemeralStorageMiB),
	}) {
		if got := limits.Requests[name]; got.Cmp(want) != 0 {
			t.Errorf("request %s = %s, want %s", name, got.String(), want.String())
		}
		if got := limits.Limits[name]; got.Cmp(want) != 0 {
			t.Errorf("limit %s = %s, want %s", name, got.String(), want.String())
		}
	}
}

func TestBuildResourceSetRejectsInvalidCommandWithoutEmbeddingSensitiveData(t *testing.T) {
	secretImage := "registry.example.invalid/private/secret-challenge:token-123"
	for _, mutate := range []func(*provisioner.CreateWorkloadCommand){
		func(command *provisioner.CreateWorkloadCommand) { command.InstanceID = "not-a-uuid" },
		func(command *provisioner.CreateWorkloadCommand) { command.TargetID = "other-target" },
		func(command *provisioner.CreateWorkloadCommand) { command.Image = "" },
		func(command *provisioner.CreateWorkloadCommand) { command.ContainerPort = 0 },
		func(command *provisioner.CreateWorkloadCommand) { command.ResourceLimits.CPUMillicores = 0 },
		func(command *provisioner.CreateWorkloadCommand) { command.ResourceLimits.MemoryMiB = 0 },
		func(command *provisioner.CreateWorkloadCommand) { command.ResourceLimits.EphemeralStorageMiB = 0 },
	} {
		command := validCreateCommand("aws-dev")
		command.Image = secretImage
		mutate(&command)

		_, err := BuildResourceSet(validCluster("aws-dev"), command)
		if runtimeErrorCode(t, err) != "INVALID_WORKLOAD" {
			t.Fatalf("code = %q, want INVALID_WORKLOAD", runtimeErrorCode(t, err))
		}
		if strings.Contains(err.Error(), secretImage) || strings.Contains(err.Error(), command.TargetID) {
			t.Fatalf("error exposes command input: %v", err)
		}
	}
}

func TestBuildResourceSetRejectsResourceValuesThatOverflowByteQuantities(t *testing.T) {
	maxMiB := int(math.MaxInt64 / (1024 * 1024))
	for _, mutate := range []func(*provisioner.CreateWorkloadCommand){
		func(command *provisioner.CreateWorkloadCommand) { command.ResourceLimits.MemoryMiB = maxMiB + 1 },
		func(command *provisioner.CreateWorkloadCommand) {
			command.ResourceLimits.EphemeralStorageMiB = maxMiB + 1
		},
	} {
		command := validCreateCommand("aws-dev")
		mutate(&command)

		_, err := BuildResourceSet(validCluster("aws-dev"), command)
		if runtimeErrorCode(t, err) != "INVALID_WORKLOAD" {
			t.Fatalf("code = %q, want INVALID_WORKLOAD", runtimeErrorCode(t, err))
		}
	}
}

func TestRuntimeWorkloadIDAndServiceURL(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	const namespace = "ctf-018f3f1e21b87a91a30b63b3400fd001"
	if got, want := RuntimeWorkloadID(command.TargetID, namespace), "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge"; got != want {
		t.Fatalf("RuntimeWorkloadID() = %q, want %q", got, want)
	}
	if resources.RuntimeWorkloadID != "aws-dev/ctf-018f3f1e21b87a91a30b63b3400fd001/challenge" {
		t.Fatalf("RuntimeWorkloadID = %q", resources.RuntimeWorkloadID)
	}
	if resources.ServiceURL != "https://gateway.example.invalid/instances/"+command.InstanceID {
		t.Fatalf("ServiceURL = %q", resources.ServiceURL)
	}
}

func validCluster(targetID string) Cluster {
	return Cluster{Config: ClusterConfig{
		TargetID:      targetID,
		PublicGateway: "https://gateway.example.invalid",
		IngressClass:  "nginx",
	}}
}

func validCreateCommand(targetID string) provisioner.CreateWorkloadCommand {
	return provisioner.CreateWorkloadCommand{
		RequestID:     "req-01",
		InstanceID:    "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:        42,
		RuntimeType:   provisioner.RuntimeTypeKubernetes,
		TargetID:      targetID,
		Image:         "registry.example.invalid/challenges/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ContainerPort: 8080,
		ResourceLimits: provisioner.ResourceLimits{
			CPUMillicores:       500,
			MemoryMiB:           512,
			EphemeralStorageMiB: 1024,
		},
	}
}

func resourceQuantityMilli(value int) *resource.Quantity {
	return resource.NewMilliQuantity(int64(value), resource.DecimalSI)
}

func resourceQuantityBytes(value int) *resource.Quantity {
	return resource.NewQuantity(int64(value)*1024*1024, resource.BinarySI)
}
