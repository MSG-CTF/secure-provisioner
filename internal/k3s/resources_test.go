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
		"app.kubernetes.io/managed-by": "secure-provisioner",
		"app.kubernetes.io/name":       resourceName,
		"msgctf.io/instance-id":        command.InstanceID,
		"msgctf.io/team-id":            "42",
	}
	for resource, labels := range map[string]map[string]string{
		"namespace": resources.Namespace.Labels,
		"ingress":   resources.Ingress.Labels,
	} {
		assertExactOwnershipLabels(t, resource, labels, wantOwnerLabels)
	}
	wantContainerLabels := copyLabels(wantOwnerLabels)
	wantContainerLabels[containerNameLabel] = resourceName
	for resource, labels := range map[string]map[string]string{
		"deployment":   resources.Deployment.Labels,
		"pod template": resources.Deployment.Spec.Template.Labels,
		"service":      resources.Service.Labels,
	} {
		assertExactOwnershipLabels(t, resource, labels, wantContainerLabels)
	}
	if resources.Deployment.Spec.Replicas == nil || *resources.Deployment.Spec.Replicas != 1 {
		t.Fatalf("replicas = %v, want explicit 1", resources.Deployment.Spec.Replicas)
	}

	container := resources.Deployment.Spec.Template.Spec.Containers[0]
	if container.Image != command.Containers[0].Image {
		t.Fatalf("image = %q, want %q", container.Image, command.Containers[0].Image)
	}
	if container.Ports[0].ContainerPort != int32(command.Containers[0].Ports[0]) {
		t.Fatalf("container port = %d, want %d", container.Ports[0].ContainerPort, command.Containers[0].Ports[0])
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

	const wantSpecHash = "2d0bc30d1f4d428f92e20d14430b8a0370ab5dedad7df62dfbdb99c2b9ab4161"
	if resources.ExpectedSpecHash != wantSpecHash {
		t.Fatalf("ExpectedSpecHash = %q, want stable SHA-256", resources.ExpectedSpecHash)
	}
	for resource, annotations := range map[string]map[string]string{
		"deployment":   resources.Deployment.Annotations,
		"pod template": resources.Deployment.Spec.Template.Annotations,
	} {
		got := annotations[specHashAnnotation]
		if got != wantSpecHash {
			t.Fatalf("%s spec hash = %q, want %q", resource, got, wantSpecHash)
		}
		if strings.Contains(got, command.Containers[0].Image) || strings.Contains(got, validCluster("aws-dev").Config.PublicGateway) {
			t.Fatalf("%s spec hash exposes sensitive input", resource)
		}
	}

	path := resources.Ingress.Spec.Rules[0].HTTP.Paths[0]
	if path.Path != "/instances/"+command.InstanceID {
		t.Fatalf("path = %q, want instance path", path.Path)
	}
	if path.Backend.Service.Name != resourceName || path.Backend.Service.Port.Number != int32(command.Containers[0].Ports[0]) {
		t.Fatalf("ingress backend = %#v, want challenge:%d", path.Backend.Service, command.Containers[0].Ports[0])
	}
}

func TestBuildResourceSetSpecHashTracksSpecButNotRequestMetadata(t *testing.T) {
	command := validCreateCommand("aws-dev")
	first, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	command.RequestID = "a-different-retry-request"
	retry, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	if retry.ExpectedSpecHash != first.ExpectedSpecHash {
		t.Fatalf("request metadata changed spec hash: %q != %q", retry.ExpectedSpecHash, first.ExpectedSpecHash)
	}

	command.Containers[0].Image = "registry.example.invalid/challenges/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	revision, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	if revision.ExpectedSpecHash == first.ExpectedSpecHash {
		t.Fatal("image revision did not change spec hash")
	}
}

func assertExactOwnershipLabels(t *testing.T, resource string, got, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s labels = %#v, want %#v", resource, got, want)
	}
	for _, obsoleteKey := range []string{"managed-by", "instance-id", "team-id", "app"} {
		if _, found := got[obsoleteKey]; found {
			t.Fatalf("%s has obsolete label %q", resource, obsoleteKey)
		}
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

func TestBuildResourceSetDistributesAggregateLimitsExactly(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.Deployments) != 2 {
		t.Fatalf("deployments = %d, want 2", len(resources.Deployments))
	}

	want := map[string]provisioner.ResourceLimits{
		"web": {
			CPUMillicores:       251,
			MemoryMiB:           257,
			EphemeralStorageMiB: 513,
		},
		"internal": {
			CPUMillicores:       250,
			MemoryMiB:           256,
			EphemeralStorageMiB: 512,
		},
	}
	gotTotal := provisioner.ResourceLimits{}
	for _, deployment := range resources.Deployments {
		container := deployment.Spec.Template.Spec.Containers[0]
		expected, found := want[container.Name]
		if !found {
			t.Fatalf("unexpected container %q", container.Name)
		}
		got := provisioner.ResourceLimits{
			CPUMillicores:       int(container.Resources.Limits.Cpu().MilliValue()),
			MemoryMiB:           int(container.Resources.Limits.Memory().Value() / (1024 * 1024)),
			EphemeralStorageMiB: int(container.Resources.Limits.StorageEphemeral().Value() / (1024 * 1024)),
		}
		if got != expected {
			t.Fatalf("%s limits = %#v, want %#v", container.Name, got, expected)
		}
		gotTotal.CPUMillicores += got.CPUMillicores
		gotTotal.MemoryMiB += got.MemoryMiB
		gotTotal.EphemeralStorageMiB += got.EphemeralStorageMiB
	}
	if gotTotal != command.ResourceLimits {
		t.Fatalf("distributed total = %#v, want %#v", gotTotal, command.ResourceLimits)
	}
}

func TestBuildResourceSetCreatesMultipleContainerResources(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.Deployments) != 2 || len(resources.Services) != 2 {
		t.Fatalf("resources = %d deployments, %d services", len(resources.Deployments), len(resources.Services))
	}
	if resources.Deployments[0].Name != "web" || resources.Deployments[1].Name != "internal" {
		t.Fatalf("deployment names = %q, %q", resources.Deployments[0].Name, resources.Deployments[1].Name)
	}
	if resources.Services[0].Name != "web" || resources.Services[1].Name != "internal" {
		t.Fatalf("service names = %q, %q", resources.Services[0].Name, resources.Services[1].Name)
	}
	if len(resources.Services[1].Spec.Ports) != 2 ||
		resources.Services[1].Spec.Ports[0].Port != 8080 ||
		resources.Services[1].Spec.Ports[1].Port != 9090 {
		t.Fatalf("internal service ports = %#v", resources.Services[1].Spec.Ports)
	}
	paths := resources.Ingress.Spec.Rules[0].HTTP.Paths
	if len(paths) != 1 {
		t.Fatalf("ingress paths = %#v, want one exposed port", paths)
	}
	if paths[0].Path != "/instances/"+command.InstanceID ||
		paths[0].Backend.Service.Name != "web" ||
		paths[0].Backend.Service.Port.Number != 8080 {
		t.Fatalf("public path = %#v", paths[0])
	}
	if len(resources.Endpoints) != 1 ||
		resources.Endpoints[0].ContainerName != "web" ||
		resources.Endpoints[0].Port != 8080 ||
		resources.ServiceURL != resources.Endpoints[0].ServiceURL {
		t.Fatalf("endpoints = %#v, service URL = %q", resources.Endpoints, resources.ServiceURL)
	}
}

func TestBuildResourceSetUsesNodePortOnlyForExposedContainers(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	cluster := validCluster("aws-dev")
	cluster.Config.ExposureMode = ExposureModeNodePort
	cluster.Config.PublicGateway = "http://203.0.113.10"

	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	if resources.Ingress != nil {
		t.Fatalf("Ingress = %#v, want nil in NodePort mode", resources.Ingress)
	}
	if resources.Services[0].Name != "web" || resources.Services[0].Spec.Type != corev1.ServiceTypeNodePort {
		t.Fatalf("public service = %#v, want web NodePort", resources.Services[0])
	}
	if resources.Services[1].Name != "internal" || resources.Services[1].Spec.Type != corev1.ServiceTypeClusterIP {
		t.Fatalf("internal service = %#v, want internal ClusterIP", resources.Services[1])
	}
	if len(resources.Endpoints) != 0 || resources.ServiceURL != "" {
		t.Fatalf("unallocated endpoints = %#v, service URL = %q", resources.Endpoints, resources.ServiceURL)
	}
}

func TestBuildNodePortEndpointsUsesKubernetesAllocationsInServiceOrder(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	cluster := validCluster("aws-dev")
	cluster.Config.ExposureMode = ExposureModeNodePort
	cluster.Config.PublicGateway = "http://203.0.113.10"
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Services[0].Spec.Ports[0].NodePort = 31042

	endpoints, err := BuildNodePortEndpoints(cluster.Config.PublicGateway, resources.Services)
	if err != nil {
		t.Fatal(err)
	}
	want := []provisioner.WorkloadEndpoint{{ContainerName: "web", Port: 8080, ServiceURL: "http://203.0.113.10:31042"}}
	if !reflect.DeepEqual(endpoints, want) {
		t.Fatalf("endpoints = %#v, want %#v", endpoints, want)
	}
}

func TestBuildNodePortEndpointsRejectsMissingAllocation(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	cluster := validCluster("aws-dev")
	cluster.Config.ExposureMode = ExposureModeNodePort
	cluster.Config.PublicGateway = "http://203.0.113.10"
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}

	_, err = BuildNodePortEndpoints(cluster.Config.PublicGateway, resources.Services)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
}

func TestBuildResourceSetRejectsInvalidCommandWithoutEmbeddingSensitiveData(t *testing.T) {
	secretImage := "registry.example.invalid/private/secret-challenge:token-123"
	for _, mutate := range []func(*provisioner.CreateWorkloadCommand){
		func(command *provisioner.CreateWorkloadCommand) { command.InstanceID = "not-a-uuid" },
		func(command *provisioner.CreateWorkloadCommand) { command.TargetID = "other-target" },
		func(command *provisioner.CreateWorkloadCommand) { command.Containers[0].Image = "" },
		func(command *provisioner.CreateWorkloadCommand) { command.Containers[0].Ports[0] = 0 },
		func(command *provisioner.CreateWorkloadCommand) { command.ResourceLimits.CPUMillicores = 0 },
		func(command *provisioner.CreateWorkloadCommand) { command.ResourceLimits.MemoryMiB = 0 },
		func(command *provisioner.CreateWorkloadCommand) { command.ResourceLimits.EphemeralStorageMiB = 0 },
	} {
		command := validCreateCommand("aws-dev")
		command.Containers[0].Image = secretImage
		mutate(&command)

		_, err := BuildResourceSet(validCluster("aws-dev"), command)
		if runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
			t.Fatalf("code = %q, want INVALID_CREATE_COMMAND", runtimeErrorCode(t, err))
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
		if runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
			t.Fatalf("code = %q, want INVALID_CREATE_COMMAND", runtimeErrorCode(t, err))
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
		RequestID:   "req-01",
		InstanceID:  "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:      42,
		RuntimeType: provisioner.RuntimeTypeKubernetes,
		TargetID:    targetID,
		Containers: []provisioner.WorkloadContainer{{
			Name:   "challenge",
			Image:  "registry.example.invalid/challenges/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ports:  []int{8080},
			Expose: true,
		}},
		ResourceLimits: provisioner.ResourceLimits{
			CPUMillicores:       500,
			MemoryMiB:           512,
			EphemeralStorageMiB: 1024,
		},
	}
}

func validMultiCreateCommand(targetID string) provisioner.CreateWorkloadCommand {
	return provisioner.CreateWorkloadCommand{
		RequestID:   "req-multi",
		InstanceID:  "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:      42,
		RuntimeType: provisioner.RuntimeTypeKubernetes,
		TargetID:    targetID,
		Containers: []provisioner.WorkloadContainer{
			{Name: "web", Image: "ghcr.io/msg-ctf/challenges/oob-test/web:latest", Ports: []int{8080}, Expose: true},
			{Name: "internal", Image: "ghcr.io/msg-ctf/challenges/oob-test/web:latest", Ports: []int{8080, 9090}, Expose: false},
		},
		ResourceLimits: provisioner.ResourceLimits{
			CPUMillicores:       501,
			MemoryMiB:           513,
			EphemeralStorageMiB: 1025,
		},
	}
}

func resourceQuantityMilli(value int) *resource.Quantity {
	return resource.NewMilliQuantity(int64(value), resource.DecimalSI)
}

func resourceQuantityBytes(value int) *resource.Quantity {
	return resource.NewQuantity(int64(value)*1024*1024, resource.BinarySI)
}
