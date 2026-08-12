package k3s

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestIntegrationCreateCommandUsesCanonicalResolvedPolicy(t *testing.T) {
	command, err := integrationCreateCommand(
		"aws-dev",
		"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"request-01",
		[]provisioner.WorkloadContainer{{Name: "challenge", Image: "registry.example.invalid/challenge:latest", Ports: []int{8080}, Expose: true}},
		isolation.ProfileRef{Name: "WEB", Version: "v1"},
		isolation.ProfileRef{Name: "SMALL_SINGLE", Version: "v1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !command.Policy.Baseline.RunAsNonRoot || command.Policy.Containers[0].RunAsUser != 10001 ||
		command.Policy.ResourceLimits != (isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128}) {
		t.Fatalf("command policy = %#v", command.Policy)
	}
	if _, err := BuildResourceSet(validCluster("aws-dev"), command); err != nil {
		t.Fatalf("BuildResourceSet() rejected integration fixture: %v", err)
	}
}

func TestIntegrationPwnResolvesGVisorAndReturnsTCPEndpoint(t *testing.T) {
	command, err := integrationCreateCommand(
		"aws-pwn",
		"018f3f1e-21b8-7a91-a30b-63b3400fd009",
		"request-pwn-01",
		[]provisioner.WorkloadContainer{{
			Name: "challenge", Image: "registry.example.invalid/pwn:latest", Ports: []int{31337}, Expose: true,
		}},
		isolation.ProfileRef{Name: "PWN", Version: "v1"},
		isolation.ProfileRef{Name: "SMALL_SINGLE", Version: "v1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	cluster := nodePortGVisorCluster(command.TargetID)
	client := readyIntegrationClient(t, cluster, command)
	installNodePortAllocator(t, client, 31042)
	config := validClusterConfig(command.TargetID, ProviderAWS, "pwn-kubeconfig")
	config.PublicGateway = cluster.Config.PublicGateway
	config.ExposureMode = ExposureModeNodePort
	config.SecurityCapabilities.RuntimeClasses = []string{"gvisor"}
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{config}, client))

	result, err := adapter.CreateWorkload(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Endpoints) != 1 || result.Endpoints[0].Protocol != isolation.EndpointProtocolTCP ||
		result.Endpoints[0].ServiceURL != "tcp://203.0.113.10:31042" {
		t.Fatalf("Pwn endpoints = %#v", result.Endpoints)
	}
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	runtimeClassName := resources.Deployments[0].Spec.Template.Spec.RuntimeClassName
	if runtimeClassName == nil || *runtimeClassName != "gvisor" {
		t.Fatalf("Pwn RuntimeClassName = %#v", runtimeClassName)
	}
}

func readyIntegrationClient(t *testing.T, cluster Cluster, command provisioner.CreateWorkloadCommand) *fake.Clientset {
	t.Helper()
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	pod := readyPod(
		resources.Namespace.Name,
		resources.ExpectedSpecHash,
		"ready-pwn-pod",
		"10.0.0.9",
		resources.Deployment.Spec.Template.Labels,
	)
	client := fake.NewSimpleClientset(pod, readyEndpointSlice(resources.Namespace.Name, pod))
	installNamespaceCreateMetadata(t, client, "test-pwn-namespace-uid", "1")
	installDeploymentController(client, true)
	return client
}

func TestIntegrationPwnRejectsUnsupportedTargetWithoutCreatingNamespace(t *testing.T) {
	command := validPwnCreateCommand("web-only")
	cluster := validCluster("web-only")
	client := fake.NewSimpleClientset()
	cluster.Client = client

	_, err := BuildResourceSet(cluster, command)
	if code := runtimeErrorCode(t, err); code != "TARGET_CAPABILITY_MISMATCH" {
		t.Fatalf("code = %q, want TARGET_CAPABILITY_MISMATCH", code)
	}
	if len(client.Actions()) != 0 {
		t.Fatalf("Kubernetes actions = %#v, want none", client.Actions())
	}
}

func TestK3sIntegrationCreateReadyAndCleanup(t *testing.T) {
	targetID := requireIntegrationEnv(t, "K3S_INTEGRATION_TARGET_ID")
	kubeconfig := requireIntegrationEnv(t, "K3S_INTEGRATION_KUBECONFIG")
	gateway := requireIntegrationEnv(t, "K3S_INTEGRATION_PUBLIC_GATEWAY")
	image := requireIntegrationEnv(t, "K3S_INTEGRATION_IMAGE")
	port := requireIntegrationPort(t, "K3S_INTEGRATION_CONTAINER_PORT")
	instanceID := integrationUUID(t)

	registry, err := NewRegistry([]ClusterConfig{{
		TargetID:       targetID,
		Provider:       ProviderAWS,
		Region:         "ap-northeast-2",
		Architecture:   "amd64",
		KubeconfigPath: kubeconfig,
		PublicGateway:  gateway,
		Enabled:        true,
		SecurityCapabilities: SecurityCapabilities{
			NetworkPolicyEnforced:          true,
			SupplementalGroupsPolicyStrict: true,
			PodPIDLimitEnforced:            true,
			NetworkPolicyProvider:          "kube-router",
			DNSNamespace:                   "kube-system",
			DNSPodSelector:                 map[string]string{"k8s-app": "kube-dns"},
			IngressNamespace:               "kube-system",
			IngressPodSelector:             map[string]string{"app.kubernetes.io/name": "traefik"},
		},
	}}, KubeconfigClientFactory{})
	if err != nil {
		t.Fatal("NewRegistry() failed")
	}
	cluster, err := registry.Lookup(targetID)
	if err != nil {
		t.Fatal("Registry.Lookup() failed")
	}
	testCtx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	namespace, err := NamespaceForInstance(instanceID)
	if err != nil {
		t.Fatal("NamespaceForInstance() failed")
	}
	t.Cleanup(func() { deleteIntegrationNamespace(t, cluster.Client, namespace) })

	adapter, err := NewAdapter(registry, AdapterConfig{
		ReadyTimeout:    5 * time.Minute,
		PollInterval:    time.Second,
		RollbackTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal("NewAdapter() failed")
	}
	command, err := integrationCreateCommand(
		targetID,
		instanceID,
		integrationUUID(t),
		[]provisioner.WorkloadContainer{{
			Name: "challenge", Image: image, Ports: []int{port}, Expose: true,
		}},
		isolation.ProfileRef{Name: "WEB", Version: "v1"},
		isolation.ProfileRef{Name: "SMALL_SINGLE", Version: "v1"},
	)
	if err != nil {
		t.Fatal("integrationCreateCommand() failed")
	}
	result, err := adapter.CreateWorkload(testCtx, command)
	if err != nil {
		t.Fatal("CreateWorkload() failed")
	}
	if _, retryErr := adapter.CreateWorkload(testCtx, command); runtimeErrorCode(t, retryErr) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("second direct CreateWorkload() error = %v, want RESOURCE_OWNERSHIP_CONFLICT", retryErr)
	}

	if result.RuntimeWorkloadID != RuntimeWorkloadID(targetID, namespace) {
		t.Fatal("CreateWorkload() returned an unexpected runtime workload ID")
	}
	if result.ServiceURL != strings.TrimRight(gateway, "/")+"/instances/"+instanceID {
		t.Fatal("CreateWorkload() returned an unexpected service URL")
	}
	createdNamespace, err := cluster.Client.CoreV1().Namespaces().Get(testCtx, namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("created namespace cannot be retrieved")
	}
	if result.NamespaceUID == "" || result.NamespaceUID != string(createdNamespace.UID) {
		t.Fatal("CreateWorkload() did not preserve the exact Namespace UID")
	}
	if _, err := cluster.Client.AppsV1().Deployments(namespace).Get(testCtx, resourceName, metav1.GetOptions{}); err != nil {
		t.Fatal("created deployment cannot be retrieved")
	}
	if _, err := cluster.Client.CoreV1().Services(namespace).Get(testCtx, resourceName, metav1.GetOptions{}); err != nil {
		t.Fatal("created service cannot be retrieved")
	}
	if _, err := cluster.Client.NetworkingV1().Ingresses(namespace).Get(testCtx, resourceName, metav1.GetOptions{}); err != nil {
		t.Fatal("created ingress cannot be retrieved")
	}
	readyPod, err := hasReadyPod(testCtx, cluster.Client, namespace)
	if err != nil || !readyPod {
		t.Fatal("ready pod cannot be reconfirmed")
	}
	readyEndpoint, err := hasReadyEndpoint(testCtx, cluster.Client, namespace)
	if err != nil || !readyEndpoint {
		t.Fatal("ready EndpointSlice cannot be reconfirmed")
	}
}

func TestK3sIntegrationCreateMultiContainerReadyAndDelete(t *testing.T) {
	targetID := requireIntegrationEnv(t, "K3S_INTEGRATION_TARGET_ID")
	kubeconfig := requireIntegrationEnv(t, "K3S_INTEGRATION_KUBECONFIG")
	gateway := requireIntegrationEnv(t, "K3S_INTEGRATION_PUBLIC_GATEWAY")
	image := requireIntegrationEnv(t, "K3S_INTEGRATION_IMAGE")
	port := requireIntegrationPort(t, "K3S_INTEGRATION_CONTAINER_PORT")
	instanceID := integrationUUID(t)

	registry, err := NewRegistry([]ClusterConfig{{
		TargetID:       targetID,
		Provider:       ProviderAWS,
		Region:         "ap-northeast-2",
		Architecture:   "amd64",
		KubeconfigPath: kubeconfig,
		PublicGateway:  gateway,
		Enabled:        true,
		SecurityCapabilities: SecurityCapabilities{
			NetworkPolicyEnforced:          true,
			SupplementalGroupsPolicyStrict: true,
			PodPIDLimitEnforced:            true,
			NetworkPolicyProvider:          "kube-router",
			DNSNamespace:                   "kube-system",
			DNSPodSelector:                 map[string]string{"k8s-app": "kube-dns"},
			IngressNamespace:               "kube-system",
			IngressPodSelector:             map[string]string{"app.kubernetes.io/name": "traefik"},
		},
	}}, KubeconfigClientFactory{})
	if err != nil {
		t.Fatal("NewRegistry() failed")
	}
	cluster, err := registry.Lookup(targetID)
	if err != nil {
		t.Fatal("Registry.Lookup() failed")
	}
	testCtx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	namespace, err := NamespaceForInstance(instanceID)
	if err != nil {
		t.Fatal("NamespaceForInstance() failed")
	}
	t.Cleanup(func() { deleteIntegrationNamespace(t, cluster.Client, namespace) })

	createAdapter, err := NewAdapter(registry, AdapterConfig{
		ReadyTimeout:    5 * time.Minute,
		PollInterval:    time.Second,
		RollbackTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal("NewAdapter() failed")
	}
	command, err := integrationCreateCommand(
		targetID,
		instanceID,
		integrationUUID(t),
		[]provisioner.WorkloadContainer{
			{Name: "web", Image: image, Ports: []int{port}, Expose: true},
			{Name: "internal", Image: image, Ports: []int{port}, Expose: false},
		},
		isolation.ProfileRef{Name: "WEB", Version: "v1"},
		isolation.ProfileRef{Name: "SMALL_MULTI", Version: "v1"},
	)
	if err != nil {
		t.Fatal("integrationCreateCommand() failed")
	}
	result, err := createAdapter.CreateWorkload(testCtx, command)
	if err != nil {
		t.Fatal("CreateWorkload() failed")
	}
	if len(result.Endpoints) != 1 ||
		result.Endpoints[0].ContainerName != "web" ||
		result.Endpoints[0].Port != port {
		t.Fatalf("CreateWorkload() endpoints = %#v", result.Endpoints)
	}
	for _, name := range []string{"web", "internal"} {
		if _, err := cluster.Client.AppsV1().Deployments(namespace).Get(testCtx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("deployment %q cannot be retrieved", name)
		}
		if _, err := cluster.Client.CoreV1().Services(namespace).Get(testCtx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("service %q cannot be retrieved", name)
		}
	}

	deleteAdapter, err := NewDeleteAdapterForCreateAdapter(createAdapter, DeleteAdapterConfig{
		DeleteTimeout: 2 * time.Minute,
		PollInterval:  time.Second,
	})
	if err != nil {
		t.Fatal("NewDeleteAdapterForCreateAdapter() failed")
	}
	binding := runtimebinding.Binding{
		InstanceID:        instanceID,
		TeamID:            command.TeamID,
		TargetID:          targetID,
		Namespace:         namespace,
		NamespaceUID:      result.NamespaceUID,
		RuntimeWorkloadID: result.RuntimeWorkloadID,
	}
	deleteCommand := provisioner.DeleteWorkloadCommand{
		RequestID:         integrationUUID(t),
		InstanceID:        instanceID,
		TeamID:            command.TeamID,
		RuntimeType:       provisioner.RuntimeTypeKubernetes,
		TargetID:          targetID,
		RuntimeWorkloadID: result.RuntimeWorkloadID,
		Reason:            provisioner.DeleteReasonUserRequested,
	}
	if err := deleteAdapter.DeleteWorkload(testCtx, deleteCommand, binding); err != nil {
		t.Fatal("DeleteWorkload() failed")
	}
	if _, err := cluster.Client.CoreV1().Namespaces().Get(testCtx, namespace, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("namespace Get() after delete error = %v, want NotFound", err)
	}
}

func integrationCreateCommand(
	targetID string,
	instanceID string,
	requestID string,
	containers []provisioner.WorkloadContainer,
	workloadProfileRef isolation.ProfileRef,
	resourceRef isolation.ProfileRef,
) (provisioner.CreateWorkloadCommand, error) {
	var limits isolation.ResourceLimits
	switch resourceRef {
	case (isolation.ProfileRef{Name: "SMALL_SINGLE", Version: "v1"}):
		limits = isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128}
	case (isolation.ProfileRef{Name: "SMALL_MULTI", Version: "v1"}):
		limits = isolation.ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256}
	default:
		return provisioner.CreateWorkloadCommand{}, fmt.Errorf("unsupported integration resource profile %s@%s", resourceRef.Name, resourceRef.Version)
	}
	requirements := make([]isolation.ContainerRequirement, len(containers))
	for index, container := range containers {
		requirements[index] = isolation.ContainerRequirement{
			Name:      container.Name,
			Ports:     append([]int(nil), container.Ports...),
			Expose:    container.Expose,
			RunAsUser: int64(10001 + index),
		}
	}
	policyRequest := isolation.Request{
		ChallengeID:        "k3s-integration",
		IsolationRef:       isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
		WorkloadProfileRef: workloadProfileRef,
		ResourceRef:        resourceRef,
		Containers:         requirements,
		OutboundMode:       isolation.OutboundNone,
		ResourceLimits:     limits,
	}
	policy, err := isolation.NewStaticResolver().Resolve(policyRequest)
	if err != nil {
		return provisioner.CreateWorkloadCommand{}, err
	}
	return provisioner.CreateWorkloadCommand{
		RequestID:      requestID,
		InstanceID:     instanceID,
		TeamID:         18,
		ChallengeRef:   provisioner.ChallengeRef{ChallengeID: policy.ChallengeID, Version: "integration"},
		RuntimeType:    provisioner.RuntimeTypeKubernetes,
		TargetID:       targetID,
		Containers:     append([]provisioner.WorkloadContainer(nil), containers...),
		ResourceLimits: provisioner.ResourceLimits{CPUMillicores: limits.CPUMillicores, MemoryMiB: limits.MemoryMiB, EphemeralStorageMiB: limits.EphemeralStorageMiB},
		PolicyRequest:  policyRequest,
		Policy:         policy,
	}, nil
}

func requireIntegrationEnv(t *testing.T, name string) string {
	t.Helper()
	value, found := os.LookupEnv(name)
	if !found || strings.TrimSpace(value) == "" {
		t.Skipf("K3s integration test skipped: %s is not set", name)
	}
	return value
}

func requireIntegrationPort(t *testing.T, name string) int {
	t.Helper()
	port, ok := parseIntegrationPort(requireIntegrationEnv(t, name))
	if !ok {
		t.Fatalf("%s must be an integer from 1 through 65535", name)
	}
	return port
}

func parseIntegrationPort(value string) (int, bool) {
	port, err := strconv.Atoi(value)
	return port, err == nil && port >= 1 && port <= 65535
}

func integrationUUID(t *testing.T) string {
	t.Helper()
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal("failed to generate an integration UUID")
	}
	bytes[6] = bytes[6]&0x0f | 0x40
	bytes[8] = bytes[8]&0x3f | 0x80
	encoded := hex.EncodeToString(bytes)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func deleteIntegrationNamespace(t *testing.T, client kubernetes.Interface, namespace string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		t.Error("integration namespace deletion failed")
		return
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		_, err := client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		if err != nil {
			t.Error("integration namespace cleanup could not be verified")
			return
		}
		select {
		case <-ctx.Done():
			t.Errorf("integration namespace cleanup did not reach NotFound before timeout")
			return
		case <-ticker.C:
		}
	}
}

func TestParseIntegrationPort(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  int
		ok    bool
	}{
		{name: "lowest valid port", value: "1", want: 1, ok: true},
		{name: "highest valid port", value: "65535", want: 65535, ok: true},
		{name: "zero", value: "0"},
		{name: "too high", value: "65536"},
		{name: "not a number", value: "http"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseIntegrationPort(test.value)
			if ok != test.ok {
				t.Fatalf("parseIntegrationPort() validity = %t, want %t", ok, test.ok)
			}
			if ok && got != test.want {
				t.Fatalf("parseIntegrationPort() port = %d, want %d", got, test.want)
			}
		})
	}
}
