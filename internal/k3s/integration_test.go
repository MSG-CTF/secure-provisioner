package k3s

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestIntegrationCreateCommandUsesCanonicalResolvedPolicy(t *testing.T) {
	command, err := integrationCreateCommand(
		"aws-dev",
		"018f3f1e-21b8-7a91-a30b-63b3400fd001",
		"request-01",
		[]provisioner.WorkloadContainer{{Name: "challenge", Image: "registry.example.invalid/challenge:latest", Ports: []int{8080}, Expose: true}},
		isolation.WorkloadProfileWeb,
		isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
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
		isolation.WorkloadProfilePwn,
		isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
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

func TestPwnLiveNodePortConfigDoesNotRequireIngressControllerMetadata(t *testing.T) {
	config := ClusterConfig{
		TargetID:       "aws-pwn",
		Provider:       ProviderAWS,
		Region:         "ap-northeast-2",
		Architecture:   "amd64",
		KubeconfigPath: "pwn-kubeconfig",
		PublicGateway:  "http://203.0.113.10",
		ExposureMode:   ExposureModeNodePort,
		Enabled:        true,
		SecurityCapabilities: SecurityCapabilities{
			NetworkPolicyEnforced:          true,
			SupplementalGroupsPolicyStrict: true,
			PodPIDLimitEnforced:            true,
			NetworkPolicyProvider:          "kube-router",
			DNSNamespace:                   "kube-system",
			DNSPodSelector:                 map[string]string{"k8s-app": "kube-dns"},
			RuntimeClasses:                 []string{"gvisor"},
		},
	}
	if _, err := validateClusterConfig(config, map[string]struct{}{}); err != nil {
		t.Fatalf("validateClusterConfig() rejected NodePort-only Pwn target: %v", err)
	}
}

func TestIntegrationNamespaceCleanupRefusesForeignNamespace(t *testing.T) {
	expected := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "ctf-expected",
		UID:  "expected-uid",
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "secure-provisioner",
			"msgctf.io/instance-id":        "expected-instance",
			"msgctf.io/team-id":            "00000000-0000-4000-8000-000000000018",
		},
	}}
	foreign := expected.DeepCopy()
	foreign.UID = "foreign-uid"
	foreign.Labels["msgctf.io/instance-id"] = "foreign-instance"
	client := fake.NewSimpleClientset(foreign)

	err := cleanupIntegrationNamespace(context.Background(), client, expected)
	if !errors.Is(err, errNamespaceOwnership) {
		t.Fatalf("cleanupIntegrationNamespace() error = %v, want ownership error", err)
	}
	if _, err := client.CoreV1().Namespaces().Get(context.Background(), expected.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign namespace was removed: %v", err)
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
		IngressClass:   "traefik",
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
		isolation.WorkloadProfileWeb,
		isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
	)
	if err != nil {
		t.Fatal("integrationCreateCommand() failed")
	}
	result, err := adapter.CreateWorkload(testCtx, command)
	if err != nil {
		t.Fatalf("CreateWorkload() failed: %s", integrationErrorChain(err))
	}
	if result.NamespaceUID == "" {
		t.Fatal("CreateWorkload() did not return a Namespace UID")
	}
	expectedNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: namespace, UID: types.UID(result.NamespaceUID), Labels: ownershipLabels(command),
	}}
	t.Cleanup(func() { deleteIntegrationNamespace(t, cluster.Client, expectedNamespace) })
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
	if result.NamespaceUID != string(createdNamespace.UID) {
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
		t.Fatalf("ready pod cannot be reconfirmed: error=%v diagnostics=%s", err, integrationPodDiagnostics(testCtx, cluster.Client, namespace))
	}
	readyEndpoint, err := hasReadyEndpoint(testCtx, cluster.Client, namespace)
	if err != nil || !readyEndpoint {
		t.Fatal("ready EndpointSlice cannot be reconfirmed")
	}
}

func TestK3sIntegrationPwnCreateReadyAndCleanup(t *testing.T) {
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
		ExposureMode:   ExposureModeNodePort,
		Enabled:        true,
		SecurityCapabilities: SecurityCapabilities{
			NetworkPolicyEnforced:          true,
			SupplementalGroupsPolicyStrict: true,
			PodPIDLimitEnforced:            true,
			NetworkPolicyProvider:          "kube-router",
			DNSNamespace:                   "kube-system",
			DNSPodSelector:                 map[string]string{"k8s-app": "kube-dns"},
			RuntimeClasses:                 []string{"gvisor"},
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
	adapter, err := NewAdapter(registry, AdapterConfig{
		ReadyTimeout: 5 * time.Minute, PollInterval: time.Second, RollbackTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal("NewAdapter() failed")
	}
	command, err := integrationCreateCommand(
		targetID,
		instanceID,
		integrationUUID(t),
		[]provisioner.WorkloadContainer{{Name: "challenge", Image: image, Ports: []int{port}, Expose: true}},
		isolation.WorkloadProfilePwn,
		isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
	)
	if err != nil {
		t.Fatal("integrationCreateCommand() failed")
	}
	result, err := adapter.CreateWorkload(testCtx, command)
	if err != nil {
		t.Fatalf("CreateWorkload() failed: %s", integrationErrorChain(err))
	}
	if result.NamespaceUID == "" {
		t.Fatal("Pwn CreateWorkload() did not return a Namespace UID")
	}
	expectedNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: namespace, UID: types.UID(result.NamespaceUID), Labels: ownershipLabels(command),
	}}
	t.Cleanup(func() { deleteIntegrationNamespace(t, cluster.Client, expectedNamespace) })
	if len(result.Endpoints) != 1 || result.Endpoints[0].Protocol != isolation.EndpointProtocolTCP ||
		!strings.HasPrefix(result.Endpoints[0].ServiceURL, "tcp://") {
		t.Fatalf("Pwn endpoints = %#v", result.Endpoints)
	}
	createdNamespace, err := cluster.Client.CoreV1().Namespaces().Get(testCtx, namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("Pwn namespace cannot be retrieved")
	}
	if result.NamespaceUID != string(createdNamespace.UID) {
		t.Fatal("Pwn CreateWorkload() did not preserve the exact Namespace UID")
	}
	deployment, err := cluster.Client.AppsV1().Deployments(namespace).Get(testCtx, resourceName, metav1.GetOptions{})
	if err != nil {
		t.Fatal("Pwn deployment cannot be retrieved")
	}
	if deployment.Spec.Template.Spec.RuntimeClassName == nil || *deployment.Spec.Template.Spec.RuntimeClassName != "gvisor" {
		t.Fatalf("runtimeClassName = %#v", deployment.Spec.Template.Spec.RuntimeClassName)
	}
	service, err := cluster.Client.CoreV1().Services(namespace).Get(testCtx, resourceName, metav1.GetOptions{})
	if err != nil {
		t.Fatal("Pwn service cannot be retrieved")
	}
	if service.Spec.Type != corev1.ServiceTypeNodePort || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].NodePort == 0 {
		t.Fatalf("Pwn service = %#v", service.Spec)
	}
	policies, err := cluster.Client.NetworkingV1().NetworkPolicies(namespace).List(testCtx, metav1.ListOptions{})
	if err != nil {
		t.Fatal("Pwn NetworkPolicies cannot be retrieved")
	}
	foundDefaultDeny := false
	for _, policy := range policies.Items {
		foundDefaultDeny = foundDefaultDeny || policy.Name == "default-deny-all"
	}
	if !foundDefaultDeny {
		t.Fatalf("Pwn NetworkPolicies = %#v, want default-deny-all", policies.Items)
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
		IngressClass:   "traefik",
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
		isolation.WorkloadProfileWeb,
		isolation.ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256},
	)
	if err != nil {
		t.Fatal("integrationCreateCommand() failed")
	}
	result, err := createAdapter.CreateWorkload(testCtx, command)
	if err != nil {
		t.Fatalf("CreateWorkload() failed: %s", integrationErrorChain(err))
	}
	if result.NamespaceUID == "" {
		t.Fatal("multi-container CreateWorkload() did not return a Namespace UID")
	}
	expectedNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: namespace, UID: types.UID(result.NamespaceUID), Labels: ownershipLabels(command),
	}}
	t.Cleanup(func() { deleteIntegrationNamespace(t, cluster.Client, expectedNamespace) })
	createdNamespace, err := cluster.Client.CoreV1().Namespaces().Get(testCtx, namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("created multi-container namespace cannot be retrieved")
	}
	if result.NamespaceUID != string(createdNamespace.UID) {
		t.Fatal("multi-container CreateWorkload() did not preserve the exact Namespace UID")
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
	workloadProfile isolation.WorkloadProfile,
	limits isolation.ResourceLimits,
) (provisioner.CreateWorkloadCommand, error) {
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
		WorkloadProfile: workloadProfile,
		Containers:      requirements,
		ResourceLimits:  limits,
	}
	policy, err := isolation.NewStaticResolver().Resolve(policyRequest)
	if err != nil {
		return provisioner.CreateWorkloadCommand{}, err
	}
	return provisioner.CreateWorkloadCommand{
		RequestID:      requestID,
		InstanceID:     instanceID,
		TeamID:         "00000000-0000-4000-8000-000000000018",
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

func integrationErrorChain(err error) string {
	parts := make([]string, 0, 4)
	for err != nil {
		parts = append(parts, err.Error())
		err = errors.Unwrap(err)
	}
	return strings.Join(parts, ": ")
}

func integrationPodDiagnostics(ctx context.Context, client kubernetes.Interface, namespace string) string {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "list pods: " + err.Error()
	}
	parts := make([]string, 0, len(pods.Items))
	for _, pod := range pods.Items {
		statuses := make([]string, 0, len(pod.Status.ContainerStatuses))
		logs := make([]string, 0, len(pod.Status.ContainerStatuses))
		for _, status := range pod.Status.ContainerStatuses {
			state := "waiting"
			if status.State.Running != nil {
				state = "running"
			} else if status.State.Terminated != nil {
				state = fmt.Sprintf("terminated(exit=%d,reason=%s)", status.State.Terminated.ExitCode, status.State.Terminated.Reason)
			} else if status.State.Waiting != nil {
				state = "waiting(" + status.State.Waiting.Reason + ")"
			}
			statuses = append(statuses, fmt.Sprintf("%s=%s,restarts=%d", status.Name, state, status.RestartCount))
			tailLines := int64(20)
			previous := status.RestartCount > 0
			if output, logErr := client.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
				Container: status.Name, Previous: previous, TailLines: &tailLines,
			}).DoRaw(ctx); logErr == nil && len(output) > 0 {
				logs = append(logs, fmt.Sprintf("%s=%q", status.Name, strings.TrimSpace(string(output))))
			}
		}
		parts = append(parts, fmt.Sprintf("pod=%s phase=%s containers=[%s] logs=[%s]", pod.Name, pod.Status.Phase, strings.Join(statuses, ";"), strings.Join(logs, ";")))
	}
	return strings.Join(parts, " | ")
}

func deleteIntegrationNamespace(t *testing.T, client kubernetes.Interface, namespace *corev1.Namespace) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cleanupIntegrationNamespace(ctx, client, namespace); err != nil {
		t.Errorf("integration namespace cleanup failed: %v", err)
	}
}

func cleanupIntegrationNamespace(ctx context.Context, client kubernetes.Interface, namespace *corev1.Namespace) error {
	return rollbackNamespace(ctx, client, namespace, time.Second)
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
