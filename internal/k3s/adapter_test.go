package k3s

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
)

func TestAdapterRoutesEachTargetToItsOwnClient(t *testing.T) {
	awsClient := readyClient(t, validCreateCommand("aws-dev"))
	gcpClient := readyClient(t, validCreateCommand("gcp-dev"))
	registry := adapterRegistry(t, []ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
		validClusterConfig("gcp-dev", ProviderGCP, "gcp-kubeconfig"),
	}, awsClient, gcpClient)
	adapter := newTestAdapter(t, registry)

	if _, err := adapter.CreateWorkload(context.Background(), validCreateCommand("aws-dev")); err != nil {
		t.Fatal(err)
	}
	assertNamespaceCreateCount(t, awsClient, 1)
	assertNamespaceCreateCount(t, gcpClient, 0)

	if _, err := adapter.CreateWorkload(context.Background(), validCreateCommand("gcp-dev")); err != nil {
		t.Fatal(err)
	}
	assertNamespaceCreateCount(t, awsClient, 1)
	assertNamespaceCreateCount(t, gcpClient, 1)
}

func TestAdapterReturnsOnlyAfterReadyPodAndEndpointSlice(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	resourcesApplied := actionSignal(client, "create", "ingresses")
	podListed := actionSignal(client, "list", "pods")
	result := make(chan createResult, 1)
	go func() {
		value, err := adapter.CreateWorkload(context.Background(), command)
		result <- createResult{value, err}
	}()
	<-resourcesApplied
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().Pods(namespace).Create(context.Background(), readyPod(namespace), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	<-podListed
	assertNoCreateResult(t, result)
	if _, err := client.DiscoveryV1().EndpointSlices(namespace).Create(context.Background(), readyEndpointSlice(namespace), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	got := <-result
	if got.err != nil {
		t.Fatal(got.err)
	}
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	if got.result.RuntimeWorkloadID != resources.RuntimeWorkloadID || got.result.ServiceURL != resources.ServiceURL {
		t.Fatalf("CreateWorkload() = %#v, want workload ID and URL from resource set", got.result)
	}
}

func TestAdapterDoesNotReturnWithOnlyReadyPod(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Tracker().Delete(discoveryv1.SchemeGroupVersion.WithResource("endpointslices"), namespace, "ready"); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	assertNotReadyAfterGate(t, adapter, client, command, "list", "endpointslices")
}

func TestAdapterDoesNotReturnWithOnlyReadyEndpointSlice(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), namespace, "ready"); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
	assertNotReadyAfterGate(t, adapter, client, command, "list", "pods")
}

func TestAdapterRetriesSameCommandWithoutDuplicateResources(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"namespaces", "deployments", "services", "ingresses"} {
		assertCreateActionCount(t, client, resource, 1)
	}
}

func TestAdapterPreservesServiceClusterAllocationOnRetry(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := readyClient(t, command)
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	resources.Service.Spec.ClusterIP = "10.0.0.42"
	resources.Service.Spec.ClusterIPs = []string{"10.0.0.42"}
	for _, object := range []runtime.Object{resources.Namespace, resources.Deployment, resources.Service, resources.Ingress} {
		if err := client.Tracker().Add(object); err != nil {
			t.Fatal(err)
		}
	}
	client.ClearActions()
	updatedService := make(chan *corev1.Service, 1)
	client.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updatedService <- action.(k8stesting.UpdateAction).GetObject().(*corev1.Service).DeepCopy()
		return false, nil, nil
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	if _, err := adapter.CreateWorkload(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	got := <-updatedService
	if got.Spec.ClusterIP != "10.0.0.42" || len(got.Spec.ClusterIPs) != 1 || got.Spec.ClusterIPs[0] != "10.0.0.42" {
		t.Fatalf("updated service allocation = %#v, want preserved ClusterIP and ClusterIPs", got.Spec)
	}
}

func TestAdapterRollsBackOwnedNamespaceWhenResourceApplyFails(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("https://cluster.example.invalid deployment failure")
	})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("code = %q, want RESOURCE_APPLY_FAILED", runtimeErrorCode(t, err))
	}
	namespace, namespaceErr := NamespaceForInstance(command.InstanceID)
	if namespaceErr != nil {
		t.Fatal(namespaceErr)
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
	if _, getErr := client.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{}); !apierrors.IsNotFound(getErr) {
		t.Fatalf("namespace get error = %v, want NotFound", getErr)
	}
}

func TestAdapterRollsBackOwnedNamespaceWhenReadinessTimesOut(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client)
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Millisecond, PollInterval: time.Microsecond})
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "WORKLOAD_NOT_READY" {
		t.Fatalf("code = %q, want WORKLOAD_NOT_READY", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 1)
}

func TestAdapterDoesNotDeleteNamespaceOwnedByAnotherInstance(t *testing.T) {
	command := validCreateCommand("aws-dev")
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: namespace,
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "secure-provisioner",
			"app.kubernetes.io/name":       resourceName,
			"msgctf.io/instance-id":        "018f3f1e-21b8-7a91-a30b-63b3400fd002",
			"msgctf.io/team-id":            "42",
		},
	}})
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))

	_, err = adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "RESOURCE_OWNERSHIP_CONFLICT" {
		t.Fatalf("code = %q, want RESOURCE_OWNERSHIP_CONFLICT", runtimeErrorCode(t, err))
	}
	assertDeleteActionCount(t, client, "namespaces", 0)
}

func TestAdapterDoesNotExposeKubeconfigOrAPIServerInErrors(t *testing.T) {
	command := validCreateCommand("aws-dev")
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("https://api.private.example.invalid kubeconfig=/private/kubeconfig")
	})
	config := validClusterConfig("aws-dev", ProviderAWS, "/private/kubeconfig")
	adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{config}, client))

	_, err := adapter.CreateWorkload(context.Background(), command)
	if err == nil || err.Error() != "RESOURCE_APPLY_FAILED" {
		t.Fatalf("error = %v, want RESOURCE_APPLY_FAILED", err)
	}
	for _, secret := range []string{"api.private.example.invalid", "/private/kubeconfig", "kubeconfig="} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error exposes %q: %v", secret, err)
		}
	}
}

type createResult struct {
	result provisioner.CreateWorkloadResult
	err    error
}

func assertNotReadyAfterGate(t *testing.T, adapter *Adapter, client *fake.Clientset, command provisioner.CreateWorkloadCommand, verb, resource string) {
	t.Helper()
	gateReached := actionSignal(client, verb, resource)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan createResult, 1)
	go func() {
		value, err := adapter.CreateWorkload(ctx, command)
		result <- createResult{value, err}
	}()
	<-gateReached
	assertNoCreateResult(t, result)
	cancel()
	got := <-result
	if runtimeErrorCode(t, got.err) != "WORKLOAD_NOT_READY" {
		t.Fatalf("code = %q, want WORKLOAD_NOT_READY", runtimeErrorCode(t, got.err))
	}
}

func actionSignal(client *fake.Clientset, verb, resource string) <-chan struct{} {
	signal := make(chan struct{}, 1)
	client.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		select {
		case signal <- struct{}{}:
		default:
		}
		return false, nil, nil
	})
	return signal
}

func assertNoCreateResult(t *testing.T, result <-chan createResult) {
	t.Helper()
	select {
	case got := <-result:
		t.Fatalf("CreateWorkload returned early: %#v", got)
	default:
	}
}

func readyPod(namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "ready", Labels: map[string]string{"app.kubernetes.io/name": resourceName}},
		Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

func readyEndpointSlice(namespace string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Namespace: namespace, Name: resourceName, Labels: map[string]string{discoveryv1.LabelServiceName: resourceName}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}}},
	}
}

func TestAdapterRejectsUnknownAndDisabledTargetWithoutCallingAnyClient(t *testing.T) {
	activeClient := readyClient(t, validCreateCommand("aws-dev"))
	disabled := validClusterConfig("retired", ProviderNCP, "unused-kubeconfig")
	disabled.Enabled = false
	registry := adapterRegistry(t, []ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
		disabled,
	}, activeClient)
	adapter := newTestAdapter(t, registry)

	for _, targetID := range []string{"missing", "retired"} {
		command := validCreateCommand(targetID)
		_, err := adapter.CreateWorkload(context.Background(), command)
		if err == nil {
			t.Fatalf("CreateWorkload(%q) error = nil", targetID)
		}
	}
	if got := len(activeClient.Actions()); got != 0 {
		t.Fatalf("active client actions = %d, want 0", got)
	}
}

func newTestAdapter(t *testing.T, registry *Registry) *Adapter {
	t.Helper()
	adapter, err := NewAdapter(registry, AdapterConfig{ReadyTimeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func adapterRegistry(t *testing.T, configs []ClusterConfig, clients ...kubernetes.Interface) *Registry {
	t.Helper()
	registry, err := NewRegistry(configs, &sequenceFactory{clients: clients})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func readyClient(t *testing.T, command provisioner.CreateWorkloadCommand) *fake.Clientset {
	t.Helper()
	namespace, err := NamespaceForInstance(command.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	return fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "ready", Labels: map[string]string{"app.kubernetes.io/name": resourceName}},
			Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Namespace: namespace, Name: "ready", Labels: map[string]string{discoveryv1.LabelServiceName: resourceName}},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}}},
		},
	)
}

func assertNamespaceCreateCount(t *testing.T, client *fake.Clientset, want int) {
	t.Helper()
	assertCreateActionCount(t, client, "namespaces", want)
}

func assertCreateActionCount(t *testing.T, client *fake.Clientset, resource string, want int) {
	t.Helper()
	got := actionCount(client, "create", resource)
	if got != want {
		t.Fatalf("%s create actions = %d, want %d", resource, got, want)
	}
}

func assertDeleteActionCount(t *testing.T, client *fake.Clientset, resource string, want int) {
	t.Helper()
	got := actionCount(client, "delete", resource)
	if got != want {
		t.Fatalf("%s delete actions = %d, want %d", resource, got, want)
	}
}

func actionCount(client *fake.Clientset, verb, resource string) int {
	count := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == verb && action.GetResource().Resource == resource {
			count++
		}
	}
	return count
}
