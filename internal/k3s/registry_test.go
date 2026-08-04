package k3s

import (
	"errors"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
	metricsfake "k8s.io/metrics/pkg/client/clientset/versioned/fake"
)

type sequenceFactory struct {
	clients []kubernetes.Interface
	metrics []metricsclient.Interface
	err     error
	calls   int
}

type unidentifiableClient struct {
	kubernetes.Interface
	values []string
}

func (f *sequenceFactory) FromKubeconfig(string) (ClientSet, error) {
	f.calls++
	if f.err != nil {
		return ClientSet{}, f.err
	}
	if f.calls > len(f.clients) {
		return ClientSet{}, errors.New("unexpected client factory call")
	}
	metrics := metricsclient.Interface(metricsfake.NewSimpleClientset())
	if len(f.metrics) >= f.calls && f.metrics[f.calls-1] != nil {
		metrics = f.metrics[f.calls-1]
	}
	return ClientSet{Kubernetes: f.clients[f.calls-1], Metrics: metrics}, nil
}

func validClusterConfig(targetID string, provider Provider, kubeconfigPath string) ClusterConfig {
	return ClusterConfig{
		TargetID:             targetID,
		Provider:             provider,
		Region:               "test-region",
		Architecture:         "amd64",
		KubeconfigPath:       kubeconfigPath,
		PublicGateway:        "https://gateway.example.invalid/",
		IngressClass:         "nginx",
		Enabled:              true,
		SecurityCapabilities: supportedSecurityCapabilities(),
	}
}

func supportedSecurityCapabilities() SecurityCapabilities {
	return SecurityCapabilities{
		NetworkPolicyEnforced:          true,
		SupplementalGroupsPolicyStrict: true,
		NetworkPolicyProvider:          "kube-router",
		DNSNamespace:                   "kube-system",
		DNSPodSelector:                 map[string]string{"k8s-app": "kube-dns"},
		IngressNamespace:               "kube-system",
		IngressPodSelector:             map[string]string{"app.kubernetes.io/name": "traefik"},
	}
}

func runtimeErrorCode(t *testing.T, err error) string {
	t.Helper()
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) {
		t.Fatalf("error type = %T, want *RuntimeError", err)
	}
	return runtimeErr.Code()
}

func TestNewRegistryCreatesDistinctClientsPerEnabledTarget(t *testing.T) {
	awsClient, gcpClient := fake.NewSimpleClientset(), fake.NewSimpleClientset()
	factory := &sequenceFactory{clients: []kubernetes.Interface{awsClient, gcpClient}}

	registry, err := NewRegistry([]ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
		validClusterConfig("gcp-dev", ProviderGCP, "gcp-kubeconfig"),
	}, factory)
	if err != nil {
		t.Fatal(err)
	}

	aws, err := registry.Lookup("aws-dev")
	if err != nil {
		t.Fatal(err)
	}
	gcp, err := registry.Lookup("gcp-dev")
	if err != nil {
		t.Fatal(err)
	}
	if aws.Client == gcp.Client {
		t.Fatal("targets share a Kubernetes client")
	}
	if aws.Config.PublicGateway != "https://gateway.example.invalid" {
		t.Fatalf("PublicGateway = %q, want trailing slash removed", aws.Config.PublicGateway)
	}
}

func TestNewRegistryCopiesInputSecurityCapabilitySelectors(t *testing.T) {
	config := validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")
	registry, err := NewRegistry([]ClusterConfig{config}, &sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}})
	if err != nil {
		t.Fatal(err)
	}

	config.SecurityCapabilities.DNSPodSelector["k8s-app"] = "tampered$value"
	delete(config.SecurityCapabilities.IngressPodSelector, "app.kubernetes.io/name")
	cluster, err := registry.Lookup("aws-dev")
	if err != nil {
		t.Fatal(err)
	}
	assertSupportedSelectors(t, cluster)
}

func TestRegistryLookupsDoNotExposeStoredSecurityCapabilitySelectors(t *testing.T) {
	registry, err := NewRegistry(
		[]ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")},
		&sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}},
	)
	if err != nil {
		t.Fatal(err)
	}

	created, err := registry.LookupForCreate("aws-dev")
	if err != nil {
		t.Fatal(err)
	}
	created.Config.SecurityCapabilities.DNSPodSelector["k8s-app"] = "tampered$value"
	delete(created.Config.SecurityCapabilities.IngressPodSelector, "app.kubernetes.io/name")

	maintenance, err := registry.LookupForMaintenance("aws-dev")
	if err != nil {
		t.Fatal(err)
	}
	assertSupportedSelectors(t, maintenance)
	maintenance.Config.SecurityCapabilities.DNSPodSelector["k8s-app"] = "second$tamper"
	delete(maintenance.Config.SecurityCapabilities.IngressPodSelector, "app.kubernetes.io/name")

	current, err := registry.Lookup("aws-dev")
	if err != nil {
		t.Fatal(err)
	}
	assertSupportedSelectors(t, current)
}

func assertSupportedSelectors(t *testing.T, cluster Cluster) {
	t.Helper()
	capabilities := cluster.Config.SecurityCapabilities
	if capabilities.DNSPodSelector["k8s-app"] != "kube-dns" ||
		capabilities.IngressPodSelector["app.kubernetes.io/name"] != "traefik" {
		t.Fatalf("security capability selectors = %#v / %#v", capabilities.DNSPodSelector, capabilities.IngressPodSelector)
	}
	if err := cluster.Supports(isolation.ResolvedPolicy{}); err != nil {
		t.Fatalf("Cluster.Supports() error = %v", err)
	}
}

func TestNewRegistryRejectsSharedClientAcrossEnabledTargets(t *testing.T) {
	sharedClient := fake.NewSimpleClientset()
	_, err := NewRegistry([]ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
		validClusterConfig("gcp-dev", ProviderGCP, "gcp-kubeconfig"),
	}, &sequenceFactory{clients: []kubernetes.Interface{sharedClient, sharedClient}})
	if runtimeErrorCode(t, err) != "CONFIG_INVALID" {
		t.Fatalf("code = %q, want CONFIG_INVALID", runtimeErrorCode(t, err))
	}
}

func TestNewRegistryRejectsUnidentifiableClientWithoutPanic(t *testing.T) {
	client := unidentifiableClient{
		Interface: fake.NewSimpleClientset(),
		values:    []string{"not comparable"},
	}
	_, err := NewRegistry([]ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
	}, &sequenceFactory{clients: []kubernetes.Interface{client}})
	if runtimeErrorCode(t, err) != "CONFIG_INVALID" {
		t.Fatalf("code = %q, want CONFIG_INVALID", runtimeErrorCode(t, err))
	}
}

func TestRegistryCreateLookupRejectsDisabledButMaintenanceLookupAllowsIt(t *testing.T) {
	disabled := validClusterConfig("retired", ProviderNCP, "unused-kubeconfig")
	disabled.Enabled = false
	factory := &sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}}

	registry, err := NewRegistry([]ClusterConfig{disabled}, factory)
	if err != nil {
		t.Fatal(err)
	}
	if factory.calls != 1 {
		t.Fatalf("factory calls = %d, want 1 so maintenance remains available", factory.calls)
	}

	if _, err := registry.LookupForCreate("missing"); runtimeErrorCode(t, err) != "TARGET_NOT_FOUND" {
		t.Fatalf("unknown target code = %q, want TARGET_NOT_FOUND", runtimeErrorCode(t, err))
	}
	if _, err := registry.LookupForCreate("retired"); runtimeErrorCode(t, err) != "TARGET_DISABLED" {
		t.Fatalf("disabled target code = %q, want TARGET_DISABLED", runtimeErrorCode(t, err))
	}
	maintenance, err := registry.LookupForMaintenance("retired")
	if err != nil {
		t.Fatalf("LookupForMaintenance() error = %v", err)
	}
	if maintenance.Client == nil || maintenance.Metrics == nil {
		t.Fatal("maintenance lookup returned incomplete client pair")
	}
	if factory.calls != 1 {
		t.Fatalf("factory calls = %d after lookups, want cached client pair", factory.calls)
	}
}

func TestRegistryUsesDistinctKubeAndMetricsClientsPerTarget(t *testing.T) {
	awsClient, gcpClient := fake.NewSimpleClientset(), fake.NewSimpleClientset()
	registry, err := NewRegistry([]ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig"),
		validClusterConfig("gcp-dev", ProviderGCP, "gcp-kubeconfig"),
	}, &sequenceFactory{clients: []kubernetes.Interface{awsClient, gcpClient}})
	if err != nil {
		t.Fatal(err)
	}
	aws, _ := registry.LookupForMaintenance("aws-dev")
	gcp, _ := registry.LookupForMaintenance("gcp-dev")
	if aws.Client == gcp.Client || aws.Metrics == gcp.Metrics {
		t.Fatal("targets share a Kubernetes or Metrics client")
	}
}

func TestNewRegistryRejectsDuplicateTargetAndInvalidProvider(t *testing.T) {
	valid := validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")
	for _, test := range []struct {
		name     string
		configs  []ClusterConfig
		contains string
	}{
		{
			name:     "duplicate target",
			configs:  []ClusterConfig{valid, valid},
			contains: "CONFIG_INVALID",
		},
		{
			name: "invalid provider",
			configs: []ClusterConfig{func() ClusterConfig {
				config := valid
				config.Provider = Provider("OTHER")
				return config
			}()},
			contains: "CONFIG_INVALID",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRegistry(test.configs, &sequenceFactory{})
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("NewRegistry error = %v, want %s", err, test.contains)
			}
		})
	}
}

func TestNewRegistryRejectsUnsafeGateway(t *testing.T) {
	for _, gateway := range []string{
		"ftp://gateway.example.invalid",
		"https://",
		"https://user@gateway.example.invalid",
		"https://gateway.example.invalid?unexpected=value",
		"https://gateway.example.invalid#fragment",
	} {
		t.Run(gateway, func(t *testing.T) {
			config := validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")
			config.PublicGateway = gateway
			_, err := NewRegistry([]ClusterConfig{config}, &sequenceFactory{})
			if runtimeErrorCode(t, err) != "CONFIG_INVALID" {
				t.Fatalf("code = %q, want CONFIG_INVALID", runtimeErrorCode(t, err))
			}
		})
	}
}

func TestNewRegistryHidesClientFactoryDetails(t *testing.T) {
	factoryFailure := errors.New("factory credential failure")
	_, err := NewRegistry([]ClusterConfig{
		validClusterConfig("aws-dev", ProviderAWS, "secret-kubeconfig"),
	}, &sequenceFactory{err: factoryFailure})
	if err == nil {
		t.Fatal("NewRegistry error = nil, want K3S_UNAVAILABLE")
	}
	if runtimeErrorCode(t, err) != "K3S_UNAVAILABLE" {
		t.Fatalf("code = %q, want K3S_UNAVAILABLE", runtimeErrorCode(t, err))
	}
	if strings.Contains(err.Error(), "secret-kubeconfig") || strings.Contains(err.Error(), factoryFailure.Error()) {
		t.Fatalf("error exposed sensitive detail: %v", err)
	}
}

func TestRuntimeErrorExposesOnlyStableMessageAndMetadata(t *testing.T) {
	cause := errors.New("underlying detail")
	err := &RuntimeError{code: "K3S_UNAVAILABLE", retryable: true, cause: cause}
	if err.Error() != "K3S_UNAVAILABLE" || err.Code() != "K3S_UNAVAILABLE" || !err.Retryable() {
		t.Fatalf("RuntimeError metadata is not preserved: %#v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatal("RuntimeError does not unwrap its cause")
	}
}
