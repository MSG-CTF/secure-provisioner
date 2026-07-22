package k3s

import (
	"errors"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

type sequenceFactory struct {
	clients []kubernetes.Interface
	err     error
	calls   int
}

func (f *sequenceFactory) FromKubeconfig(string) (kubernetes.Interface, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.calls > len(f.clients) {
		return nil, errors.New("unexpected client factory call")
	}
	return f.clients[f.calls-1], nil
}

func validClusterConfig(targetID string, provider Provider, kubeconfigPath string) ClusterConfig {
	return ClusterConfig{
		TargetID:       targetID,
		Provider:       provider,
		Region:         "test-region",
		Architecture:   "amd64",
		KubeconfigPath: kubeconfigPath,
		PublicGateway:  "https://gateway.example.invalid/",
		IngressClass:   "nginx",
		Enabled:        true,
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

func TestRegistryRejectsUnknownAndDisabledTargetBeforeClientUse(t *testing.T) {
	disabled := validClusterConfig("retired", ProviderNCP, "unused-kubeconfig")
	disabled.Enabled = false
	factory := &sequenceFactory{}

	registry, err := NewRegistry([]ClusterConfig{disabled}, factory)
	if err != nil {
		t.Fatal(err)
	}
	if factory.calls != 0 {
		t.Fatalf("factory calls = %d, want 0 for disabled target", factory.calls)
	}

	if _, err := registry.Lookup("missing"); runtimeErrorCode(t, err) != "TARGET_NOT_FOUND" {
		t.Fatalf("unknown target code = %q, want TARGET_NOT_FOUND", runtimeErrorCode(t, err))
	}
	if _, err := registry.Lookup("retired"); runtimeErrorCode(t, err) != "TARGET_DISABLED" {
		t.Fatalf("disabled target code = %q, want TARGET_DISABLED", runtimeErrorCode(t, err))
	}
	if factory.calls != 0 {
		t.Fatalf("factory calls = %d after lookups, want 0", factory.calls)
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
