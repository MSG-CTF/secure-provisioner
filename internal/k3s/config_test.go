package k3s

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func writeRegistryFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clusters.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRegistryRejectsUnknownFieldsAndMultipleJSONValues(t *testing.T) {
	validJSON := `{"clusters":[{"target_id":"aws-dev","provider":"AWS","region":"test-region","architecture":"amd64","kubeconfig_path":"aws-kubeconfig","public_gateway":"https://gateway.example.invalid","enabled":true}]}`
	for _, content := range []string{
		`{"clusters":[],"unexpected":true}`,
		validJSON + "\n{}",
	} {
		_, err := LoadRegistry(writeRegistryFile(t, content), &sequenceFactory{})
		if runtimeErrorCode(t, err) != "CONFIG_INVALID" {
			t.Fatalf("code = %q, want CONFIG_INVALID", runtimeErrorCode(t, err))
		}
	}
}

func TestLoadRegistryRejectsMissingRequiredJSONFields(t *testing.T) {
	clusterWithoutEnabled := `{"target_id":"aws-dev","provider":"AWS","region":"test-region","architecture":"amd64","kubeconfig_path":"aws-kubeconfig","public_gateway":"https://gateway.example.invalid"}`
	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "missing clusters", content: `{}`},
		{name: "null clusters", content: `{"clusters":null}`},
		{name: "empty clusters", content: `{"clusters":[]}`},
		{name: "missing enabled", content: `{"clusters":[` + clusterWithoutEnabled + `]}`},
		{name: "null enabled", content: `{"clusters":[` + strings.TrimSuffix(clusterWithoutEnabled, "}") + `,"enabled":null}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadRegistry(writeRegistryFile(t, test.content), &sequenceFactory{})
			if runtimeErrorCode(t, err) != "CONFIG_INVALID" {
				t.Fatalf("code = %q, want CONFIG_INVALID", runtimeErrorCode(t, err))
			}
		})
	}
}

func TestLoadRegistryDoesNotExposePathOrKubeconfigError(t *testing.T) {
	registryPath := writeRegistryFile(t, `{"clusters":[{"target_id":"aws-dev","provider":"AWS","region":"test-region","architecture":"amd64","kubeconfig_path":"private-kubeconfig","public_gateway":"https://gateway.example.invalid","enabled":true}]}`)
	factoryFailure := errors.New("kubeconfig parsing detail")
	_, err := LoadRegistry(registryPath, &sequenceFactory{err: factoryFailure})
	if err == nil {
		t.Fatal("LoadRegistry error = nil, want K3S_UNAVAILABLE")
	}
	if strings.Contains(err.Error(), registryPath) || strings.Contains(err.Error(), "private-kubeconfig") || strings.Contains(err.Error(), factoryFailure.Error()) {
		t.Fatalf("error exposed sensitive detail: %v", err)
	}
}

func TestKubeconfigClientFactoryBuildsIndependentClients(t *testing.T) {
	kubeconfigPath := filepath.Join(t.TempDir(), "config")
	kubeconfig := `apiVersion: v1
clusters:
- cluster:
    server: https://cluster.example.invalid
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
kind: Config
users:
- name: test
  user:
    token: test-token
`
	if err := os.WriteFile(kubeconfigPath, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	factory := KubeconfigClientFactory{}
	first, err := factory.FromKubeconfig(kubeconfigPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := factory.FromKubeconfig(kubeconfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if first.Kubernetes == second.Kubernetes || first.Metrics == second.Metrics {
		t.Fatal("KubeconfigClientFactory returned a shared client pair")
	}
}

func TestLoadRegistryBuildsARegistry(t *testing.T) {
	path := writeRegistryFile(t, `{"clusters":[{"target_id":"aws-dev","provider":"AWS","region":"test-region","architecture":"amd64","kubeconfig_path":"aws-kubeconfig","public_gateway":"https://gateway.example.invalid","enabled":true}]}`)
	client := fake.NewSimpleClientset()
	registry, err := LoadRegistry(path, &sequenceFactory{clients: []kubernetes.Interface{client}})
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := registry.Lookup("aws-dev")
	if err != nil {
		t.Fatal(err)
	}
	if cluster.Client != client {
		t.Fatal("registry did not retain factory client")
	}
}
