package k3s

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
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

const completeSecurityCapabilitiesJSON = `{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`

func TestLoadClusterConfigsAcceptsCompleteIsolationCapability(t *testing.T) {
	path := writeRegistryFile(t, `{"clusters":[{"target_id":"lab","provider":"AWS","region":"ap-northeast-2","architecture":"amd64","kubeconfig_path":"lab.yaml","public_gateway":"https://lab.example","enabled":true,"security_capabilities":`+completeSecurityCapabilitiesJSON+`}]}`)
	client := fake.NewSimpleClientset()
	registry, err := LoadRegistry(path, &sequenceFactory{clients: []kubernetes.Interface{client}})
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := registry.Lookup("lab")
	if err != nil {
		t.Fatal(err)
	}
	if !cluster.Config.SecurityCapabilities.NetworkPolicyEnforced ||
		!cluster.Config.SecurityCapabilities.SupplementalGroupsPolicyStrict ||
		cluster.Config.SecurityCapabilities.NetworkPolicyProvider != "kube-router" {
		t.Fatalf("security capabilities = %#v", cluster.Config.SecurityCapabilities)
	}
}

func TestLoadClusterConfigsPreservesExplicitUnsupportedCapability(t *testing.T) {
	capabilities := `{"network_policy_enforced":false,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`
	path := writeRegistryFile(t, `{"clusters":[{"target_id":"lab","provider":"AWS","region":"ap-northeast-2","architecture":"amd64","kubeconfig_path":"lab.yaml","public_gateway":"https://lab.example","enabled":true,"security_capabilities":`+capabilities+`}]}`)
	registry, err := LoadRegistry(path, &sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}})
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := registry.Lookup("lab")
	if err != nil {
		t.Fatal(err)
	}
	if cluster.Config.SecurityCapabilities.NetworkPolicyEnforced {
		t.Fatal("explicit false enforcement declaration was not preserved")
	}
}

func TestLoadClusterConfigsPreservesExplicitUnsupportedStrictSupplementalGroupsCapability(t *testing.T) {
	capabilities := `{"network_policy_enforced":true,"supplemental_groups_policy_strict":false,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`
	path := writeRegistryFile(t, `{"clusters":[{"target_id":"lab","provider":"AWS","region":"ap-northeast-2","architecture":"amd64","kubeconfig_path":"lab.yaml","public_gateway":"https://lab.example","enabled":true,"security_capabilities":`+capabilities+`}]}`)
	registry, err := LoadRegistry(path, &sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}})
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := registry.Lookup("lab")
	if err != nil {
		t.Fatal(err)
	}
	if !cluster.Config.SecurityCapabilities.NetworkPolicyEnforced || cluster.Config.SecurityCapabilities.SupplementalGroupsPolicyStrict {
		t.Fatalf("security capabilities = %#v, want strict policy capability preserved as false", cluster.Config.SecurityCapabilities)
	}
	err = cluster.Supports(isolation.ResolvedPolicy{})
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Code() != "TARGET_CAPABILITY_MISMATCH" || runtimeErr.Retryable() {
		t.Fatalf("Cluster.Supports() error = %#v, want non-retryable TARGET_CAPABILITY_MISMATCH", err)
	}
}

func TestLoadClusterConfigsRejectsIncompleteIsolationCapability(t *testing.T) {
	for _, test := range []struct {
		name         string
		capabilities string
	}{
		{name: "missing", capabilities: ""},
		{name: "null", capabilities: `,"security_capabilities":null`},
		{name: "missing enforcement declaration", capabilities: `,"security_capabilities":{"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`},
		{name: "missing strict supplemental groups declaration", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`},
		{name: "null strict supplemental groups declaration", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":null,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`},
		{name: "missing provider", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`},
		{name: "missing DNS namespace", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`},
		{name: "missing ingress namespace", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`},
		{name: "empty DNS selector", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`},
		{name: "empty ingress selector", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{}}`},
		{name: "invalid DNS selector key", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"invalid key":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`},
		{name: "invalid ingress selector value", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"invalid$value"}}`},
		{name: "malformed selector", capabilities: `,"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":["kube-dns"],"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			cluster := `{"target_id":"lab","provider":"AWS","region":"ap-northeast-2","architecture":"amd64","kubeconfig_path":"lab.yaml","public_gateway":"https://lab.example","enabled":true` + test.capabilities + `}`
			factory := &sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}}
			_, err := LoadRegistry(writeRegistryFile(t, `{"clusters":[`+cluster+`]}`), factory)
			if code := runtimeErrorCode(t, err); code != "CONFIG_INVALID" {
				t.Fatalf("code = %q, want CONFIG_INVALID", code)
			}
			if factory.calls != 0 {
				t.Fatalf("client factory calls = %d, want 0", factory.calls)
			}
		})
	}
}

func TestLoadClusterConfigsKeepsDisabledLegacyTargetLoadable(t *testing.T) {
	path := writeRegistryFile(t, `{"clusters":[{"target_id":"retired","provider":"AWS","region":"ap-northeast-2","architecture":"amd64","kubeconfig_path":"retired.yaml","public_gateway":"https://retired.example","enabled":false}]}`)
	if _, err := LoadRegistry(path, &sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}}); err != nil {
		t.Fatal(err)
	}
}

func TestLoadClusterConfigsRejectsDuplicateJSONKeysRecursively(t *testing.T) {
	capabilityTail := `"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}`
	clusterPrefix := `{"target_id":"lab","provider":"AWS","region":"ap-northeast-2","architecture":"amd64","kubeconfig_path":"lab.yaml","public_gateway":"https://lab.example","enabled":true,`
	for _, test := range []struct {
		name    string
		cluster string
	}{
		{
			name:    "exact duplicate capability field",
			cluster: clusterPrefix + `"security_capabilities":` + completeSecurityCapabilitiesJSON + `,"security_capabilities":` + completeSecurityCapabilitiesJSON + `}`,
		},
		{
			name:    "case variant duplicate capability field",
			cluster: clusterPrefix + `"security_capabilities":` + completeSecurityCapabilitiesJSON + `,"SECURITY_CAPABILITIES":` + completeSecurityCapabilitiesJSON + `}`,
		},
		{
			name:    "exact duplicate enforcement field",
			cluster: clusterPrefix + `"security_capabilities":{"network_policy_enforced":true,"network_policy_enforced":true,` + capabilityTail + `}`,
		},
		{
			name:    "case variant duplicate enforcement field",
			cluster: clusterPrefix + `"security_capabilities":{"network_policy_enforced":true,"NETWORK_POLICY_ENFORCED":true,` + capabilityTail + `}`,
		},
		{
			name:    "exact duplicate strict supplemental groups field",
			cluster: clusterPrefix + `"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"supplemental_groups_policy_strict":false,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}}`,
		},
		{
			name:    "case variant duplicate strict supplemental groups field",
			cluster: clusterPrefix + `"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"SUPPLEMENTAL_GROUPS_POLICY_STRICT":false,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}}`,
		},
		{
			name:    "duplicate selector field",
			cluster: clusterPrefix + `"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns"},"DNS_POD_SELECTOR":{"k8s-app":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}}`,
		},
		{
			name:    "duplicate key inside selector",
			cluster: clusterPrefix + `"security_capabilities":{"network_policy_enforced":true,"supplemental_groups_policy_strict":true,"network_policy_provider":"kube-router","dns_namespace":"kube-system","dns_pod_selector":{"k8s-app":"kube-dns","K8S-APP":"kube-dns"},"ingress_namespace":"kube-system","ingress_pod_selector":{"app.kubernetes.io/name":"traefik"}}}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory := &sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}}
			_, err := LoadRegistry(writeRegistryFile(t, `{"clusters":[`+test.cluster+`]}`), factory)
			if code := runtimeErrorCode(t, err); code != "CONFIG_INVALID" {
				t.Fatalf("code = %q, want CONFIG_INVALID", code)
			}
			if factory.calls != 0 {
				t.Fatalf("client factory calls = %d, want 0", factory.calls)
			}
		})
	}
}

func TestLoadRegistryRejectsUnknownFieldsAndMultipleJSONValues(t *testing.T) {
	validJSON := `{"clusters":[{"target_id":"aws-dev","provider":"AWS","region":"test-region","architecture":"amd64","kubeconfig_path":"aws-kubeconfig","public_gateway":"https://gateway.example.invalid","enabled":true,"security_capabilities":` + completeSecurityCapabilitiesJSON + `}]}`
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
	clusterWithoutEnabled := `{"target_id":"aws-dev","provider":"AWS","region":"test-region","architecture":"amd64","kubeconfig_path":"aws-kubeconfig","public_gateway":"https://gateway.example.invalid","security_capabilities":` + completeSecurityCapabilitiesJSON + `}`
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
	registryPath := writeRegistryFile(t, `{"clusters":[{"target_id":"aws-dev","provider":"AWS","region":"test-region","architecture":"amd64","kubeconfig_path":"private-kubeconfig","public_gateway":"https://gateway.example.invalid","enabled":true,"security_capabilities":`+completeSecurityCapabilitiesJSON+`}]}`)
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
	path := writeRegistryFile(t, `{"clusters":[{"target_id":"aws-dev","provider":"AWS","region":"test-region","architecture":"amd64","kubeconfig_path":"aws-kubeconfig","public_gateway":"https://gateway.example.invalid","enabled":true,"security_capabilities":`+completeSecurityCapabilitiesJSON+`}]}`)
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

func TestLoadRegistryNormalizesExposureMode(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		want  ExposureMode
	}{
		{name: "omitted defaults to ingress", field: "", want: ExposureModeIngressPath},
		{name: "node port is retained", field: `,"exposure_mode":"NODE_PORT"`, want: ExposureModeNodePort},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := `{"clusters":[{"target_id":"aws-dev","provider":"AWS","region":"test-region","architecture":"amd64","kubeconfig_path":"aws-kubeconfig","public_gateway":"http://203.0.113.10"` + test.field + `,"enabled":true,"security_capabilities":` + completeSecurityCapabilitiesJSON + `}]}`
			registry, err := LoadRegistry(writeRegistryFile(t, content), &sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}})
			if err != nil {
				t.Fatal(err)
			}
			cluster, err := registry.Lookup("aws-dev")
			if err != nil {
				t.Fatal(err)
			}
			if cluster.Config.ExposureMode != test.want {
				t.Fatalf("ExposureMode = %q, want %q", cluster.Config.ExposureMode, test.want)
			}
		})
	}
}
