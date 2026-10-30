package k3s

import (
	"slices"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)
import metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"

type Provider string
type ExposureMode string

const (
	ProviderAWS   Provider = "AWS"
	ProviderGCP   Provider = "GCP"
	ProviderNCP   Provider = "NCP"
	ProviderLocal Provider = "LOCAL"

	ExposureModeIngressPath ExposureMode = "INGRESS_PATH"
	ExposureModeNodePort    ExposureMode = "NODE_PORT"
)

type ClusterConfig struct {
	TargetID               string               `json:"target_id"`
	BrokerResourceTargetID string               `json:"broker_resource_target_id,omitempty"`
	Provider               Provider             `json:"provider"`
	Region                 string               `json:"region"`
	Architecture           string               `json:"architecture"`
	KubeconfigPath         string               `json:"kubeconfig_path"`
	PublicGateway          string               `json:"public_gateway"`
	IngressClass           string               `json:"ingress_class,omitempty"`
	ExposureMode           ExposureMode         `json:"exposure_mode,omitempty"`
	Enabled                bool                 `json:"enabled"`
	Gateway                *GatewayConfig       `json:"gateway,omitempty"`
	SecurityCapabilities   SecurityCapabilities `json:"security_capabilities"`
}

type GatewayConfig struct {
	Enabled    bool   `json:"enabled"`
	UpstreamIP string `json:"upstream_ip"`
}

// SecurityCapabilities records operator-declared lab configuration. It is not
// runtime attestation that the target enforces these capabilities.
type SecurityCapabilities struct {
	NetworkPolicyEnforced          bool              `json:"network_policy_enforced"`
	SupplementalGroupsPolicyStrict bool              `json:"supplemental_groups_policy_strict"`
	PodPIDLimitEnforced            bool              `json:"pod_pid_limit_enforced"`
	NetworkPolicyProvider          string            `json:"network_policy_provider"`
	DNSNamespace                   string            `json:"dns_namespace"`
	DNSPodSelector                 map[string]string `json:"dns_pod_selector"`
	IngressNamespace               string            `json:"ingress_namespace"`
	IngressPodSelector             map[string]string `json:"ingress_pod_selector"`
	RuntimeClasses                 []string          `json:"runtime_classes,omitempty"`
}

type Cluster struct {
	Config  ClusterConfig
	Client  kubernetes.Interface
	Metrics metricsclient.Interface
	// Keep resolved credentials in memory for exec; never serialize them.
	restConfig *rest.Config
}

func (c Cluster) Supports(policy isolation.ResolvedPolicy) error {
	capabilities := c.Config.SecurityCapabilities
	if !capabilities.NetworkPolicyEnforced ||
		!capabilities.SupplementalGroupsPolicyStrict ||
		!capabilities.PodPIDLimitEnforced ||
		!validSecurityCapabilities(capabilities, c.Config.ExposureMode) {
		return newRuntimeError("TARGET_CAPABILITY_MISMATCH", false, nil)
	}
	if policy.RuntimeClassName != "" && !slices.Contains(capabilities.RuntimeClasses, policy.RuntimeClassName) {
		return newRuntimeError("TARGET_CAPABILITY_MISMATCH", false, nil)
	}
	if policy.ExposureRequirement == isolation.ExposureNodePortOnly && c.Config.ExposureMode != ExposureModeNodePort {
		return newRuntimeError("TARGET_CAPABILITY_MISMATCH", false, nil)
	}
	return nil
}

type ClientSet struct {
	Kubernetes kubernetes.Interface
	Metrics    metricsclient.Interface
	restConfig *rest.Config
}

func cloneRESTConfig(config *rest.Config) *rest.Config {
	if config == nil {
		return nil
	}
	copy := *config
	// client-go CopyConfig replaces ExecProvider.Config on its provider pointer.
	// Detach the provider first so registry readers never mutate shared auth.
	if config.ExecProvider != nil {
		copy.ExecProvider = config.ExecProvider.DeepCopy()
	}
	return rest.CopyConfig(&copy)
}

type ClientFactory interface {
	FromKubeconfig(string) (ClientSet, error)
}
