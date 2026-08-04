package k3s

import (
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"

	"k8s.io/client-go/kubernetes"
)
import metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"

type Provider string

const (
	ProviderAWS Provider = "AWS"
	ProviderGCP Provider = "GCP"
	ProviderNCP Provider = "NCP"
)

type ClusterConfig struct {
	TargetID             string               `json:"target_id"`
	Provider             Provider             `json:"provider"`
	Region               string               `json:"region"`
	Architecture         string               `json:"architecture"`
	KubeconfigPath       string               `json:"kubeconfig_path"`
	PublicGateway        string               `json:"public_gateway"`
	IngressClass         string               `json:"ingress_class,omitempty"`
	Enabled              bool                 `json:"enabled"`
	SecurityCapabilities SecurityCapabilities `json:"security_capabilities"`
}

// SecurityCapabilities records operator-declared lab configuration. It is not
// runtime attestation that the target enforces these capabilities.
type SecurityCapabilities struct {
	NetworkPolicyEnforced bool              `json:"network_policy_enforced"`
	NetworkPolicyProvider string            `json:"network_policy_provider"`
	DNSNamespace          string            `json:"dns_namespace"`
	DNSPodSelector        map[string]string `json:"dns_pod_selector"`
	IngressNamespace      string            `json:"ingress_namespace"`
	IngressPodSelector    map[string]string `json:"ingress_pod_selector"`
}

type Cluster struct {
	Config  ClusterConfig
	Client  kubernetes.Interface
	Metrics metricsclient.Interface
}

func (c Cluster) Supports(_ isolation.ResolvedPolicy) error {
	capabilities := c.Config.SecurityCapabilities
	if !capabilities.NetworkPolicyEnforced || !validSecurityCapabilities(capabilities) {
		return newRuntimeError("TARGET_CAPABILITY_MISMATCH", false, nil)
	}
	return nil
}

type ClientSet struct {
	Kubernetes kubernetes.Interface
	Metrics    metricsclient.Interface
}

type ClientFactory interface {
	FromKubeconfig(string) (ClientSet, error)
}
