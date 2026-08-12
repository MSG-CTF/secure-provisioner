package k3s

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
)

type registryFile struct {
	Clusters *[]registryClusterConfig `json:"clusters"`
}

type registryClusterConfig struct {
	TargetID             string                        `json:"target_id"`
	Provider             Provider                      `json:"provider"`
	Region               string                        `json:"region"`
	Architecture         string                        `json:"architecture"`
	KubeconfigPath       string                        `json:"kubeconfig_path"`
	PublicGateway        string                        `json:"public_gateway"`
	IngressClass         string                        `json:"ingress_class,omitempty"`
	ExposureMode         ExposureMode                  `json:"exposure_mode,omitempty"`
	Enabled              *bool                         `json:"enabled"`
	SecurityCapabilities *registrySecurityCapabilities `json:"security_capabilities"`
}

type registrySecurityCapabilities struct {
	NetworkPolicyEnforced          *bool             `json:"network_policy_enforced"`
	SupplementalGroupsPolicyStrict *bool             `json:"supplemental_groups_policy_strict"`
	NetworkPolicyProvider          string            `json:"network_policy_provider"`
	DNSNamespace                   string            `json:"dns_namespace"`
	DNSPodSelector                 map[string]string `json:"dns_pod_selector"`
	IngressNamespace               string            `json:"ingress_namespace"`
	IngressPodSelector             map[string]string `json:"ingress_pod_selector"`
	RuntimeClasses                 []string          `json:"runtime_classes,omitempty"`
}

func LoadRegistry(path string, factory ClientFactory) (*Registry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, newRuntimeError("CONFIG_INVALID", false, err)
	}
	defer file.Close()

	if err := rejectDuplicateRegistryJSONKeys(file); err != nil {
		return nil, newRuntimeError("CONFIG_INVALID", false, err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, newRuntimeError("CONFIG_INVALID", false, err)
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var config registryFile
	if err := decoder.Decode(&config); err != nil {
		return nil, newRuntimeError("CONFIG_INVALID", false, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, newRuntimeError("CONFIG_INVALID", false, err)
	}
	if config.Clusters == nil || len(*config.Clusters) == 0 {
		return nil, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	clusters := make([]ClusterConfig, len(*config.Clusters))
	for index, rawCluster := range *config.Clusters {
		cluster, ok := rawCluster.clusterConfig()
		if !ok {
			return nil, newRuntimeError("CONFIG_INVALID", false, nil)
		}
		clusters[index] = cluster
	}
	return NewRegistry(clusters, factory)
}

func rejectDuplicateRegistryJSONKeys(reader io.Reader) error {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	if err := scanRegistryJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("registry must contain one JSON value")
		}
		return err
	}
	return nil
}

func scanRegistryJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make([]string, 0)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object field name must be a string")
			}
			for _, existing := range seen {
				if strings.EqualFold(existing, key) {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
			}
			seen = append(seen, key)
			if err := scanRegistryJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanRegistryJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func (c registryClusterConfig) clusterConfig() (ClusterConfig, bool) {
	if c.Enabled == nil {
		return ClusterConfig{}, false
	}
	if *c.Enabled && (c.SecurityCapabilities == nil ||
		c.SecurityCapabilities.NetworkPolicyEnforced == nil ||
		c.SecurityCapabilities.SupplementalGroupsPolicyStrict == nil) {
		return ClusterConfig{}, false
	}
	capabilities := SecurityCapabilities{}
	if c.SecurityCapabilities != nil {
		capabilities = c.SecurityCapabilities.clusterCapabilities()
	}
	return ClusterConfig{
		TargetID:             c.TargetID,
		Provider:             c.Provider,
		Region:               c.Region,
		Architecture:         c.Architecture,
		KubeconfigPath:       c.KubeconfigPath,
		PublicGateway:        c.PublicGateway,
		IngressClass:         c.IngressClass,
		ExposureMode:         c.ExposureMode,
		Enabled:              *c.Enabled,
		SecurityCapabilities: capabilities,
	}, true
}

func (c registrySecurityCapabilities) clusterCapabilities() SecurityCapabilities {
	capabilities := SecurityCapabilities{
		NetworkPolicyProvider: c.NetworkPolicyProvider,
		DNSNamespace:          c.DNSNamespace,
		DNSPodSelector:        c.DNSPodSelector,
		IngressNamespace:      c.IngressNamespace,
		IngressPodSelector:    c.IngressPodSelector,
		RuntimeClasses:        append([]string(nil), c.RuntimeClasses...),
	}
	if c.NetworkPolicyEnforced != nil {
		capabilities.NetworkPolicyEnforced = *c.NetworkPolicyEnforced
	}
	if c.SupplementalGroupsPolicyStrict != nil {
		capabilities.SupplementalGroupsPolicyStrict = *c.SupplementalGroupsPolicyStrict
	}
	return capabilities
}

type KubeconfigClientFactory struct{}

func (KubeconfigClientFactory) FromKubeconfig(path string) (ClientSet, error) {
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return ClientSet{}, err
	}
	kubernetesClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return ClientSet{}, err
	}
	metrics, err := metricsclient.NewForConfig(config)
	if err != nil {
		return ClientSet{}, err
	}
	return ClientSet{Kubernetes: kubernetesClient, Metrics: metrics}, nil
}
