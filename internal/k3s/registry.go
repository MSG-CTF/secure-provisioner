package k3s

import (
	"net/url"
	"strings"
)

type Registry struct {
	targets map[string]Cluster
}

func NewRegistry(configs []ClusterConfig, factory ClientFactory) (*Registry, error) {
	normalizedConfigs := make([]ClusterConfig, len(configs))
	seenTargetIDs := make(map[string]struct{}, len(configs))
	for index, config := range configs {
		normalized, err := validateClusterConfig(config, seenTargetIDs)
		if err != nil {
			return nil, err
		}
		normalizedConfigs[index] = normalized
	}

	targets := make(map[string]Cluster, len(normalizedConfigs))
	for _, config := range normalizedConfigs {
		cluster := Cluster{Config: config}
		if config.Enabled {
			if factory == nil {
				return nil, newRuntimeError("K3S_UNAVAILABLE", true, nil)
			}
			client, err := factory.FromKubeconfig(config.KubeconfigPath)
			if err != nil || client == nil {
				return nil, newRuntimeError("K3S_UNAVAILABLE", true, err)
			}
			cluster.Client = client
		}
		targets[config.TargetID] = cluster
	}

	return &Registry{targets: targets}, nil
}

func (r *Registry) Lookup(targetID string) (Cluster, error) {
	cluster, found := r.targets[targetID]
	if !found {
		return Cluster{}, newRuntimeError("TARGET_NOT_FOUND", false, nil)
	}
	if !cluster.Config.Enabled {
		return Cluster{}, newRuntimeError("TARGET_DISABLED", false, nil)
	}
	return cluster, nil
}

func validateClusterConfig(config ClusterConfig, seenTargetIDs map[string]struct{}) (ClusterConfig, error) {
	if strings.TrimSpace(config.TargetID) == "" || strings.TrimSpace(config.Region) == "" || strings.TrimSpace(config.Architecture) == "" || strings.TrimSpace(config.KubeconfigPath) == "" {
		return ClusterConfig{}, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	if _, exists := seenTargetIDs[config.TargetID]; exists {
		return ClusterConfig{}, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	if config.Provider != ProviderAWS && config.Provider != ProviderGCP && config.Provider != ProviderNCP {
		return ClusterConfig{}, newRuntimeError("CONFIG_INVALID", false, nil)
	}

	gateway, err := url.ParseRequestURI(config.PublicGateway)
	if err != nil || (gateway.Scheme != "http" && gateway.Scheme != "https") || gateway.Hostname() == "" || gateway.User != nil || gateway.RawQuery != "" || gateway.Fragment != "" {
		return ClusterConfig{}, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	gateway.Path = strings.TrimRight(gateway.Path, "/")
	gateway.RawPath = ""
	config.PublicGateway = gateway.String()
	seenTargetIDs[config.TargetID] = struct{}{}
	return config, nil
}
