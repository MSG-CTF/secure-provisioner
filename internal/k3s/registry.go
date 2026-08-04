package k3s

import (
	"net/url"
	"reflect"
	"strings"
)

type Registry struct {
	targets map[string]Cluster
}

type clientIdentity struct {
	clientType reflect.Type
	pointer    uintptr
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
	clientIdentities := make(map[clientIdentity]struct{}, len(normalizedConfigs))
	metricsIdentities := make(map[clientIdentity]struct{}, len(normalizedConfigs))
	for _, config := range normalizedConfigs {
		cluster := Cluster{Config: config}
		if factory == nil {
			return nil, newRuntimeError("K3S_UNAVAILABLE", true, nil)
		}
		clients, err := factory.FromKubeconfig(config.KubeconfigPath)
		if err != nil || clients.Kubernetes == nil || clients.Metrics == nil {
			return nil, newRuntimeError("K3S_UNAVAILABLE", true, err)
		}
		identity, ok := identifyClient(clients.Kubernetes)
		if !ok {
			return nil, newRuntimeError("CONFIG_INVALID", false, nil)
		}
		if _, exists := clientIdentities[identity]; exists {
			return nil, newRuntimeError("CONFIG_INVALID", false, nil)
		}
		metricsIdentity, ok := identifyClient(clients.Metrics)
		if !ok {
			return nil, newRuntimeError("CONFIG_INVALID", false, nil)
		}
		if _, exists := metricsIdentities[metricsIdentity]; exists {
			return nil, newRuntimeError("CONFIG_INVALID", false, nil)
		}
		clientIdentities[identity] = struct{}{}
		metricsIdentities[metricsIdentity] = struct{}{}
		cluster.Client = clients.Kubernetes
		cluster.Metrics = clients.Metrics
		targets[config.TargetID] = cluster
	}

	return &Registry{targets: targets}, nil
}

func identifyClient(client any) (clientIdentity, bool) {
	value := reflect.ValueOf(client)
	if !value.IsValid() || value.Kind() != reflect.Ptr || value.IsNil() {
		return clientIdentity{}, false
	}
	return clientIdentity{clientType: value.Type(), pointer: value.Pointer()}, true
}

func (r *Registry) Lookup(targetID string) (Cluster, error) {
	return r.LookupForCreate(targetID)
}

func (r *Registry) LookupForCreate(targetID string) (Cluster, error) {
	cluster, found := r.targets[targetID]
	if !found {
		return Cluster{}, newRuntimeError("TARGET_NOT_FOUND", false, nil)
	}
	if !cluster.Config.Enabled {
		return Cluster{}, newRuntimeError("TARGET_DISABLED", false, nil)
	}
	return cluster, nil
}

func (r *Registry) LookupForMaintenance(targetID string) (Cluster, error) {
	cluster, found := r.targets[targetID]
	if !found {
		return Cluster{}, newRuntimeError("TARGET_NOT_FOUND", false, nil)
	}
	if cluster.Client == nil || cluster.Metrics == nil {
		return Cluster{}, newRuntimeError("K3S_UNAVAILABLE", true, nil)
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
	if config.ExposureMode == "" {
		config.ExposureMode = ExposureModeIngressPath
	}
	if config.ExposureMode != ExposureModeIngressPath && config.ExposureMode != ExposureModeNodePort {
		return ClusterConfig{}, newRuntimeError("CONFIG_INVALID", false, nil)
	}

	gateway, err := url.ParseRequestURI(config.PublicGateway)
	if err != nil || (gateway.Scheme != "http" && gateway.Scheme != "https") || gateway.Hostname() == "" || gateway.User != nil || gateway.RawQuery != "" || gateway.Fragment != "" {
		return ClusterConfig{}, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	if config.ExposureMode == ExposureModeNodePort && (strings.Trim(gateway.Path, "/") != "" || gateway.Port() != "") {
		return ClusterConfig{}, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	gateway.Path = strings.TrimRight(gateway.Path, "/")
	gateway.RawPath = ""
	config.PublicGateway = gateway.String()
	seenTargetIDs[config.TargetID] = struct{}{}
	return config, nil
}
