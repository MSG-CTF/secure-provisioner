package k3s

import (
	"encoding/json"
	"io"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
)

type registryFile struct {
	Clusters *[]registryClusterConfig `json:"clusters"`
}

type registryClusterConfig struct {
	TargetID       string       `json:"target_id"`
	Provider       Provider     `json:"provider"`
	Region         string       `json:"region"`
	Architecture   string       `json:"architecture"`
	KubeconfigPath string       `json:"kubeconfig_path"`
	PublicGateway  string       `json:"public_gateway"`
	IngressClass   string       `json:"ingress_class,omitempty"`
	ExposureMode   ExposureMode `json:"exposure_mode,omitempty"`
	Enabled        *bool        `json:"enabled"`
}

func LoadRegistry(path string, factory ClientFactory) (*Registry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, newRuntimeError("CONFIG_INVALID", false, err)
	}
	defer file.Close()

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

func (c registryClusterConfig) clusterConfig() (ClusterConfig, bool) {
	if c.Enabled == nil {
		return ClusterConfig{}, false
	}
	return ClusterConfig{
		TargetID:       c.TargetID,
		Provider:       c.Provider,
		Region:         c.Region,
		Architecture:   c.Architecture,
		KubeconfigPath: c.KubeconfigPath,
		PublicGateway:  c.PublicGateway,
		IngressClass:   c.IngressClass,
		ExposureMode:   c.ExposureMode,
		Enabled:        *c.Enabled,
	}, true
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
