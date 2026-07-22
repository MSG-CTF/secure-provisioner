package k3s

import (
	"encoding/json"
	"io"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type registryFile struct {
	Clusters []ClusterConfig `json:"clusters"`
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
	return NewRegistry(config.Clusters, factory)
}

type KubeconfigClientFactory struct{}

func (KubeconfigClientFactory) FromKubeconfig(path string) (kubernetes.Interface, error) {
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}
