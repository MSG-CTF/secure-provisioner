package k3s

import "k8s.io/client-go/kubernetes"

type Provider string

const (
	ProviderAWS Provider = "AWS"
	ProviderGCP Provider = "GCP"
	ProviderNCP Provider = "NCP"
)

type ClusterConfig struct {
	TargetID       string   `json:"target_id"`
	Provider       Provider `json:"provider"`
	Region         string   `json:"region"`
	Architecture   string   `json:"architecture"`
	KubeconfigPath string   `json:"kubeconfig_path"`
	PublicGateway  string   `json:"public_gateway"`
	IngressClass   string   `json:"ingress_class,omitempty"`
	Enabled        bool     `json:"enabled"`
}

type Cluster struct {
	Config ClusterConfig
	Client kubernetes.Interface
}

type ClientFactory interface {
	FromKubeconfig(string) (kubernetes.Interface, error)
}
