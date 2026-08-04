package k3s

import "k8s.io/client-go/kubernetes"
import metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"

type Provider string
type ExposureMode string

const (
	ProviderAWS Provider = "AWS"
	ProviderGCP Provider = "GCP"
	ProviderNCP Provider = "NCP"

	ExposureModeIngressPath ExposureMode = "INGRESS_PATH"
	ExposureModeNodePort    ExposureMode = "NODE_PORT"
)

type ClusterConfig struct {
	TargetID       string       `json:"target_id"`
	Provider       Provider     `json:"provider"`
	Region         string       `json:"region"`
	Architecture   string       `json:"architecture"`
	KubeconfigPath string       `json:"kubeconfig_path"`
	PublicGateway  string       `json:"public_gateway"`
	IngressClass   string       `json:"ingress_class,omitempty"`
	ExposureMode   ExposureMode `json:"exposure_mode,omitempty"`
	Enabled        bool         `json:"enabled"`
}

type Cluster struct {
	Config  ClusterConfig
	Client  kubernetes.Interface
	Metrics metricsclient.Interface
}

type ClientSet struct {
	Kubernetes kubernetes.Interface
	Metrics    metricsclient.Interface
}

type ClientFactory interface {
	FromKubeconfig(string) (ClientSet, error)
}
