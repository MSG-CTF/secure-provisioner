package k3s

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
)

func TestGatewayTargetRequiresNodePortAndExplicitPublicIP(t *testing.T) {
	for _, tc := range []struct {
		mode  ExposureMode
		ip    string
		valid bool
	}{{ExposureModeNodePort, "8.8.8.8", true}, {ExposureModeIngressPath, "8.8.8.8", false}, {ExposureModeNodePort, "worker.example", false}, {ExposureModeNodePort, "127.0.0.1", false}, {ExposureModeNodePort, "10.0.0.2", false}} {
		config := validClusterConfig("target", ProviderAWS, "unused")
		config.ExposureMode = tc.mode
		config.Gateway = &GatewayConfig{Enabled: true, UpstreamIP: tc.ip}
		_, err := NewRegistry([]ClusterConfig{config}, &sequenceFactory{clients: []kubernetes.Interface{fake.NewSimpleClientset()}})
		if (err == nil) != tc.valid {
			t.Fatal(tc, err)
		}
	}
}
