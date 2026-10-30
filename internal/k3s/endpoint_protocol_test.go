package k3s

import (
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEndpointHintsChangeOnlyTheSelectedPort(t *testing.T) {
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{containerNameLabel: "web"}},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Ports: []corev1.ServicePort{{Port: 8080, NodePort: 31001}, {Port: 9000, NodePort: 31002}}}}
	endpoints, err := BuildNodePortEndpoints("http://203.0.113.10", isolation.EndpointProtocolHTTP, []*corev1.Service{service})
	if err != nil {
		t.Fatal(err)
	}
	containers := []provisioner.WorkloadContainer{{Name: "web", EndpointProtocols: []provisioner.PortProtocol{{Port: 8080, Protocol: isolation.EndpointProtocolTCP}}}}
	endpoints, err = applyEndpointProtocols(endpoints, containers)
	if err != nil || len(endpoints) != 2 || endpoints[0].Protocol != isolation.EndpointProtocolTCP || endpoints[0].ServiceURL != "tcp://203.0.113.10:31001" || endpoints[1].Protocol != isolation.EndpointProtocolHTTP || endpoints[1].ServiceURL != "http://203.0.113.10:31002" {
		t.Fatalf("mixed endpoint protocols = %#v, error=%v", endpoints, err)
	}
}

func TestWebTCPHintsKeepNetworkIsolationAndRequireNodePort(t *testing.T) {
	command := validCreateCommand("aws-dev")
	cluster := validCluster("aws-dev")
	cluster.Config.ExposureMode = ExposureModeNodePort
	before, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	command.Containers[0].EndpointProtocols = []provisioner.PortProtocol{{Port: command.Containers[0].Ports[0], Protocol: isolation.EndpointProtocolTCP}}
	after, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	if command.Policy.EndpointProtocol != isolation.EndpointProtocolHTTP || !reflect.DeepEqual(before.NetworkPolicies, after.NetworkPolicies) || !reflect.DeepEqual(before.Deployment.Spec.Template.Spec, after.Deployment.Spec.Template.Spec) || !reflect.DeepEqual(before.Services, after.Services) {
		t.Fatal("connection hints changed security, networking, ports or the Pod")
	}
	cluster.Config.ExposureMode = ExposureModeIngressPath
	if _, err := BuildResourceSet(cluster, command); err == nil {
		t.Fatal("HTTP ingress accepted a raw TCP hint")
	}
}

func TestEndpointHintsRejectInvalidPortsAndProtocols(t *testing.T) {
	for _, hints := range [][]provisioner.PortProtocol{
		{{Port: 0, Protocol: isolation.EndpointProtocolTCP}},
		{{Port: 8080, Protocol: "UDP"}},
		{{Port: 8080, Protocol: isolation.EndpointProtocolTCP}, {Port: 8080, Protocol: isolation.EndpointProtocolTCP}},
	} {
		command := validCreateCommand("aws-dev")
		cluster := validCluster("aws-dev")
		cluster.Config.ExposureMode = ExposureModeNodePort
		command.Containers[0].EndpointProtocols = hints
		if _, err := BuildResourceSet(cluster, command); err == nil {
			t.Fatal("invalid connection hints accepted")
		}
	}
}
