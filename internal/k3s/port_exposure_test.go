package k3s

import (
	"context"
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mixedPortCommand() provisioner.CreateWorkloadCommand {
	command := validCreateCommand("aws-dev")
	command.Containers[0].Ports = []int{8080, 9000}
	command.Containers[0].Expose = false
	command.Containers[0].ExposedPorts = []int{8080}
	command.Policy.Containers[0].Ports = []int{8080, 9000}
	command.Policy.Containers[0].Expose = false
	command.Policy.Containers[0].ExposedPorts = []int{8080}
	return command
}

func TestMixedPortAdapterRequiresPublicServiceEndpoints(t *testing.T) {
	for _, publicReady := range []bool{false, true} {
		t.Run(map[bool]string{false: "public missing", true: "public ready"}[publicReady], func(t *testing.T) {
			command := mixedPortCommand()
			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if err != nil {
				t.Fatal(err)
			}
			client := readyClient(t, command)
			if publicReady {
				pods, err := client.CoreV1().Pods(resources.Namespace.Name).List(context.Background(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.DiscoveryV1().EndpointSlices(resources.Namespace.Name).Create(context.Background(), readyEndpointSliceForService(resources.Namespace.Name, resources.Services[1].Name, &pods.Items[0]), metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			adapter := newTestAdapter(t, adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "aws-kubeconfig")}, client))
			result, err := adapter.CreateWorkload(context.Background(), command)
			if !publicReady {
				if err == nil {
					t.Fatal("reported ready while public service has no endpoints")
				}
				if runtimeErrorCode(t, err) != "WORKLOAD_NOT_READY" {
					t.Fatal(err)
				}
				assertDeleteActionCount(t, client, "namespaces", 1)
			} else if err != nil || len(result.Endpoints) != 1 || result.Endpoints[0].Port != 8080 {
				t.Fatalf("create result = %#v, err = %v", result, err)
			}
		})
	}
}

func TestMixedPortResourcesNeverPublishPrivatePort(t *testing.T) {
	for _, mode := range []ExposureMode{ExposureModeNodePort, ExposureModeIngressPath} {
		t.Run(string(mode), func(t *testing.T) {
			cluster := validCluster("aws-dev")
			cluster.Config.ExposureMode = mode
			resources, err := BuildResourceSet(cluster, mixedPortCommand())
			if err != nil {
				t.Fatal(err)
			}
			if len(resources.Services) != 2 {
				t.Fatalf("services = %d, want internal and public", len(resources.Services))
			}
			internal, public := resources.Services[0], resources.Services[1]
			if internal.Name != "challenge" || internal.Spec.Type != corev1.ServiceTypeClusterIP || len(internal.Spec.Ports) != 2 {
				t.Fatalf("internal service = %#v", internal)
			}
			if public.Name == internal.Name || len(public.Spec.Ports) != 1 || public.Spec.Ports[0].Port != 8080 ||
				!reflect.DeepEqual(public.Spec.Selector, internal.Spec.Selector) {
				t.Fatalf("public service = %#v", public)
			}
			quota := resources.ResourceQuota.Spec.Hard[corev1.ResourceServices]
			if quota.Value() != 2 {
				t.Fatalf("service quota = %s", quota.String())
			}
			foundPublicPolicy := false
			for _, policy := range resources.NetworkPolicies {
				if policy.Name == "allow-public-ingress-challenge" {
					foundPublicPolicy = true
					if len(policy.Spec.Ingress) != 1 || len(policy.Spec.Ingress[0].Ports) != 1 || policy.Spec.Ingress[0].Ports[0].Port.IntVal != 8080 {
						t.Fatalf("public ingress leaks private port: %#v", policy.Spec)
					}
				}
			}
			if !foundPublicPolicy {
				t.Fatal("missing public ingress policy")
			}
			if mode == ExposureModeNodePort {
				if public.Spec.Type != corev1.ServiceTypeNodePort {
					t.Fatal("missing public NodePort")
				}
				public.Spec.Ports[0].NodePort = 31042
				endpoints, err := BuildNodePortEndpoints("http://203.0.113.10", isolation.EndpointProtocolHTTP, resources.Services)
				if err != nil {
					t.Fatal(err)
				}
				if len(endpoints) != 1 || endpoints[0].ContainerName != "challenge" || endpoints[0].Port != 8080 || endpoints[0].ServiceURL != "http://203.0.113.10:31042" {
					t.Fatalf("endpoints = %#v", endpoints)
				}
			} else {
				paths := resources.Ingress.Spec.Rules[0].HTTP.Paths
				if len(paths) != 1 || paths[0].Backend.Service.Name != public.Name || paths[0].Backend.Service.Port.Number != 8080 || len(resources.Endpoints) != 1 || resources.Endpoints[0].Port != 8080 {
					t.Fatal("Ingress did not exclusively route the public service and port")
				}
			}
		})
	}
}

func TestMixedPortResourcesRejectUnapprovedExposure(t *testing.T) {
	command := mixedPortCommand()
	command.Policy.Containers[0].ExposedPorts = []int{9000}
	if _, err := BuildResourceSet(validCluster("aws-dev"), command); err == nil {
		t.Fatal("policy and command exposure mismatch accepted")
	}
}

// Losing a second public URL, publishing the private port, or returning the
// generated public Service name instead of the container name must fail here.
func TestMixedPortResourcesReturnOneURLPerPublicPort(t *testing.T) {
	for _, mode := range []ExposureMode{ExposureModeNodePort, ExposureModeIngressPath} {
		t.Run(string(mode), func(t *testing.T) {
			command := mixedPortCommand()
			command.Containers[0].Ports = []int{8080, 9000, 9090}
			command.Containers[0].ExposedPorts = []int{8080, 9090}
			command.Policy.Containers[0].Ports = []int{8080, 9000, 9090}
			command.Policy.Containers[0].ExposedPorts = []int{8080, 9090}
			cluster := validCluster("aws-dev")
			cluster.Config.ExposureMode = mode
			cluster.Config.PublicGateway = "http://203.0.113.10"
			resources, err := BuildResourceSet(cluster, command)
			if err != nil {
				t.Fatal(err)
			}
			if len(resources.Services) != 2 || len(resources.Services[1].Spec.Ports) != 2 {
				t.Fatalf("services = %#v, want internal Service and two-port public Service", resources.Services)
			}
			endpoints := resources.Endpoints
			want := []provisioner.WorkloadEndpoint{
				{ContainerName: "challenge", Port: 8080, Protocol: isolation.EndpointProtocolHTTP, ServiceURL: "http://203.0.113.10:31042"},
				{ContainerName: "challenge", Port: 9090, Protocol: isolation.EndpointProtocolHTTP, ServiceURL: "http://203.0.113.10:31043"},
			}
			if mode == ExposureModeNodePort {
				resources.Services[1].Spec.Ports[0].NodePort = 31042
				resources.Services[1].Spec.Ports[1].NodePort = 31043
				endpoints, err = BuildNodePortEndpoints(cluster.Config.PublicGateway, isolation.EndpointProtocolHTTP, resources.Services)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				want[0].ServiceURL = "http://203.0.113.10/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001"
				want[1].ServiceURL = "http://203.0.113.10/instances/018f3f1e-21b8-7a91-a30b-63b3400fd001/challenge/9090"
				paths := resources.Ingress.Spec.Rules[0].HTTP.Paths
				if len(paths) != 2 || paths[0].Backend.Service.Port.Number != 8080 || paths[1].Backend.Service.Port.Number != 9090 {
					t.Fatalf("ingress paths = %#v, want only the two public ports", paths)
				}
				if resources.ServiceURL != want[0].ServiceURL {
					t.Fatalf("service URL = %q, want first public URL", resources.ServiceURL)
				}
			}
			if !reflect.DeepEqual(endpoints, want) {
				t.Fatalf("endpoints = %#v, want %#v", endpoints, want)
			}
		})
	}
}

func TestMixedPublicServiceNamesAvoidContainerNames(t *testing.T) {
	command := mixedPortCommand()
	for _, name := range []string{"public-0", "public-0-1"} {
		container := provisioner.WorkloadContainer{Name: name, Image: command.Containers[0].Image, Ports: []int{9000}}
		command.Containers = append(command.Containers, container)
		command.Policy.Containers = append(command.Policy.Containers, isolation.ContainerRequirement{Name: name, Ports: []int{9000}, RunAsUser: 10001})
	}
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, service := range resources.Services {
		if seen[service.Name] {
			t.Fatalf("duplicate service name %q", service.Name)
		}
		seen[service.Name] = true
	}
	if len(resources.Services) != 4 {
		t.Fatalf("services = %d", len(resources.Services))
	}
}
