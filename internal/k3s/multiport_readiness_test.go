package k3s

import (
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestBuildResourceSetTCPReadinessUsesOnlyPublicPort(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Containers[0].Ports = []int{9000, 8080}
	command.Policy = resolvedPolicyForCommand(command, "SMALL_SINGLE")
	command.Containers[0].Expose = false
	command.Containers[0].ExposedPorts = []int{8080}
	command.Policy.Containers[0].Expose = false
	command.Policy.Containers[0].ExposedPorts = []int{8080}

	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	probe := resources.Deployment.Spec.Template.Spec.Containers[0].ReadinessProbe
	if probe == nil || probe.TCPSocket == nil || probe.TCPSocket.Port.IntValue() != 8080 {
		t.Fatalf("TCP readiness checks %#v, want the exposed port 8080", probe)
	}
}

func TestBuildResourceSetAcceptsMultiplePublicPortsWithOptionalHTTPReadiness(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Containers[0].Ports = []int{8080, 9090}
	command.Policy = resolvedPolicyForCommand(command, "SMALL_SINGLE")

	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatalf("multi-port TCP fallback rejected: %v", err)
	}
	probe := resources.Deployment.Spec.Template.Spec.Containers[0].ReadinessProbe
	if probe == nil || probe.TCPSocket == nil || probe.TCPSocket.Port.IntValue() != 8080 || probe.SuccessThreshold != 2 {
		t.Fatalf("TCP fallback = %#v, want first public port with two successes", probe)
	}

	command.Containers[0].ReadinessHTTP = &provisioner.HTTPReadiness{Path: "/healthz", Port: 9090}
	resources, err = BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatalf("explicit HTTP readiness with multiple public ports rejected: %v", err)
	}
	probe = resources.Deployment.Spec.Template.Spec.Containers[0].ReadinessProbe
	if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Port.IntValue() != 9090 || probe.HTTPGet.Path != "/healthz" {
		t.Fatalf("explicit HTTP healthcheck not preserved: %#v", probe)
	}
}

func TestBuildResourceSetMultiportTCPReadinessFollowsPublicPortOrder(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Containers[0].Ports = []int{9000, 8080, 9090}
	command.Policy = resolvedPolicyForCommand(command, "SMALL_SINGLE")
	command.Containers[0].Expose = false
	command.Containers[0].ExposedPorts = []int{9090, 8080}
	command.Policy.Containers[0].Expose = false
	command.Policy.Containers[0].ExposedPorts = []int{9090, 8080}

	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	probe := resources.Deployment.Spec.Template.Spec.Containers[0].ReadinessProbe
	if probe == nil || probe.TCPSocket == nil || probe.TCPSocket.Port.IntValue() != 9090 {
		t.Fatalf("TCP readiness = %#v, want first public port 9090 instead of private port 9000", probe)
	}
}
