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

func TestBuildResourceSetRequiresExplicitReadinessForMultiplePublicPorts(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Containers[0].Ports = []int{8080, 9090}
	command.Policy = resolvedPolicyForCommand(command, "SMALL_SINGLE")

	if _, err := BuildResourceSet(validCluster("aws-dev"), command); runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
		t.Fatalf("without explicit readiness, error = %v, want INVALID_CREATE_COMMAND", err)
	}

	command.Containers[0].ReadinessHTTP = &provisioner.HTTPReadiness{Path: "/healthz", Port: 8080}
	if _, err := BuildResourceSet(validCluster("aws-dev"), command); err != nil {
		t.Fatalf("explicit HTTP readiness with multiple public ports rejected: %v", err)
	}
}
