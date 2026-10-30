package operations

import (
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
)

func TestOperationCopiesPublicPortsAndRejectsChangedSelection(t *testing.T) {
	command := validCreateCommand("mixed")
	command.Containers[0].Expose = false
	command.Containers[0].ExposedPorts = []int{8080}
	command.PolicyRequest.Containers = []isolation.ContainerRequirement{{Ports: []int{8080, 9000}, ExposedPorts: []int{8080}}}
	command.Policy.Containers = []isolation.ContainerRequirement{{Ports: []int{8080, 9000}, ExposedPorts: []int{8080}}}
	op, err := NewCreateOperation("op-1", command, 4)
	if err != nil {
		t.Fatal(err)
	}
	command.Containers[0].ExposedPorts[0] = 9000
	command.PolicyRequest.Containers[0].ExposedPorts[0] = 9000
	command.Policy.Containers[0].ExposedPorts[0] = 9000
	if op.CreateCommand.Containers[0].ExposedPorts[0] != 8080 || op.CreateCommand.PolicyRequest.Containers[0].ExposedPorts[0] != 8080 || op.CreateCommand.Policy.Containers[0].ExposedPorts[0] != 8080 {
		t.Fatal("operation exposure changed through caller slices")
	}
	changed, err := NewCreateOperation("op-2", *op.CreateCommand, 4)
	if err != nil {
		t.Fatal(err)
	}
	changed.CreateCommand.Containers[0].ExposedPorts = []int{9000}
	if op.SameRequest(changed) {
		t.Fatal("different public selection treated as identical request")
	}
}
