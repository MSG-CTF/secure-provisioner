package k3s

import (
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"testing"
)

func graceCommand(seconds int64) provisioner.CreateWorkloadCommand {
	c := validCreateCommand("aws-dev")
	c.Containers[0].TerminationGracePeriodSeconds = seconds
	c.Policy.Containers[0].TerminationGracePeriodSeconds = seconds
	c.PolicyRequest.Containers = append([]isolation.ContainerRequirement(nil), c.Policy.Containers...)
	return c
}
func TestReviewedGraceRendersPodAndChangesResourceIdentity(t *testing.T) {
	legacy, err := BuildResourceSet(validCluster("aws-dev"), validCreateCommand("aws-dev"))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := BuildResourceSet(validCluster("aws-dev"), graceCommand(5))
	if err != nil {
		t.Fatal(err)
	}
	got := resources.Deployment.Spec.Template.Spec.TerminationGracePeriodSeconds
	if got == nil || *got != 5 {
		t.Fatalf("reviewed grace not rendered: %v", got)
	}
	if resources.ExpectedSpecHash == legacy.ExpectedSpecHash {
		t.Fatal("grace not included in resource identity")
	}
	if legacy.Deployment.Spec.Template.Spec.TerminationGracePeriodSeconds != nil {
		t.Fatal("legacy/DB default changed")
	}
}
func TestGraceCannotBypassRequestedOrResolvedApproval(t *testing.T) {
	for _, mutate := range []func(*provisioner.CreateWorkloadCommand){
		func(c *provisioner.CreateWorkloadCommand) { c.Containers[0].TerminationGracePeriodSeconds = 1 },
		func(c *provisioner.CreateWorkloadCommand) { c.Policy.Containers[0].TerminationGracePeriodSeconds = 0 },
		func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.Containers[0].TerminationGracePeriodSeconds = 0
		},
		func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.Containers = append(c.PolicyRequest.Containers, isolation.ContainerRequirement{Name: "unmatched", TerminationGracePeriodSeconds: 5})
		},
		func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.Containers[0].TerminationGracePeriodSeconds = -1
		},
	} {
		c := graceCommand(5)
		mutate(&c)
		if _, err := BuildResourceSet(validCluster("aws-dev"), c); err == nil {
			t.Fatal("unapproved grace was rendered")
		}
	}
	for _, seconds := range []int64{-1, 301} {
		if _, err := BuildResourceSet(validCluster("aws-dev"), graceCommand(seconds)); err == nil {
			t.Fatalf("unsafe grace accepted: %d", seconds)
		}
	}
}
