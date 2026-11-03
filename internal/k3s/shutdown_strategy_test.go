package k3s

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func setShutdownJSON(t *testing.T, value string, destination any) {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{"ShutdownStrategy": value})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, destination); err != nil {
		t.Fatal(err)
	}
}

func shutdownCommand(t *testing.T, strategy string) provisioner.CreateWorkloadCommand {
	t.Helper()
	command := validCreateCommand("aws-dev")
	command.PolicyRequest.WorkloadProfile = isolation.WorkloadProfileWeb
	command.PolicyRequest.Containers = append([]isolation.ContainerRequirement(nil), command.Policy.Containers...)
	setShutdownJSON(t, strategy, &command.Containers[0])
	setShutdownJSON(t, strategy, &command.PolicyRequest.Containers[0])
	setShutdownJSON(t, strategy, &command.Policy.Containers[0])
	return command
}

func TestReviewedShutdownRendersFixedHookAndPreservesBaseline(t *testing.T) {
	legacy, err := BuildResourceSet(validCluster("aws-dev"), validCreateCommand("aws-dev"))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := BuildResourceSet(validCluster("aws-dev"), shutdownCommand(t, "python_sigint_pid1"))
	if err != nil {
		t.Fatal(err)
	}
	got := resources.Deployment.Spec.Template.Spec.Containers[0]
	if got.Lifecycle == nil || got.Lifecycle.PreStop == nil || got.Lifecycle.PreStop.Exec == nil {
		t.Fatal("reviewed shutdown is missing its fixed preStop exec")
	}
	want := []string{"/usr/local/bin/python3", "-I", "-B", "-c", "import os, signal; os.kill(1, signal.SIGINT)"}
	if !reflect.DeepEqual(got.Lifecycle.PreStop.Exec.Command, want) || got.Lifecycle.PostStart != nil || got.Lifecycle.StopSignal != nil {
		t.Fatalf("shutdown lifecycle = %#v, want only the approved preStop exec", got.Lifecycle)
	}
	if resources.ExpectedSpecHash == legacy.ExpectedSpecHash {
		t.Fatal("shutdown behavior did not change the persisted resource identity")
	}
	if legacy.Deployment.Spec.Template.Spec.Containers[0].Lifecycle != nil {
		t.Fatal("legacy image gained a lifecycle hook")
	}
	// All other rendering, including image command/args and isolation, must match.
	approvedPod := resources.Deployment.Spec.Template.Spec.DeepCopy()
	approvedPod.Containers[0].Lifecycle = nil
	if !reflect.DeepEqual(*approvedPod, legacy.Deployment.Spec.Template.Spec) {
		t.Fatal("shutdown strategy changed other pod execution or security settings")
	}
}

func TestShutdownRejectsInvalidOrUnapprovedDurableRequirements(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*provisioner.CreateWorkloadCommand)
	}{
		{"unsupported enum", func(c *provisioner.CreateWorkloadCommand) {
			setShutdownJSON(t, "arbitrary_exec", &c.Containers[0])
			setShutdownJSON(t, "arbitrary_exec", &c.PolicyRequest.Containers[0])
			setShutdownJSON(t, "arbitrary_exec", &c.Policy.Containers[0])
		}},
		{"missing resolved approval", func(c *provisioner.CreateWorkloadCommand) { setShutdownJSON(t, "", &c.Policy.Containers[0]) }},
		{"missing requested approval", func(c *provisioner.CreateWorkloadCommand) { setShutdownJSON(t, "", &c.PolicyRequest.Containers[0]) }},
		{"command differs from approval", func(c *provisioner.CreateWorkloadCommand) { setShutdownJSON(t, "", &c.Containers[0]) }},
		{"PWN profile", func(c *provisioner.CreateWorkloadCommand) {
			*c = validPwnCreateCommand("aws-dev")
			c.PolicyRequest.WorkloadProfile = isolation.WorkloadProfilePwn
			c.PolicyRequest.Containers = append([]isolation.ContainerRequirement(nil), c.Policy.Containers...)
			setShutdownJSON(t, "python_sigint_pid1", &c.Containers[0])
			setShutdownJSON(t, "python_sigint_pid1", &c.PolicyRequest.Containers[0])
			setShutdownJSON(t, "python_sigint_pid1", &c.Policy.Containers[0])
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := shutdownCommand(t, "python_sigint_pid1")
			test.mutate(&command)
			if _, err := BuildResourceSet(nodePortGVisorCluster("aws-dev"), command); err == nil {
				t.Fatal("invalid or unapproved shutdown command was rendered")
			}
		})
	}
}

func TestDeploymentReadbackRejectsShutdownLifecycleDrift(t *testing.T) {
	resources, err := BuildResourceSet(validCluster("aws-dev"), shutdownCommand(t, "python_sigint_pid1"))
	if err != nil {
		t.Fatal(err)
	}
	desired := resources.Deployment
	if desired.Spec.Template.Spec.Containers[0].Lifecycle == nil {
		t.Fatal("reviewed shutdown is missing before drift verification")
	}
	missing := desired.DeepCopy()
	missing.Spec.Template.Spec.Containers[0].Lifecycle = nil
	if sameDeploymentSpec(missing, desired) {
		t.Fatal("deployment verification accepted a removed shutdown hook")
	}
	changed := desired.DeepCopy()
	changed.Spec.Template.Spec.Containers[0].Lifecycle.PreStop.Exec.Command[4] = "import os; os._exit(0)"
	if sameDeploymentSpec(changed, desired) {
		t.Fatal("deployment verification accepted a replaced shutdown program")
	}
}

func TestShutdownRejectsUnmatchedOrDuplicateRequestedEntries(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*provisioner.CreateWorkloadCommand)
	}{
		{"unknown extra strategy", func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.Containers = append(c.PolicyRequest.Containers, isolation.ContainerRequirement{
				Name: "unused", ShutdownStrategy: "arbitrary_exec",
			})
		}},
		{"reviewed strategy on unmatched name", func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.Containers = append(c.PolicyRequest.Containers, isolation.ContainerRequirement{
				Name: "unused", ShutdownStrategy: isolation.ShutdownStrategyPythonSIGINTPID1,
			})
		}},
		{"duplicate reviewed name", func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.Containers = append(c.PolicyRequest.Containers, c.PolicyRequest.Containers[0])
		}},
		{"duplicate empty requested names", func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.Containers = append(c.PolicyRequest.Containers,
				isolation.ContainerRequirement{Name: "unused"}, isolation.ContainerRequirement{Name: "unused"})
		}},
		{"unknown duplicate overwritten by valid strategy", func(c *provisioner.CreateWorkloadCommand) {
			invalid := c.PolicyRequest.Containers[0]
			invalid.ShutdownStrategy = "arbitrary_exec"
			c.PolicyRequest.Containers = append([]isolation.ContainerRequirement{invalid}, c.PolicyRequest.Containers...)
		}},
		{"extra strategy on PWN profile", func(c *provisioner.CreateWorkloadCommand) {
			*c = validPwnCreateCommand("aws-dev")
			c.PolicyRequest.WorkloadProfile = isolation.WorkloadProfilePwn
			c.PolicyRequest.Containers = []isolation.ContainerRequirement{{
				Name: "unused", ShutdownStrategy: isolation.ShutdownStrategyPythonSIGINTPID1,
			}}
		}},
		{"requested PWN profile with resolved WEB strategy", func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.WorkloadProfile = isolation.WorkloadProfilePwn
		}},
		{"omitted requested profile with strategy", func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.WorkloadProfile = ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := shutdownCommand(t, "python_sigint_pid1")
			test.mutate(&command)
			if _, err := BuildResourceSet(nodePortGVisorCluster("aws-dev"), command); err == nil {
				t.Fatal("malformed requested shutdown entry bypassed durable validation")
			}
		})
	}
}

func TestShutdownKeepsLegacyEmptyRequestedSettingsCompatible(t *testing.T) {
	for _, test := range []struct {
		name    string
		command provisioner.CreateWorkloadCommand
	}{
		{"omitted legacy requirements", validCreateCommand("aws-dev")},
		{"unmatched empty strategy", func() provisioner.CreateWorkloadCommand {
			command := shutdownCommand(t, "python_sigint_pid1")
			command.PolicyRequest.Containers = append(command.PolicyRequest.Containers, isolation.ContainerRequirement{Name: "unused"})
			return command
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildResourceSet(validCluster("aws-dev"), test.command); err != nil {
				t.Fatalf("empty requested shutdown setting broke legacy compatibility: %v", err)
			}
		})
	}
}
