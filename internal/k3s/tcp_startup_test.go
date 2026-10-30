package k3s

import (
	"encoding/json"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestReviewedTCPStartupChecksOnceAndChangesTheSpecHash(t *testing.T) {
	cluster := nodePortGVisorCluster("aws-dev")
	command := validPwnCreateCommand("aws-dev")
	legacy, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	// Use the persisted command representation, also exercised by queue restarts.
	if err := json.Unmarshal([]byte(`{"TCPStartupOnly":true}`), &command.Containers[0]); err != nil {
		t.Fatal(err)
	}
	resources, err := BuildResourceSet(cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	container := resources.Deployment.Spec.Template.Spec.Containers[0]
	probe := container.StartupProbe
	if probe == nil || probe.TCPSocket == nil || probe.TCPSocket.Port.IntValue() != 31337 ||
		probe.SuccessThreshold != 1 || probe.FailureThreshold != 30 || probe.TimeoutSeconds != 1 {
		t.Fatalf("startup probe = %#v, want a bounded one-time TCP check", probe)
	}
	if container.ReadinessProbe != nil || container.LivenessProbe != nil {
		t.Fatal("interactive TCP service still receives continuous probe connections")
	}
	if resources.ExpectedSpecHash == legacy.ExpectedSpecHash {
		t.Fatal("changing probe behavior must change the persisted resource identity")
	}
}

func TestTCPStartupRejectsHTTPChecksAndNonTCPProfiles(t *testing.T) {
	for _, name := range []string{"HTTP check", "WEB profile"} {
		t.Run(name, func(t *testing.T) {
			command := validPwnCreateCommand("aws-dev")
			if name == "WEB profile" {
				command = validCreateCommand("aws-dev")
			} else {
				command.Containers[0].ReadinessHTTP = &provisioner.HTTPReadiness{Path: "/", Port: 31337}
			}
			if err := json.Unmarshal([]byte(`{"TCPStartupOnly":true}`), &command.Containers[0]); err != nil {
				t.Fatal(err)
			}
			if _, err := BuildResourceSet(nodePortGVisorCluster("aws-dev"), command); err == nil {
				t.Fatal("conflicting or non-TCP startup policy was accepted")
			}
		})
	}
}
