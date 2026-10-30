package operations

import (
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"testing"
)

func TestCreateTracingIsImmutableInLegacyCommandReplay(t *testing.T) {
	original := provisioner.CreateWorkloadCommand{RequestID: "legacy", InstanceID: "instance", TargetID: "target"}
	changed := original
	changed.Architecture = "AMD64"
	if sameCreateCommand(original, changed) {
		t.Fatal("legacy replay gained architecture")
	}
	changed = original
	changed.ReleaseID = "11111111-1111-4111-8111-111111111111"
	if sameCreateCommand(original, changed) {
		t.Fatal("legacy replay gained release")
	}
}
