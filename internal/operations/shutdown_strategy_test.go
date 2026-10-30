package operations

import (
	"encoding/json"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestLegacyCreateEqualityIncludesShutdownStrategy(t *testing.T) {
	command := provisioner.CreateWorkloadCommand{RequestID: "shutdown", Containers: []provisioner.WorkloadContainer{{Name: "web"}}}
	original, err := NewCreateOperation("original", command, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"ShutdownStrategy":"python_sigint_pid1"}`), &command.Containers[0]); err != nil {
		t.Fatal(err)
	}
	changed, err := NewCreateOperation("changed", command, 2)
	if err != nil {
		t.Fatal(err)
	}
	if original.SameRequest(changed) {
		t.Fatal("legacy operation reused an idempotency key for different shutdown behavior")
	}
}
