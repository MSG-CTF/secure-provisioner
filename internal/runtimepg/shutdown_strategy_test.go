package runtimepg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func TestOperationCodecRetainsReviewedShutdownWithFingerprint(t *testing.T) {
	command := validResolvedPwnCommand(t)
	command.PolicyRequest.WorkloadProfile = isolation.WorkloadProfileWeb
	var err error
	command.Policy, err = isolation.NewStaticResolver().Resolve(command.PolicyRequest)
	if err != nil {
		t.Fatal(err)
	}
	command.RequestFingerprint = "accepted-input"
	for _, destination := range []any{&command.Containers[0], &command.PolicyRequest.Containers[0], &command.Policy.Containers[0]} {
		if err := json.Unmarshal([]byte(`{"ShutdownStrategy":"python_sigint_pid1"}`), destination); err != nil {
			t.Fatal(err)
		}
	}
	operation, err := operations.NewCreateOperation("shutdown", command, 2)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeOperationCommand(operation)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeOperationCommand(operation.Type, payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(decoded.CreateCommand)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(encoded), `"ShutdownStrategy":"python_sigint_pid1"`) != 3 {
		t.Fatal("operation codec lost immutable reviewed shutdown settings")
	}
}
