package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func TestCleanupProofIsOnlyExposedForTerminalCreateFailure(t *testing.T) {
	for _, kind := range []operations.OperationType{operations.OperationTypeCreate, operations.OperationTypeDelete} {
		for _, state := range []operations.OperationStatus{operations.OperationStatusRunning, operations.OperationStatusRetrying, operations.OperationStatusSucceeded, operations.OperationStatusFailed} {
			response := newOperationResponse(operations.Operation{Type: kind, Status: state, Result: operations.OperationResult{CreateCleanupCompleted: true}})
			body, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			_, exists := decoded["cleanup_completed"]
			if want := kind == operations.OperationTypeCreate && state == operations.OperationStatusFailed; exists != want {
				t.Fatalf("%s %s: proof=%v", kind, state, exists)
			}
		}
	}
}
