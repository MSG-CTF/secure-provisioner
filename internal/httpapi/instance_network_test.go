package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCreateRejectsRemovedInternalConnections(t *testing.T) {
	for _, value := range []string{"null", "[]", `[{"source_container":"web","destination_container":"api","protocol":"TCP","port":9000}]`} {
		t.Run(value, func(t *testing.T) {
			var body map[string]any
			if err := json.Unmarshal([]byte(validCreateRequestJSON()), &body); err != nil {
				t.Fatal(err)
			}
			body["workload"].(map[string]any)["internal_connections"] = json.RawMessage(value)
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			var request CreateWorkloadRequest
			err = json.Unmarshal(encoded, &request)
			if err == nil || !strings.Contains(err.Error(), "internal_connections") {
				t.Fatalf("removed field must be rejected, got %v", err)
			}
		})
	}
}
