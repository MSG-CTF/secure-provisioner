package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCreateTracingPreservesOmissionAndRejectsNull(t *testing.T) {
	for _, raw := range []string{`{"release_id":null}`, `{"architecture":null}`, `{"architecture":"arm64"}`, `{"release_id":"bad"}`} {
		var request CreateWorkloadRequest
		if json.Unmarshal([]byte(raw), &request) == nil {
			t.Fatalf("invalid tracing accepted: %s", raw)
		}
	}
	var request CreateWorkloadRequest
	if err := json.Unmarshal([]byte(`{"release_id":"11111111-1111-4111-8111-111111111111","architecture":"ARM64"}`), &request); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	if command.ReleaseID != request.ReleaseID || command.Architecture != "ARM64" {
		t.Fatal("trace lost")
	}
	b, _ := json.Marshal(CreateWorkloadRequest{})
	if strings.Contains(string(b), "release_id") || strings.Contains(string(b), "architecture") {
		t.Fatal("legacy payload gained tracing fields")
	}
}
