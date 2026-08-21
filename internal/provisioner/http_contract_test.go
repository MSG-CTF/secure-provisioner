package provisioner

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateRequestUsesSnakeCaseAndNumericTeamID(t *testing.T) {
	body := `{"request_id":"req-1","instance_id":"inst-1","team_id":101,"challenge_id":"web-1","cluster_id":"k3s-1","reservation_id":"rsv-1","created_by":"scheduler","expires_at":"2030-01-01T00:00:00Z"}`
	request := httptest.NewRequest("POST", "/internal/v1/instances", strings.NewReader(body))

	var decoded CreateRequest
	if err := decodeJSON(request, &decoded); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(decoded.TeamID) != "101" {
		t.Fatalf("team_id = %v, want 101", decoded.TeamID)
	}
	if decoded.RequestID != "req-1" || decoded.InstanceID != "inst-1" {
		t.Fatalf("decoded request IDs = %q/%q", decoded.RequestID, decoded.InstanceID)
	}
}

func TestCreateRequestRejectsCamelCase(t *testing.T) {
	body := `{"requestId":"req-1","instance_id":"inst-1","team_id":101,"challenge_id":"web-1","cluster_id":"k3s-1","reservation_id":"rsv-1","created_by":"scheduler","expires_at":"2030-01-01T00:00:00Z"}`
	request := httptest.NewRequest("POST", "/internal/v1/instances", strings.NewReader(body))

	var decoded CreateRequest
	if err := decodeJSON(request, &decoded); err == nil {
		t.Fatal("camelCase requestId must be rejected")
	}
}

func TestAcceptedOperationResponseUsesSnakeCase(t *testing.T) {
	payload, err := json.Marshal(AcceptedOperation{
		OperationID: "op-1",
		InstanceID:  "inst-1",
		Phase:       PhaseRequested,
		Duplicate:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(payload)
	for _, expected := range []string{`"operation_id"`, `"instance_id"`} {
		if !strings.Contains(jsonText, expected) {
			t.Fatalf("response %s does not contain %s", jsonText, expected)
		}
	}
	for _, forbidden := range []string{`"operationId"`, `"instanceId"`} {
		if strings.Contains(jsonText, forbidden) {
			t.Fatalf("response %s contains camelCase field %s", jsonText, forbidden)
		}
	}
}

func TestRuntimeEndpointUsesSnakeCase(t *testing.T) {
	payload, err := json.Marshal(RuntimeResources{NodePort: 31001})
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(payload)
	if !strings.Contains(jsonText, `"node_port"`) {
		t.Fatalf("response %s does not contain node_port", jsonText)
	}
	if strings.Contains(jsonText, `"nodePort"`) {
		t.Fatalf("response %s contains camelCase nodePort", jsonText)
	}
}
