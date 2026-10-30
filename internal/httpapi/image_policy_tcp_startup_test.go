package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func tcpStartupPolicy(t *testing.T, override map[string]any) string {
	t.Helper()
	var data map[string]any
	if err := json.Unmarshal([]byte(testImagePolicies), &data); err != nil {
		t.Fatal(err)
	}
	policy := data["images"].([]any)[0].(map[string]any)
	policy["isolation_profile"] = "PWN"
	policy["writable_paths"] = []any{map[string]any{"path": "/tmp", "size_mib": 32}}
	policy["tcp_startup_only"] = true
	for name, value := range override {
		policy[name] = value
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func startupRequest() CreateWorkloadRequest {
	request := validCreateWorkloadRequest()
	request.IsolationProfile = "PWN"
	request.Workload.Containers = []RuntimeContainer{{
		Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true,
	}}
	return request
}

func TestImagePolicyCarriesReviewedTCPStartupIntoDurableCommand(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(tcpStartupPolicy(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	request := startupRequest()
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(request.ToCommand())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"TCPStartupOnly":true`) {
		t.Fatal("approved startup behavior is missing from the durable command")
	}
}

func TestImagePolicyTCPStartupRejectsConflictingProfileOrHTTPCheck(t *testing.T) {
	for _, override := range []map[string]any{
		{"isolation_profile": "WEB"},
		{"readiness_http": map[string]any{"path": "/", "port": 8080}},
	} {
		if _, err := ParseImagePolicies([]byte(tcpStartupPolicy(t, override))); err == nil {
			t.Fatal("conflicting startup policy was accepted")
		}
	}
}

func TestImagePolicyTCPStartupCannotBeOverriddenByRequestedHTTPCheck(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(tcpStartupPolicy(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	request := startupRequest()
	request.Workload.Healthcheck = &RuntimeHealthcheck{Container: "web", Port: 8080, Path: "/"}
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err == nil {
		t.Fatal("caller replaced a reviewed TCP-only check with continuous HTTP traffic")
	}
}

func TestCallerCannotSelectTCPStartupPolicy(t *testing.T) {
	for _, field := range []string{"tcp_startup_only", "TCPStartupOnly"} {
		var container RuntimeContainer
		if err := json.Unmarshal([]byte(`{"name":"web","`+field+`":true}`), &container); err == nil {
			t.Fatalf("caller-selected %s was accepted", field)
		}
	}
}
