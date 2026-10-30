package httpapi

import (
	"encoding/json"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"testing"
)

func TestEndpointJSONPreservesExplicitTransportAndLegacyOmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint provisioner.WorkloadEndpoint
		wantTLS  string
	}{
		{"plaintext", provisioner.WorkloadEndpoint{ContainerName: "pwn", Port: 1337, Protocol: "TCP", ServiceURL: "tcp://abc.gate.msgctf.kr:42817", Hostname: "abc.gate.msgctf.kr", ConnectionPort: 42817}, "false"},
		{"encrypted", provisioner.WorkloadEndpoint{ContainerName: "pwn", Port: 1337, Protocol: "TCP", ServiceURL: "tls://abc.gate.msgctf.kr:443", Hostname: "abc.gate.msgctf.kr", ConnectionPort: 443, TLS: true, ServerName: "abc.gate.msgctf.kr"}, "true"},
		{"legacy", provisioner.WorkloadEndpoint{ContainerName: "pwn", Port: 1337, Protocol: "TCP", ServiceURL: "tcp://old.example:31042"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(newWorkloadEndpointResponse(tc.endpoint))
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			if string(body["tls"]) != tc.wantTLS || string(body["port"]) != "1337" {
				t.Fatalf("unexpected endpoint JSON: %s", raw)
			}
			if tc.name == "plaintext" && (string(body["connection_port"]) != "42817" || body["server_name"] != nil) {
				t.Fatalf("plaintext transport lost or SNI leaked: %s", raw)
			}
			if tc.name == "legacy" && (body["hostname"] != nil || body["connection_port"] != nil || body["server_name"] != nil) {
				t.Fatalf("legacy endpoint acquired transport metadata: %s", raw)
			}
		})
	}
}

func TestGatewayTransportAndCleanupProofSurviveDTO(t *testing.T) {
	ep := newWorkloadEndpointResponse(provisioner.WorkloadEndpoint{ContainerName: "pwn", Port: 31337, Protocol: "TCP", ServiceURL: "tls://abc.gate.msgctf.kr:443", Hostname: "abc.gate.msgctf.kr", ConnectionPort: 443, TLS: true, ServerName: "abc.gate.msgctf.kr"})
	if ep.Port != 31337 || ep.TLS == nil || !*ep.TLS || ep.Hostname != ep.ServerName || ep.ConnectionPort != 443 {
		t.Fatal(ep)
	}
	if !newRuntimeStatusResponse(k3s.RuntimeStatus{CleanupPending: true}).CleanupPending {
		t.Fatal("lost pending state")
	}
	failed := newOperationResponse(operations.Operation{Type: operations.OperationTypeDelete, Status: operations.OperationStatusFailed})
	succeeded := newOperationResponse(operations.Operation{Type: operations.OperationTypeDelete, Status: operations.OperationStatusSucceeded, Result: operations.OperationResult{DeleteCompleted: true}})
	if failed.CleanupCompleted || !succeeded.CleanupCompleted {
		t.Fatal(failed, succeeded)
	}
}
