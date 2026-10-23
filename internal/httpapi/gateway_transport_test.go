package httpapi

import (
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"testing"
)

func TestGatewayTransportAndCleanupProofSurviveDTO(t *testing.T) {
	ep := newWorkloadEndpointResponse(provisioner.WorkloadEndpoint{ContainerName: "pwn", Port: 31337, Protocol: "TCP", ServiceURL: "tls://abc.gate.msgctf.kr:443", Hostname: "abc.gate.msgctf.kr", ConnectionPort: 443, TLS: true, ServerName: "abc.gate.msgctf.kr"})
	if ep.Port != 31337 || !ep.TLS || ep.Hostname != ep.ServerName || ep.ConnectionPort != 443 {
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
