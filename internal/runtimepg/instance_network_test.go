package runtimepg

import (
	"bytes"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func TestNewOperationSnapshotOmitsInternalConnections(t *testing.T) {
	op, err := operations.NewCreateOperation("op-instance", validResolvedPwnCommand(t), 3)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeOperationCommand(op)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(encoded), []byte("internalconnections")) {
		t.Fatal("new snapshots must not store retired connection fields")
	}
	decoded, err := decodeOperationCommand(operations.OperationTypeCreate, encoded)
	if err != nil || !op.SameRequest(decoded) {
		t.Fatal("instance policy must preserve request identity after persistence")
	}
}

func TestLegacyOperationSnapshotRetainsApprovedNetworkGraph(t *testing.T) {
	command := validResolvedPwnCommand(t)
	command.Policy.IsolationRef.Version = "v1"
	command.Policy.InternalConnections = []isolation.InternalConnection{{
		SourceContainer: "challenge", DestinationContainer: "challenge", Protocol: isolation.ProtocolTCP, Port: 31337,
	}}
	command.PolicyRequest.InternalConnections = command.Policy.InternalConnections
	op, err := operations.NewCreateOperation("op-legacy", command, 3)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeOperationCommand(op)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeOperationCommand(operations.OperationTypeCreate, payload)
	if err != nil || !op.SameRequest(decoded) {
		t.Fatal("legacy snapshot must retain approved policy and idempotency")
	}
	if decoded.CreateCommand.Policy.IsolationRef.Version != "v1" || len(decoded.CreateCommand.Policy.InternalConnections) != 1 {
		t.Fatal("legacy network policy was upgraded or lost")
	}
}
