package runtimepg

import (
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestOperationCodecRoundTripsResolvedCreateCommand(t *testing.T) {
	command := validResolvedPwnCommand(t)
	want, err := operations.NewCreateOperation("op-1", command, 4)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeOperationCommand(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeOperationCommand(want.Type, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !want.SameRequest(got) {
		t.Fatalf("round trip mismatch\nwant=%#v\ngot=%#v", want, got)
	}
}

func TestOperationCodecRejectsMalformedJSONAndUnknownType(t *testing.T) {
	if _, err := decodeOperationCommand(operations.OperationTypeCreate, []byte("{")); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	if _, err := decodeOperationCommand(operations.OperationType("REPLACE"), []byte(`{}`)); err == nil {
		t.Fatal("unknown operation type accepted")
	}
}

func validResolvedPwnCommand(t *testing.T) provisioner.CreateWorkloadCommand {
	t.Helper()
	request := isolation.Request{
		WorkloadProfile: isolation.WorkloadProfilePwn,
		Containers:      []isolation.ContainerRequirement{{Name: "challenge", Ports: []int{31337}, Expose: true, RunAsUser: 10001}},
		ResourceLimits:  isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
	}
	policy, err := isolation.NewStaticResolver().Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	return provisioner.CreateWorkloadCommand{
		RequestID: "request-1", InstanceID: "11111111-1111-4111-8111-111111111111",
		TeamID: "00000000-0000-4000-8000-000000000001", RuntimeType: provisioner.RuntimeTypeKubernetes, TargetID: "aws-k3s-001",
		Containers: []provisioner.WorkloadContainer{{
			Name: "challenge", Image: "ghcr.io/msg-ctf/pwn@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ports: []int{31337}, Expose: true,
		}},
		PolicyRequest: request, Policy: policy,
		ResourceLimits: provisioner.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
	}
}
