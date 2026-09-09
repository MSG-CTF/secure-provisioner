package runtimeops

import (
	"errors"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestCreateRetryAcrossPolicyUpgradeReturnsOriginalOperation(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "original-operation", nil })
	oldPolicy := validResolvedPolicy()
	oldPolicy.IsolationRef.Version = "v1"
	oldService := newTestServiceWithResolver(t, &recordingResolver{resolved: oldPolicy}, store)
	original, _, err := oldService.EnqueueCreate(createCommand())
	if err != nil {
		t.Fatal(err)
	}
	resolver := &recordingResolver{resolved: validResolvedPolicy()}
	newService := newTestServiceWithResolver(t, resolver, store)
	replayed, created, err := newService.EnqueueCreate(createCommand())
	if err != nil || created || replayed.ID != original.ID {
		t.Fatalf("retry must recover original operation: created=%v, error=%v", created, err)
	}
	if replayed.CreateCommand.Policy.IsolationRef.Version != "v1" || resolver.calls != 0 {
		t.Fatal("retry must not reinterpret its previously approved policy")
	}
}

func TestCreateRetryAcrossPolicyUpgradeStillRejectsChangedInput(t *testing.T) {
	for name, mutate := range map[string]func(*provisioner.CreateWorkloadCommand){
		"team":   func(c *provisioner.CreateWorkloadCommand) { c.TeamID = "00000000-0000-4000-8000-000000000099" },
		"target": func(c *provisioner.CreateWorkloadCommand) { c.TargetID = "other-target" },
		"image":  func(c *provisioner.CreateWorkloadCommand) { c.Containers[0].Image = "other-image" },
		"limits": func(c *provisioner.CreateWorkloadCommand) { c.PolicyRequest.ResourceLimits.MemoryMiB++ },
		"profile": func(c *provisioner.CreateWorkloadCommand) {
			c.PolicyRequest.WorkloadProfile = isolation.WorkloadProfilePwn
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := operations.NewMemoryStore(func() (string, error) { return "original-operation", nil })
			oldPolicy := validResolvedPolicy()
			oldPolicy.IsolationRef.Version = "v1"
			oldService := newTestServiceWithResolver(t, &recordingResolver{resolved: oldPolicy}, store)
			if _, _, err := oldService.EnqueueCreate(createCommand()); err != nil {
				t.Fatal(err)
			}
			newService := newTestServiceWithResolver(t, &recordingResolver{resolved: validResolvedPolicy()}, store)
			command := createCommand()
			mutate(&command)
			if _, _, err := newService.EnqueueCreate(command); !errors.Is(err, operations.ErrIdempotencyConflict) {
				t.Fatalf("changed request must conflict: %v", err)
			}
		})
	}
}
