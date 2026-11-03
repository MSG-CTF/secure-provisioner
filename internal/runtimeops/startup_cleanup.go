package runtimeops

import (
	"errors"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

// A failed startup can exhaust cleanup retries before it records a ready
// binding. Keep exposing its exact cleanup identity, never an access endpoint.
// The DELETE path must still verify namespace UID and actual resource absence.
type instanceCreateLookup interface {
	GetCreateByInstance(string) (operations.Operation, error)
}

func (s *Service) failedStartupBinding(instanceID string) (runtimebinding.Binding, error) {
	lookup, ok := s.operations.(instanceCreateLookup)
	if !ok {
		return runtimebinding.Binding{}, runtimebinding.ErrNotFound
	}
	op, err := lookup.GetCreateByInstance(instanceID)
	if errors.Is(err, operations.ErrOperationNotFound) {
		return runtimebinding.Binding{}, runtimebinding.ErrNotFound
	}
	if err != nil {
		return runtimebinding.Binding{}, err
	}
	c := op.CreateCommand
	cleanup := op.Result.CreateCleanup
	if op.Type != operations.OperationTypeCreate || op.Status != operations.OperationStatusFailed ||
		c == nil || c.InstanceID != instanceID || c.SteadyCPUMillicores <= 0 ||
		c.SteadyCPUMillicores >= c.ResourceLimits.CPUMillicores || len(c.Containers) != 1 ||
		c.PolicyRequest.WorkloadProfile != isolation.WorkloadProfileWeb ||
		c.RuntimeType != provisioner.RuntimeTypeKubernetes || cleanup == nil ||
		strings.TrimSpace(cleanup.NamespaceUID) == "" || cleanup.RuntimeWorkloadID != "" ||
		op.CreateCheckpoint != nil || op.Result.Create != nil {
		return runtimebinding.Binding{}, runtimebinding.ErrNotFound
	}
	namespace, err := k3s.NamespaceForInstance(instanceID)
	if err != nil {
		return runtimebinding.Binding{}, err
	}
	result := provisioner.CreateWorkloadResult{
		NamespaceUID:      cleanup.NamespaceUID,
		RuntimeWorkloadID: k3s.RuntimeWorkloadID(c.TargetID, namespace),
	}
	return createdBinding(*c, result, namespace, s.now().UTC()), nil
}
