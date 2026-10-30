package gateway

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

type Routes interface {
	Put(context.Context, string, Destination) (Route, error)
	Delete(context.Context, string) error
}
type Backend interface {
	Enabled(string) bool
	CreateWorkloadForOperation(context.Context, provisioner.CreateWorkloadCommand, string) (provisioner.CreateWorkloadResult, error)
	DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error
	CleanupFailedCreate(context.Context, provisioner.CreateWorkloadCommand, provisioner.CreateCleanup) error
	Destination(context.Context, provisioner.CreateWorkloadCommand, provisioner.CreateWorkloadResult) (Destination, string, error)
	Verify(context.Context, Record) error
	VerifyPortClaim(context.Context, Record) error
	Quiesce(context.Context, Record) error
}
type Adapter struct {
	backend Backend
	remote  Routes
	journal Journal
}

func NewAdapter(backend Backend, remote Routes, journal Journal) *Adapter {
	return &Adapter{backend, remote, journal}
}

func (a *Adapter) ValidateCreateCommand(c provisioner.CreateWorkloadCommand) error {
	if validator, ok := a.backend.(interface {
		ValidateCreateCommand(provisioner.CreateWorkloadCommand) error
	}); ok {
		if err := validator.ValidateCreateCommand(c); err != nil {
			return err
		}
	}
	if !a.backend.Enabled(c.TargetID) || c.RuntimeType != provisioner.RuntimeTypeKubernetes {
		return nil
	}
	count := 0
	for _, container := range c.Containers {
		count += len(container.PublicPorts())
	}
	if count != 1 {
		return operations.NewExecutionError("GATEWAY_SINGLE_ENDPOINT_REQUIRED", false, nil)
	}
	return nil
}
func (a *Adapter) CreateWorkload(ctx context.Context, c provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	return a.CreateWorkloadForOperation(ctx, c, "")
}
func (a *Adapter) CreateWorkloadForOperation(ctx context.Context, c provisioner.CreateWorkloadCommand, op string) (result provisioner.CreateWorkloadResult, err error) {
	if c, err = a.bindPublicOrigin(ctx, c); err != nil {
		return result, err
	}
	_, lookupErr := a.journal.Get(ctx, c.InstanceID)
	if errors.Is(lookupErr, ErrNotFound) && !a.backend.Enabled(c.TargetID) {
		return a.backend.CreateWorkloadForOperation(ctx, c, op)
	}
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return result, hold("GATEWAY_JOURNAL_UNAVAILABLE", lookupErr)
	}
	if err = a.ValidateCreateCommand(c); err != nil {
		return result, err
	}
	callbackRan := false
	err = a.journal.WithLock(ctx, c.InstanceID, func(s Session) error {
		callbackRan = true
		record, loadErr := s.Load()
		if errors.Is(loadErr, ErrNotFound) {
			unsafe, checkErr := a.journal.HasPendingCleanup(ctx, c.TargetID)
			if checkErr != nil || unsafe {
				return hold("GATEWAY_TARGET_CLEANUP_PENDING", checkErr)
			}
			raw, createErr := a.backend.CreateWorkloadForOperation(ctx, c, op)
			if createErr != nil {
				return createErr
			}
			dest, uid, destErr := a.backend.Destination(ctx, c, raw)
			if destErr != nil {
				return provisioner.WithCreateCleanupPending(operations.NewExecutionError("GATEWAY_UPSTREAM_INVALID", true, destErr), provisioner.CreateCleanup{RuntimeWorkloadID: raw.RuntimeWorkloadID, NamespaceUID: raw.NamespaceUID, FailureCode: "GATEWAY_UPSTREAM_INVALID"})
			}
			record = Record{Command: c, Result: raw, OperationID: op, Destination: dest, ServiceUID: uid, Phase: PhaseApplyPending, CreatedAt: time.Now().UTC()}
			if saveErr := s.Save(record); saveErr != nil {
				return provisioner.WithCreateCleanupPending(hold("GATEWAY_JOURNAL_UNAVAILABLE", saveErr), provisioner.CreateCleanup{RuntimeWorkloadID: raw.RuntimeWorkloadID, NamespaceUID: raw.NamespaceUID, FailureCode: "GATEWAY_JOURNAL_UNAVAILABLE"})
			}
		} else if loadErr != nil {
			return hold("GATEWAY_JOURNAL_UNAVAILABLE", loadErr)
		}
		if !reflect.DeepEqual(record.Command, c) || record.OperationID != op {
			return operations.NewExecutionError("GATEWAY_INTENT_CONFLICT", false, nil)
		}
		if record.Phase == PhaseConflictHold || record.Phase == PhaseDeletePending || record.Phase == PhaseRouteDeleted {
			return provisioner.WithCreateCleanupPending(hold("GATEWAY_CLEANUP_PENDING", nil), provisioner.CreateCleanup{RuntimeWorkloadID: record.Result.RuntimeWorkloadID, NamespaceUID: record.Result.NamespaceUID, FailureCode: "GATEWAY_CLEANUP_PENDING"})
		}
		if record.Phase != PhaseApplyPending && record.Phase != PhaseApplied {
			return operations.NewExecutionError("GATEWAY_INSTANCE_DELETED", false, nil)
		}
		if verifyErr := a.backend.Verify(ctx, record); verifyErr != nil {
			if errors.Is(verifyErr, ErrUpstreamIdentity) {
				record.Phase = PhaseDeletePending
				if err := s.Save(record); err != nil {
					return hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
				}
				return provisioner.WithCreateCleanupPending(hold("GATEWAY_UPSTREAM_IDENTITY_UNCONFIRMED", verifyErr), provisioner.CreateCleanup{RuntimeWorkloadID: record.Result.RuntimeWorkloadID, NamespaceUID: record.Result.NamespaceUID, FailureCode: "GATEWAY_UPSTREAM_IDENTITY_UNCONFIRMED"})
			}
			return hold("GATEWAY_UPSTREAM_IDENTITY_UNCONFIRMED", verifyErr)
		}
		if record.Phase == PhaseApplyPending {
			route, putErr := a.remote.Put(ctx, c.InstanceID, record.Destination)
			if putErr != nil {
				var apiErr *APIError
				if errors.As(putErr, &apiErr) && (apiErr.Code == "GATEWAY_TARGET_IN_USE" || apiErr.Code == "TARGET_IN_USE" || apiErr.Code == "GATEWAY_INSTANCE_CONFLICT" || apiErr.Code == "INSTANCE_CONFLICT" || apiErr.Code == "GATEWAY_OWNER_CONFLICT" || apiErr.Code == "OWNER_CONFLICT" || apiErr.Code == "GATEWAY_CONTRACT_UNCONFIRMED") {
					record.Phase = PhaseConflictHold
					if err := s.Save(record); err != nil {
						return hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
					}
					_ = a.backend.Quiesce(ctx, record)
					return provisioner.WithCreateCleanupPending(hold(apiErr.Code, putErr), provisioner.CreateCleanup{RuntimeWorkloadID: record.Result.RuntimeWorkloadID, NamespaceUID: record.Result.NamespaceUID, FailureCode: apiErr.Code})
				}
				if errors.As(putErr, &apiErr) && apiErr.Permanent {
					if cleanupErr := a.remove(ctx, s, record); cleanupErr != nil {
						return provisioner.WithCreateCleanupPending(cleanupErr, provisioner.CreateCleanup{RuntimeWorkloadID: record.Result.RuntimeWorkloadID, NamespaceUID: record.Result.NamespaceUID, FailureCode: apiErr.Code})
					}
					return provisioner.WithCreateCleanupCompleted(operations.NewExecutionError(apiErr.Code, false, nil))
				}
				return hold(errorCode(putErr), putErr)
			}
			if !publicOriginMatches(c, route) {
				if cleanupErr := a.remove(ctx, s, record); cleanupErr != nil {
					return provisioner.WithCreateCleanupPending(cleanupErr, provisioner.CreateCleanup{RuntimeWorkloadID: record.Result.RuntimeWorkloadID, NamespaceUID: record.Result.NamespaceUID, FailureCode: "GATEWAY_ORIGIN_MISMATCH"})
				}
				return provisioner.WithCreateCleanupCompleted(operations.NewExecutionError("GATEWAY_ORIGIN_MISMATCH", false, nil))
			}
			record.Route = route
			record.Phase = PhaseApplied
			if saveErr := s.Save(record); saveErr != nil {
				return hold("GATEWAY_JOURNAL_UNAVAILABLE", saveErr)
			}
		}
		result = publicResult(record)
		return nil
	})
	// Callback paths classify journal/remote uncertainty explicitly. Preserve
	// backend runtime errors and cleanup proof wrappers exactly as returned.
	if err != nil && !callbackRan {
		err = hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
	}
	return result, err
}
func publicResult(r Record) provisioner.CreateWorkloadResult {
	result := r.Result
	result.Endpoints = append([]provisioner.WorkloadEndpoint(nil), r.Result.Endpoints...)
	for i := range result.Endpoints {
		e := &result.Endpoints[i]
		e.Hostname = r.Route.Hostname
		e.ConnectionPort = r.Route.Port
		e.TLS = r.Route.TLS
		e.ServerName = ""
		scheme := "tcp"
		if r.Route.TLS {
			scheme = "tls"
			e.ServerName = r.Route.Hostname
		}
		e.ServiceURL = scheme + "://" + net.JoinHostPort(r.Route.Hostname, strconv.Itoa(r.Route.Port))
		if r.Destination.Protocol == "http" && r.Route.URL != nil {
			e.ServiceURL = *r.Route.URL
		}
	}
	if len(result.Endpoints) > 0 {
		result.ServiceURL = result.Endpoints[0].ServiceURL
	}
	return result
}
func (a *Adapter) DeleteWorkload(ctx context.Context, c provisioner.DeleteWorkloadCommand, b runtimebinding.Binding) error {
	_, err := a.journal.Get(ctx, c.InstanceID)
	if errors.Is(err, ErrNotFound) {
		return a.backend.DeleteWorkload(ctx, c, b)
	}
	if err != nil {
		return hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
	}
	err = a.journal.WithLock(ctx, c.InstanceID, func(s Session) error {
		record, err := s.Load()
		if err != nil {
			return hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
		}
		if record.Command.TargetID != b.TargetID || record.Command.TeamID != b.TeamID || record.Result.NamespaceUID != b.NamespaceUID || record.Result.RuntimeWorkloadID != b.RuntimeWorkloadID {
			return operations.NewExecutionError("GATEWAY_INTENT_CONFLICT", false, nil)
		}
		return a.remove(ctx, s, record)
	})
	if err != nil {
		var execution *operations.ExecutionError
		if !errors.As(err, &execution) {
			return hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
		}
	}
	return err
}
func (a *Adapter) remove(ctx context.Context, s Session, r Record) error {
	if r.Phase == PhaseDeleted {
		return nil
	}
	if r.Phase == PhaseConflictHold {
		// DELETE(current ID) cannot remove another ID's reference to this port.
		// Only a successful identical PUT proves tuple ownership after the
		// operator resolves the foreign route. Never promote this to CREATE.
		if err := a.backend.Quiesce(ctx, r); err != nil {
			return hold("GATEWAY_CONFLICT_HOLD", err)
		}
		if err := a.backend.VerifyPortClaim(ctx, r); err != nil {
			return hold("GATEWAY_CONFLICT_HOLD", err)
		}
		route, err := a.remote.Put(ctx, r.Command.InstanceID, r.Destination)
		if err != nil {
			return hold("GATEWAY_CONFLICT_HOLD", err)
		}
		r.Route = route
		r.Phase = PhaseDeletePending
		if err := s.Save(r); err != nil {
			return hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
		}
	}
	if r.Phase != PhaseRouteDeleted {
		r.Phase = PhaseDeletePending
		if err := s.Save(r); err != nil {
			return hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
		}
		quiesceErr := a.backend.Quiesce(ctx, r)
		if err := a.remote.Delete(ctx, r.Command.InstanceID); err != nil {
			return hold(errorCode(err), err)
		}
		r.Phase = PhaseRouteDeleted
		if err := s.Save(r); err != nil {
			return hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
		}
		if quiesceErr != nil {
			return hold("GATEWAY_WORKLOAD_STOP_PENDING", quiesceErr)
		}
	} else if err := a.backend.Quiesce(ctx, r); err != nil {
		// Route deletion is durable, but pod termination may still be in progress
		// after a retry or restart. Wait before handing the namespace to its controller.
		return hold("GATEWAY_WORKLOAD_STOP_PENDING", err)
	}
	binding := recoveryBinding(r)
	command := provisioner.DeleteWorkloadCommand{RequestID: r.Command.RequestID, InstanceID: r.Command.InstanceID, TeamID: r.Command.TeamID, TargetID: r.Command.TargetID, RuntimeType: r.Command.RuntimeType, RuntimeWorkloadID: r.Result.RuntimeWorkloadID}
	deleteWorkload := a.backend.DeleteWorkload
	if stepper, ok := a.backend.(interface {
		DeleteWorkloadStep(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error
	}); ok {
		deleteWorkload = stepper.DeleteWorkloadStep
	}
	if err := deleteWorkload(ctx, command, binding); err != nil {
		return hold("GATEWAY_WORKLOAD_DELETE_PENDING", err)
	}
	r.Phase = PhaseDeleted
	if err := s.Save(r); err != nil {
		return hold("GATEWAY_JOURNAL_UNAVAILABLE", err)
	}
	return nil
}
func (a *Adapter) CleanupFailedCreate(ctx context.Context, c provisioner.CreateWorkloadCommand, cleanup provisioner.CreateCleanup) error {
	r, err := a.journal.Get(ctx, c.InstanceID)
	if errors.Is(err, ErrNotFound) {
		return a.backend.CleanupFailedCreate(ctx, c, cleanup)
	}
	if err != nil {
		return provisioner.WithCreateCleanupPending(hold("GATEWAY_JOURNAL_UNAVAILABLE", err), cleanup)
	}
	err = a.DeleteWorkload(ctx, provisioner.DeleteWorkloadCommand{InstanceID: c.InstanceID}, recoveryBinding(r))
	if err != nil {
		return provisioner.WithCreateCleanupPending(err, cleanup)
	}
	return provisioner.WithCreateCleanupCompleted(operations.NewExecutionError(cleanup.FailureCode, false, nil))
}
func recoveryBinding(r Record) runtimebinding.Binding {
	namespace := "" // A Kubernetes workload ID is target/namespace/instance.
	for i, c := range r.Result.RuntimeWorkloadID {
		if c == '/' {
			tail := r.Result.RuntimeWorkloadID[i+1:]
			for j, d := range tail {
				if d == '/' {
					namespace = tail[:j]
					break
				}
			}
			break
		}
	}
	p := r.Command.Policy
	return runtimebinding.Binding{
		InstanceID:            r.Command.InstanceID,
		TeamID:                r.Command.TeamID,
		TargetID:              r.Command.TargetID,
		Namespace:             namespace,
		NamespaceUID:          r.Result.NamespaceUID,
		RuntimeWorkloadID:     r.Result.RuntimeWorkloadID,
		Endpoints:             publicResult(r).Endpoints,
		IsolationProfile:      p.IsolationRef.Name + "@" + p.IsolationRef.Version,
		WorkloadProfile:       p.WorkloadProfileRef.Name + "@" + p.WorkloadProfileRef.Version,
		ContainerRequirements: p.Containers,
		WorkloadNetwork:       isolation.CloneWorkloadNetwork(p.WorkloadNetwork),
		InternalConnections:   p.InternalConnections,
		OutboundMode:          p.OutboundMode,
		ResourceLimits:        p.ResourceLimits,
		State:                 runtimebinding.StateCreated,
		CreatedAt:             r.CreatedAt,
		UpdatedAt:             r.CreatedAt,
	}
}
func (a *Adapter) RecoveryBinding(ctx context.Context, id string) (runtimebinding.Binding, error) {
	r, err := a.journal.Get(ctx, id)
	if errors.Is(err, ErrNotFound) || (err == nil && r.Phase == PhaseDeleted) {
		return runtimebinding.Binding{}, runtimebinding.ErrNotFound
	}
	if err != nil {
		return runtimebinding.Binding{}, err
	}
	return recoveryBinding(r), nil
}
func (a *Adapter) CleanupPending(ctx context.Context, id string) (bool, error) {
	r, err := a.journal.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil && r.Phase != PhaseDeleted && r.Phase != PhaseApplied, err
}
func hold(code string, err error) error { return operations.NewHeldExecutionError(code, err) }
func errorCode(err error) string {
	var api *APIError
	if errors.As(err, &api) {
		return api.Code
	}
	return "GATEWAY_UNAVAILABLE"
}
