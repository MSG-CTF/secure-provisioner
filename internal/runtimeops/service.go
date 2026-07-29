package runtimeops

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

var ErrBindingMismatch = errors.New("instance runtime binding mismatch")

type CreateAdapter interface {
	CreateWorkload(context.Context, provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error)
}

type StatusSource interface {
	Get(context.Context, runtimebinding.Binding) (k3s.RuntimeStatus, error)
}

type DeleteAdapter interface {
	DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error
}

type Config struct {
	MaxAttempts int
	Worker      operations.WorkerConfig
}

type Service struct {
	create      CreateAdapter
	status      StatusSource
	delete      DeleteAdapter
	bindings    runtimebinding.Store
	operations  operations.Store
	worker      *operations.Worker
	maxAttempts int
	now         func() time.Time
	enqueueMu   sync.Mutex
}

func NewService(
	create CreateAdapter,
	status StatusSource,
	deleteAdapter DeleteAdapter,
	bindings runtimebinding.Store,
	operationStore operations.Store,
	config Config,
) (*Service, error) {
	if create == nil || status == nil || deleteAdapter == nil || bindings == nil || operationStore == nil || config.MaxAttempts <= 0 {
		return nil, errors.New("runtime service dependencies are required")
	}
	recordingCreate := &bindingCreateAdapter{
		inner:    create,
		cleanup:  deleteAdapter,
		bindings: bindings,
		now:      time.Now,
	}
	recordingDelete := &bindingDeleteAdapter{inner: deleteAdapter, bindings: bindings, now: time.Now}
	executor, err := k3s.NewExecutorWithDelete(recordingCreate, recordingDelete, bindings)
	if err != nil {
		return nil, err
	}
	worker, err := operations.NewWorker(operationStore, executor, config.Worker)
	if err != nil {
		return nil, err
	}
	service := &Service{
		create:      create,
		status:      status,
		delete:      deleteAdapter,
		bindings:    bindings,
		operations:  operationStore,
		worker:      worker,
		maxAttempts: config.MaxAttempts,
		now:         time.Now,
	}
	recordingCreate.now = func() time.Time { return service.now() }
	recordingDelete.now = func() time.Time { return service.now() }
	return service, nil
}

func (s *Service) EnqueueCreate(command provisioner.CreateWorkloadCommand) (operations.Operation, bool, error) {
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	return s.operations.EnqueueCreate(command, s.maxAttempts)
}

func (s *Service) CreateWorkload(ctx context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	result, err := s.create.CreateWorkload(ctx, command)
	if err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	namespace, err := k3s.NamespaceForInstance(command.InstanceID)
	if err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	now := s.now().UTC()
	_, _, err = s.bindings.SaveCreated(runtimebinding.Binding{
		InstanceID:        command.InstanceID,
		TeamID:            command.TeamID,
		TargetID:          command.TargetID,
		Namespace:         namespace,
		RuntimeWorkloadID: result.RuntimeWorkloadID,
		State:             runtimebinding.StateCreated,
		CreatedAt:         now,
		UpdatedAt:         now,
	})
	if err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	return result, nil
}

type bindingCreateAdapter struct {
	inner    CreateAdapter
	cleanup  DeleteAdapter
	bindings runtimebinding.Store
	now      func() time.Time
}

func (a *bindingCreateAdapter) CreateWorkload(ctx context.Context, command provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	result, err := a.inner.CreateWorkload(ctx, command)
	if err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	namespace, err := k3s.NamespaceForInstance(command.InstanceID)
	if err != nil {
		return provisioner.CreateWorkloadResult{}, err
	}
	now := a.now().UTC()
	binding := runtimebinding.Binding{
		InstanceID:        command.InstanceID,
		TeamID:            command.TeamID,
		TargetID:          command.TargetID,
		Namespace:         namespace,
		RuntimeWorkloadID: result.RuntimeWorkloadID,
		State:             runtimebinding.StateCreated,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if _, _, err := a.bindings.SaveCreated(binding); err != nil {
		cleanupErr := a.cleanup.DeleteWorkload(ctx, provisioner.DeleteWorkloadCommand{
			RequestID:         command.RequestID,
			InstanceID:        command.InstanceID,
			TeamID:            command.TeamID,
			RuntimeType:       command.RuntimeType,
			TargetID:          command.TargetID,
			RuntimeWorkloadID: result.RuntimeWorkloadID,
			Reason:            provisioner.DeleteReasonCreateFailedCleanup,
		}, binding)
		if cleanupErr != nil {
			return provisioner.CreateWorkloadResult{}, errors.Join(err, cleanupErr)
		}
		return provisioner.CreateWorkloadResult{}, err
	}
	return result, nil
}

func (s *Service) GetRuntimeStatus(ctx context.Context, instanceID string) (k3s.RuntimeStatus, error) {
	binding, err := s.bindings.Get(instanceID)
	if err != nil {
		return k3s.RuntimeStatus{}, err
	}
	if binding.State == runtimebinding.StateDeleted {
		return k3s.RuntimeStatus{
			InstanceID:        binding.InstanceID,
			TargetID:          binding.TargetID,
			RuntimeWorkloadID: binding.RuntimeWorkloadID,
			Phase:             "TERMINATED",
			ObservedAt:        s.now().UTC(),
			Containers:        []k3s.ContainerRuntimeStatus{},
		}, nil
	}
	return s.status.Get(ctx, binding)
}

func (s *Service) EnqueueDelete(command provisioner.DeleteWorkloadCommand) (operations.Operation, bool, error) {
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()

	existing, err := s.operations.GetByRequestID(command.RequestID)
	if err == nil {
		if existing.Type == operations.OperationTypeDelete &&
			existing.DeleteCommand != nil &&
			*existing.DeleteCommand == command {
			return existing, false, nil
		}
		return operations.Operation{}, false, operations.ErrIdempotencyConflict
	}
	if !errors.Is(err, operations.ErrOperationNotFound) {
		return operations.Operation{}, false, err
	}

	binding, err := s.bindings.Get(command.InstanceID)
	if err != nil {
		return operations.Operation{}, false, err
	}
	if !deleteMatchesBinding(command, binding) {
		return operations.Operation{}, false, ErrBindingMismatch
	}
	if binding.State == runtimebinding.StateDeleted {
		return operations.Operation{}, false, runtimebinding.ErrInvalidTransition
	}
	transitioned := binding.State == runtimebinding.StateCreated
	if _, err := s.bindings.MarkDeleting(binding.InstanceID, s.now().UTC()); err != nil {
		return operations.Operation{}, false, err
	}
	operation, created, err := s.operations.EnqueueDelete(command, s.maxAttempts)
	if err == nil {
		return operation, created, nil
	}
	if transitioned {
		if _, restoreErr := s.bindings.RestoreCreated(binding.InstanceID, s.now().UTC()); restoreErr != nil {
			return operations.Operation{}, false, errors.Join(err, restoreErr)
		}
	}
	return operations.Operation{}, false, err
}

func (s *Service) GetOperation(operationID string) (operations.Operation, error) {
	return s.operations.Get(operationID)
}

func (s *Service) Run(ctx context.Context) error {
	return s.worker.Run(ctx)
}

func deleteMatchesBinding(command provisioner.DeleteWorkloadCommand, binding runtimebinding.Binding) bool {
	return command.InstanceID == binding.InstanceID &&
		command.TeamID == binding.TeamID &&
		command.RuntimeType == provisioner.RuntimeTypeKubernetes &&
		command.TargetID == binding.TargetID &&
		command.RuntimeWorkloadID == binding.RuntimeWorkloadID
}

type bindingDeleteAdapter struct {
	inner    DeleteAdapter
	bindings runtimebinding.Store
	now      func() time.Time
}

func (a *bindingDeleteAdapter) DeleteWorkload(ctx context.Context, command provisioner.DeleteWorkloadCommand, binding runtimebinding.Binding) error {
	if err := a.inner.DeleteWorkload(ctx, command, binding); err != nil {
		return err
	}
	_, err := a.bindings.MarkDeleted(binding.InstanceID, a.now().UTC())
	return err
}
