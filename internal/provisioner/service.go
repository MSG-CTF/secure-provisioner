package provisioner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	maximumTTL     = 6 * time.Hour
	maximumRetries = 3
)

type Service struct {
	store              *memoryStore
	dependencies       *dependencyClient
	cluster            *fakeCluster
	jobs               chan string
	logger             *slog.Logger
	expirationInterval time.Duration
	instanceLocks      sync.Map
}

func NewService(mockURL string, logger *slog.Logger, expirationInterval time.Duration) *Service {
	return &Service{
		store:              newMemoryStore(),
		dependencies:       newDependencyClient(mockURL),
		cluster:            newFakeCluster(mockURL),
		jobs:               make(chan string, 128),
		logger:             logger,
		expirationInterval: expirationInterval,
	}
}

func (service *Service) Start(ctx context.Context, workerCount int) {
	if workerCount < 1 {
		workerCount = 1
	}

	for workerID := 1; workerID <= workerCount; workerID++ {
		go service.worker(ctx, workerID)
	}
	go service.expirationWorker(ctx)
}

func (service *Service) AcceptCreate(ctx context.Context, request CreateRequest) (AcceptedOperation, error) {
	now := time.Now().UTC()
	if err := validateCreateRequest(request, now); err != nil {
		return AcceptedOperation{}, err
	}

	operation, instance, duplicate, enqueue, err := service.store.acceptCreate(request, now)
	if err != nil {
		return AcceptedOperation{}, err
	}

	if enqueue {
		if err := service.enqueue(ctx, operation.OperationID); err != nil {
			return AcceptedOperation{}, err
		}
	}

	return AcceptedOperation{
		OperationID: operation.OperationID,
		InstanceID:  instance.InstanceID,
		Phase:       instance.Phase,
		Duplicate:   duplicate,
	}, nil
}

func (service *Service) AcceptDelete(ctx context.Context, requestID string, instanceID string) (AcceptedOperation, error) {
	if strings.TrimSpace(requestID) == "" {
		return AcceptedOperation{}, errors.New("requestId is required")
	}

	operation, instance, duplicate, enqueue, err := service.store.acceptDelete(requestID, instanceID, time.Now().UTC())
	if err != nil {
		return AcceptedOperation{}, err
	}

	if enqueue {
		if err := service.enqueue(ctx, operation.OperationID); err != nil {
			return AcceptedOperation{}, err
		}
	}

	return AcceptedOperation{
		OperationID: operation.OperationID,
		InstanceID:  instance.InstanceID,
		Phase:       instance.Phase,
		Duplicate:   duplicate,
	}, nil
}

func (service *Service) GetInstance(instanceID string) (InstanceView, error) {
	instance, err := service.store.getInstance(instanceID)
	if err != nil {
		return InstanceView{}, err
	}
	return newInstanceView(instance), nil
}

func (service *Service) GetOperation(operationID string) (Operation, bool) {
	return service.store.getOperation(operationID)
}

func (service *Service) GetRuntimeResources(instanceID string) (RuntimeResources, bool) {
	return service.cluster.get(instanceID)
}

func (service *Service) enqueue(ctx context.Context, operationID string) error {
	select {
	case service.jobs <- operationID:
		return nil
	case <-ctx.Done():
		return errors.New("operation queue is unavailable")
	}
}

func (service *Service) worker(ctx context.Context, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case operationID := <-service.jobs:
			service.processOperation(ctx, workerID, operationID)
		}
	}
}

func (service *Service) processOperation(ctx context.Context, workerID int, operationID string) {
	operation, started := service.store.startOperation(operationID, time.Now().UTC())
	if !started {
		return
	}

	lockValue, _ := service.instanceLocks.LoadOrStore(operation.InstanceID, &sync.Mutex{})
	instanceLock := lockValue.(*sync.Mutex)
	instanceLock.Lock()
	defer instanceLock.Unlock()

	service.logger.Info("processing operation",
		"workerId", workerID,
		"operationId", operation.OperationID,
		"instanceId", operation.InstanceID,
		"operationType", operation.OperationType,
	)

	var err error
	for attempt := 1; attempt <= maximumRetries; attempt++ {
		if attempt > 1 {
			service.store.incrementAttempt(operation.OperationID, time.Now().UTC())
		}

		switch operation.OperationType {
		case OperationCreate:
			err = service.provision(ctx, operation)
		case OperationDelete:
			err = service.delete(ctx, operation)
		default:
			err = errors.New("unsupported operation type")
		}

		if err == nil {
			service.store.finishOperation(operation.OperationID, OperationSucceeded, "", time.Now().UTC())
			return
		}

		if attempt < maximumRetries {
			service.logger.Warn("operation retry scheduled",
				"operationId", operation.OperationID,
				"instanceId", operation.InstanceID,
				"attempt", attempt,
			)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
	}

	service.failOperation(ctx, operation, err)
}

func (service *Service) provision(ctx context.Context, operation Operation) error {
	instance, err := service.store.getInstance(operation.InstanceID)
	if err != nil {
		return err
	}
	if instance.DesiredState == DesiredTerminated {
		return errors.New("creation was cancelled by a delete request")
	}

	_, err = service.store.updateInstance(instance.InstanceID, func(current *Instance) {
		current.Phase = PhaseProvisioning
		current.LastError = ""
	}, time.Now().UTC())
	if err != nil {
		return err
	}

	reservation, err := service.dependencies.validateReservation(ctx, instance.ReservationID)
	if err != nil {
		return err
	}
	if reservation.ReservationID != instance.ReservationID || reservation.ClusterID != instance.ClusterID {
		return errors.New("scheduler reservation does not match the requested cluster")
	}

	challenge, err := service.dependencies.resolveChallenge(ctx, instance.ChallengeID)
	if err != nil {
		return err
	}
	if challenge.ChallengeID != instance.ChallengeID {
		return errors.New("challenge catalog returned a mismatched challenge")
	}

	resources, err := service.cluster.create(ctx, instance, challenge)
	if err != nil {
		return err
	}

	instance, err = service.store.updateInstance(instance.InstanceID, func(current *Instance) {
		current.Namespace = resources.Namespace
		current.SecurityProfile = challenge.SecurityProfile
		current.ResourceProfile = challenge.ResourceProfile
		current.NetworkProfile = challenge.NetworkProfile
		current.Endpoint = resources.Endpoint
		current.Phase = PhaseVerifying
	}, time.Now().UTC())
	if err != nil {
		return err
	}

	if err := service.dependencies.verifyEndpoint(ctx, resources.Endpoint); err != nil {
		return err
	}

	instance, err = service.store.updateInstance(instance.InstanceID, func(current *Instance) {
		current.Phase = PhaseReady
		current.LastError = ""
	}, time.Now().UTC())
	if err != nil {
		return err
	}

	_ = service.dependencies.publishEvent(ctx, "/mock/v1/broker/events", "InstanceReady", instance)
	return nil
}

func (service *Service) delete(ctx context.Context, operation Operation) error {
	instance, err := service.store.updateInstance(operation.InstanceID, func(current *Instance) {
		current.Phase = PhaseTerminating
		current.DesiredState = DesiredTerminated
		current.LastError = ""
	}, time.Now().UTC())
	if err != nil {
		return err
	}

	if err := service.cluster.delete(ctx, instance.InstanceID); err != nil {
		return fmt.Errorf("delete K3s resources: %w", err)
	}
	if err := service.dependencies.releaseReservation(ctx, instance.ReservationID, instance.InstanceID); err != nil {
		return fmt.Errorf("release scheduler reservation: %w", err)
	}

	instance, err = service.store.updateInstance(instance.InstanceID, func(current *Instance) {
		current.Phase = PhaseTerminated
		current.Endpoint = ""
		current.LastError = ""
	}, time.Now().UTC())
	if err != nil {
		return err
	}

	_ = service.dependencies.publishEvent(ctx, "/mock/v1/broker/events", "InstanceTerminated", instance)
	return nil
}

func (service *Service) failOperation(ctx context.Context, operation Operation, operationError error) {
	lastError := operationError.Error()
	phase := PhaseFailed
	if operation.OperationType == OperationDelete {
		phase = PhaseDeleteFailed
	} else {
		_ = service.cluster.delete(ctx, operation.InstanceID)
	}

	instance, _ := service.store.updateInstance(operation.InstanceID, func(current *Instance) {
		current.Phase = phase
		current.LastError = lastError
	}, time.Now().UTC())
	service.store.finishOperation(operation.OperationID, OperationFailed, lastError, time.Now().UTC())

	service.logger.Error("operation failed",
		"operationId", operation.OperationID,
		"instanceId", operation.InstanceID,
		"operationType", operation.OperationType,
		"error", lastError,
	)
	_ = service.dependencies.publishEvent(ctx, "/mock/v1/sla/events", "OperationFailed", instance)
}

func (service *Service) expirationWorker(ctx context.Context) {
	interval := service.expirationInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, instanceID := range service.store.expiredInstances(now.UTC()) {
				requestID := "ttl-" + instanceID
				_, _ = service.AcceptDelete(ctx, requestID, instanceID)
			}
		}
	}
}

func validateCreateRequest(request CreateRequest, now time.Time) error {
	required := map[string]string{
		"requestId":     request.RequestID,
		"instanceId":    request.InstanceID,
		"teamId":        request.TeamID,
		"challengeId":   request.ChallengeID,
		"clusterId":     request.ClusterID,
		"reservationId": request.ReservationID,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}

	if request.ExpiresAt.IsZero() {
		return errors.New("expiresAt is required")
	}
	if !request.ExpiresAt.After(now) {
		return errors.New("expiresAt must be in the future")
	}
	if request.ExpiresAt.After(now.Add(maximumTTL)) {
		return errors.New("expiresAt exceeds the six-hour MVP limit")
	}

	return nil
}
