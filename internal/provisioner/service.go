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

type WorkerOptions struct {
	Concurrency    int
	PollInterval   time.Duration
	LeaseDuration  time.Duration
	MaximumRetries int
	RetryBaseDelay time.Duration
}

type Service struct {
	store              operationStore
	dependencies       *dependencyClient
	cluster            clusterAdapter
	logger             *slog.Logger
	expirationInterval time.Duration
	instanceLocks      sync.Map
	workerOptions      WorkerOptions
}

func NewService(mockURL string, logger *slog.Logger, expirationInterval time.Duration) *Service {
	return newService(mockURL, logger, expirationInterval, newFakeCluster(mockURL))
}

func NewPostgresService(ctx context.Context, mockURL string, logger *slog.Logger, expirationInterval time.Duration, dsn string) (*Service, error) {
	store, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return newServiceWithStore(mockURL, logger, expirationInterval, newFakeCluster(mockURL), store), nil
}

func newService(mockURL string, logger *slog.Logger, expirationInterval time.Duration, cluster clusterAdapter) *Service {
	return newServiceWithStore(mockURL, logger, expirationInterval, cluster, newMemoryStore())
}

func newServiceWithStore(mockURL string, logger *slog.Logger, expirationInterval time.Duration, cluster clusterAdapter, store operationStore) *Service {
	return &Service{
		store:              store,
		dependencies:       newDependencyClient(mockURL),
		cluster:            cluster,
		logger:             logger,
		expirationInterval: expirationInterval,
	}
}

func (service *Service) Start(ctx context.Context, workerCount int) {
	service.StartWithOptions(ctx, WorkerOptions{Concurrency: workerCount})
}

func (service *Service) StartWithOptions(ctx context.Context, options WorkerOptions) {
	options = normalizedWorkerOptions(options)
	service.workerOptions = options

	for workerIndex := 1; workerIndex <= options.Concurrency; workerIndex++ {
		go service.worker(ctx, fmt.Sprintf("worker-%d-%s", workerIndex, randomOperationID()))
	}
	go service.expirationWorker(ctx)
}

func (service *Service) Close() error {
	return service.store.close()
}

func normalizedWorkerOptions(options WorkerOptions) WorkerOptions {
	if options.Concurrency < 1 {
		options.Concurrency = 10
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 200 * time.Millisecond
	}
	if options.LeaseDuration <= 0 {
		options.LeaseDuration = 3 * time.Minute
	}
	if options.MaximumRetries < 0 {
		options.MaximumRetries = maximumRetries
	}
	if options.MaximumRetries == 0 {
		options.MaximumRetries = maximumRetries
	}
	if options.RetryBaseDelay <= 0 {
		options.RetryBaseDelay = time.Second
	}
	return options
}

func (service *Service) AcceptCreate(ctx context.Context, request CreateRequest) (AcceptedOperation, error) {
	now := time.Now().UTC()
	if err := validateCreateRequest(request, now); err != nil {
		return AcceptedOperation{}, err
	}

	operation, instance, duplicate, err := service.store.acceptCreate(ctx, request, now)
	if err != nil {
		return AcceptedOperation{}, err
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
		return AcceptedOperation{}, errors.New("request_id is required")
	}

	operation, instance, duplicate, err := service.store.acceptDelete(ctx, requestID, instanceID, time.Now().UTC())
	if err != nil {
		return AcceptedOperation{}, err
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

func (service *Service) worker(ctx context.Context, workerID string) {
	options := service.workerOptions
	for {
		operation, claimed, err := service.store.claim(ctx, ClaimOptions{
			WorkerID:      workerID,
			Now:           time.Now().UTC(),
			LeaseDuration: options.LeaseDuration,
		})
		if err != nil {
			service.logger.Error("claim operation", "worker_id", workerID, "error", err)
		}
		if claimed {
			service.processOperation(ctx, workerID, operation)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(options.PollInterval):
		}
	}
}

func (service *Service) processOperation(ctx context.Context, workerID string, operation Operation) {
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

	stopRenewal := make(chan struct{})
	renewalDone := make(chan struct{})
	go service.renewOperationLease(ctx, workerID, operation.OperationID, stopRenewal, renewalDone)
	err := service.executeOperation(ctx, operation)
	close(stopRenewal)
	<-renewalDone
	if err == nil {
		if finishErr := service.store.finishOperation(operation.OperationID, workerID, OperationSucceeded, "", time.Now().UTC()); finishErr != nil {
			service.logger.Error("finish operation", "operation_id", operation.OperationID, "worker_id", workerID, "error", finishErr)
		}
		return
	}
	if ctx.Err() != nil {
		return
	}
	if isPermanentOperationError(err) || operation.AttemptCount > service.workerOptions.MaximumRetries {
		service.failOperation(ctx, workerID, operation, err)
		return
	}
	delay := service.workerOptions.RetryBaseDelay * time.Duration(1<<uint(operation.AttemptCount-1))
	now := time.Now().UTC()
	if retryErr := service.store.retryOperation(operation.OperationID, workerID, now.Add(delay), err.Error(), now); retryErr != nil {
		service.logger.Error("schedule operation retry", "operation_id", operation.OperationID, "error", retryErr)
	}
}

func (service *Service) renewOperationLease(ctx context.Context, workerID string, operationID string, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	interval := service.workerOptions.LeaseDuration / 3
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case now := <-ticker.C:
			if err := service.store.renewLease(operationID, workerID, now.UTC().Add(service.workerOptions.LeaseDuration)); err != nil {
				service.logger.Warn("renew operation lease", "operation_id", operationID, "worker_id", workerID, "error", err)
				return
			}
		}
	}
}

func (service *Service) executeOperation(ctx context.Context, operation Operation) error {
	switch operation.OperationType {
	case OperationCreate:
		return service.provision(ctx, operation)
	case OperationDelete:
		return service.delete(ctx, operation)
	default:
		return errors.New("unsupported operation type")
	}
}

func isPermanentOperationError(err error) bool {
	if errors.Is(err, ErrRuntimeClassUnavailable) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "does not match") ||
		strings.Contains(message, "mismatched") ||
		strings.Contains(message, "cancelled by a delete request") ||
		strings.Contains(message, "reservation is invalid")
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

	resources, err := service.cluster.create(ctx, instance, challenge, reservation)
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

	if err := service.cluster.verify(ctx, resources); err != nil {
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

func (service *Service) failOperation(ctx context.Context, workerID string, operation Operation, operationError error) {
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
	if err := service.store.finishOperation(operation.OperationID, workerID, OperationFailed, lastError, time.Now().UTC()); err != nil {
		service.logger.Error("finish failed operation", "operation_id", operation.OperationID, "worker_id", workerID, "error", err)
	}

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
		"request_id":     request.RequestID,
		"instance_id":    request.InstanceID,
		"challenge_id":   request.ChallengeID,
		"cluster_id":     request.ClusterID,
		"reservation_id": request.ReservationID,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if request.TeamID < 1 {
		return errors.New("team_id must be a positive integer")
	}

	if request.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	if !request.ExpiresAt.After(now) {
		return errors.New("expires_at must be in the future")
	}
	if request.ExpiresAt.After(now.Add(maximumTTL)) {
		return errors.New("expires_at exceeds the six-hour MVP limit")
	}

	return nil
}
