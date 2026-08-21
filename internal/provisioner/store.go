package provisioner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrInstanceNotFound = errors.New("instance not found")
	ErrInstanceIDInUse  = errors.New("instance ID is already in use")
)

type memoryStore struct {
	mu                sync.RWMutex
	sequence          atomic.Uint64
	instances         map[string]*Instance
	activeAllocations map[string]string
	operations        map[string]*Operation
	requestOperations map[string]string
	deleteOperations  map[string]string
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		instances:         make(map[string]*Instance),
		activeAllocations: make(map[string]string),
		operations:        make(map[string]*Operation),
		requestOperations: make(map[string]string),
		deleteOperations:  make(map[string]string),
	}
}

func (store *memoryStore) acceptCreate(_ context.Context, request CreateRequest, now time.Time) (Operation, Instance, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if operationID, exists := store.requestOperations[request.RequestID]; exists {
		operation := *store.operations[operationID]
		instance := *store.instances[operation.InstanceID]
		return operation, instance, true, nil
	}

	allocationKey := activeAllocationKey(request.TeamID, request.ChallengeID)
	if instanceID, exists := store.activeAllocations[allocationKey]; exists {
		instance := *store.instances[instanceID]
		operation := store.latestOperationLocked(instanceID)
		store.requestOperations[request.RequestID] = operation.OperationID
		return operation, instance, true, nil
	}

	if _, exists := store.instances[request.InstanceID]; exists {
		return Operation{}, Instance{}, false, ErrInstanceIDInUse
	}

	operation := store.newOperationLocked(request.RequestID, request.InstanceID, OperationCreate, now)
	instance := &Instance{
		InstanceID:    request.InstanceID,
		TeamID:        request.TeamID,
		ChallengeID:   request.ChallengeID,
		ClusterID:     request.ClusterID,
		ReservationID: request.ReservationID,
		Phase:         PhaseRequested,
		DesiredState:  DesiredRunning,
		Generation:    1,
		CreatedBy:     request.CreatedBy,
		CreatedAt:     now,
		ExpiresAt:     request.ExpiresAt,
		UpdatedAt:     now,
	}

	store.instances[request.InstanceID] = instance
	store.activeAllocations[allocationKey] = request.InstanceID
	store.operations[operation.OperationID] = &operation
	store.requestOperations[request.RequestID] = operation.OperationID

	return operation, *instance, false, nil
}

func (store *memoryStore) acceptDelete(_ context.Context, requestID string, instanceID string, now time.Time) (Operation, Instance, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if operationID, exists := store.requestOperations[requestID]; exists {
		operation := *store.operations[operationID]
		instance, exists := store.instances[operation.InstanceID]
		if !exists {
			return Operation{}, Instance{}, false, ErrInstanceNotFound
		}
		return operation, *instance, true, nil
	}

	instance, exists := store.instances[instanceID]
	if !exists {
		return Operation{}, Instance{}, false, ErrInstanceNotFound
	}

	if instance.Phase == PhaseTerminated {
		operation := store.newOperationLocked(requestID, instanceID, OperationDelete, now)
		operation.Status = OperationSucceeded
		store.operations[operation.OperationID] = &operation
		store.requestOperations[requestID] = operation.OperationID
		return operation, *instance, true, nil
	}

	if operationID, exists := store.deleteOperations[instanceID]; exists {
		operation := *store.operations[operationID]
		if operation.Status == OperationFailed {
			newOperation := store.newOperationLocked(requestID, instanceID, OperationDelete, now)
			store.operations[newOperation.OperationID] = &newOperation
			store.requestOperations[requestID] = newOperation.OperationID
			store.deleteOperations[instanceID] = newOperation.OperationID
			return newOperation, *instance, false, nil
		}
		store.requestOperations[requestID] = operationID
		return operation, *instance, true, nil
	}

	operation := store.newOperationLocked(requestID, instanceID, OperationDelete, now)
	store.operations[operation.OperationID] = &operation
	store.requestOperations[requestID] = operation.OperationID
	store.deleteOperations[instanceID] = operation.OperationID
	instance.DesiredState = DesiredTerminated
	instance.UpdatedAt = now

	return operation, *instance, false, nil
}

func (store *memoryStore) incrementAttempt(operationID string, now time.Time) {
	store.mu.Lock()
	defer store.mu.Unlock()

	operation := store.operations[operationID]
	operation.AttemptCount++
	operation.UpdatedAt = now
}

func (store *memoryStore) newOperationLocked(requestID string, instanceID string, operationType OperationType, now time.Time) Operation {
	priority := createPriority
	if operationType == OperationDelete {
		priority = deletePriority
	}
	return Operation{
		OperationID:   fmt.Sprintf("op-%06d", store.sequence.Add(1)),
		RequestID:     requestID,
		InstanceID:    instanceID,
		OperationType: operationType,
		Status:        OperationPending,
		Priority:      priority,
		MaxAttempts:   maximumRetries + 1,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func (store *memoryStore) claim(_ context.Context, options ClaimOptions) (Operation, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	leaseDuration := options.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = 3 * time.Minute
	}
	var selected *Operation
	for _, operation := range store.operations {
		eligible := operation.Status == OperationPending ||
			(operation.Status == OperationRetryWait && (operation.NextRetryAt == nil || !operation.NextRetryAt.After(options.Now))) ||
			(operation.Status == OperationRunning && (operation.LeaseUntil == nil || !operation.LeaseUntil.After(options.Now)))
		if !eligible {
			continue
		}
		if selected == nil || operation.Priority > selected.Priority ||
			(operation.Priority == selected.Priority && operation.CreatedAt.Before(selected.CreatedAt)) {
			selected = operation
		}
	}
	if selected == nil {
		return Operation{}, false, nil
	}

	leaseUntil := options.Now.Add(leaseDuration)
	selected.Status = OperationRunning
	selected.AttemptCount++
	selected.LeaseOwner = options.WorkerID
	selected.LeaseUntil = &leaseUntil
	selected.UpdatedAt = options.Now
	return *selected, true, nil
}

func (store *memoryStore) latestOperationLocked(instanceID string) Operation {
	var latest *Operation
	for _, operation := range store.operations {
		if operation.InstanceID != instanceID {
			continue
		}
		if latest == nil || operation.CreatedAt.After(latest.CreatedAt) {
			latest = operation
		}
	}

	return *latest
}

func (store *memoryStore) getInstance(instanceID string) (Instance, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	instance, exists := store.instances[instanceID]
	if !exists {
		return Instance{}, ErrInstanceNotFound
	}

	return *instance, nil
}

func (store *memoryStore) getOperation(operationID string) (Operation, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	operation, exists := store.operations[operationID]
	if !exists {
		return Operation{}, false
	}

	return *operation, true
}

func (store *memoryStore) startOperation(operationID string, now time.Time) (Operation, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()

	operation, exists := store.operations[operationID]
	if !exists || operation.Status != OperationPending {
		return Operation{}, false
	}

	operation.Status = OperationRunning
	operation.AttemptCount++
	operation.UpdatedAt = now
	return *operation, true
}

func (store *memoryStore) finishOperation(operationID string, workerID string, status OperationStatus, lastError string, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	operation, exists := store.operations[operationID]
	if !exists || operation.Status != OperationRunning || operation.LeaseOwner != workerID {
		return errors.New("operation lease is not owned by worker")
	}
	operation.Status = status
	operation.LastError = lastError
	operation.LeaseOwner = ""
	operation.LeaseUntil = nil
	operation.UpdatedAt = now
	return nil
}

func (store *memoryStore) retryOperation(operationID string, workerID string, nextRetryAt time.Time, lastError string, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	operation, exists := store.operations[operationID]
	if !exists || operation.LeaseOwner != workerID {
		return errors.New("operation lease is not owned by worker")
	}
	operation.Status = OperationRetryWait
	operation.NextRetryAt = &nextRetryAt
	operation.LastError = lastError
	operation.LeaseOwner = ""
	operation.LeaseUntil = nil
	operation.UpdatedAt = now
	return nil
}

func (store *memoryStore) renewLease(operationID string, workerID string, leaseUntil time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	operation, exists := store.operations[operationID]
	if !exists || operation.Status != OperationRunning || operation.LeaseOwner != workerID {
		return errors.New("operation lease is not owned by worker")
	}
	operation.LeaseUntil = &leaseUntil
	operation.UpdatedAt = time.Now().UTC()
	return nil
}

func (store *memoryStore) close() error { return nil }

func (store *memoryStore) updateInstance(instanceID string, update func(*Instance), now time.Time) (Instance, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	instance, exists := store.instances[instanceID]
	if !exists {
		return Instance{}, ErrInstanceNotFound
	}

	update(instance)
	instance.UpdatedAt = now

	if instance.Phase == PhaseTerminated {
		delete(store.activeAllocations, activeAllocationKey(instance.TeamID, instance.ChallengeID))
		delete(store.deleteOperations, instanceID)
	}

	return *instance, nil
}

func (store *memoryStore) expiredInstances(now time.Time) []string {
	store.mu.RLock()
	defer store.mu.RUnlock()

	var instanceIDs []string
	for instanceID, instance := range store.instances {
		if instance.Phase == PhaseReady && !instance.ExpiresAt.After(now) {
			instanceIDs = append(instanceIDs, instanceID)
		}
	}

	return instanceIDs
}

func activeAllocationKey(teamID int64, challengeID string) string {
	return fmt.Sprintf("%d\x00%s", teamID, challengeID)
}
