package operations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type MemoryStore struct {
	mu           sync.Mutex
	operations   map[string]*Operation
	requestIDs   map[string]string
	queue        []string
	notification chan struct{}
	idGenerator  IDGenerator
	leases       map[string]Lease
}

func NewMemoryStore(idGenerator IDGenerator) *MemoryStore {
	if idGenerator == nil {
		idGenerator = randomID
	}
	return &MemoryStore{
		operations:   make(map[string]*Operation),
		requestIDs:   make(map[string]string),
		notification: make(chan struct{}, 1),
		idGenerator:  idGenerator,
		leases:       make(map[string]Lease),
	}
}

func (s *MemoryStore) Claim(ctx context.Context, options ClaimOptions) (ClaimedOperation, bool, error) {
	if err := ctx.Err(); err != nil {
		return ClaimedOperation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.queue {
		operation, ok := s.operations[id]
		if !ok {
			continue
		}
		lease := s.leases[id]
		eligible := operation.Status == OperationStatusQueued ||
			(operation.Status == OperationStatusRetrying && !operation.NextRetryAt.After(options.Now)) ||
			(operation.Status == OperationStatusRunning && !lease.Until.After(options.Now))
		if !eligible {
			continue
		}
		operation.Status = OperationStatusRunning
		operation.Attempt++
		lease.Owner = options.WorkerID
		lease.Version++
		lease.Until = options.Now.Add(options.LeaseDuration)
		s.leases[id] = lease
		return ClaimedOperation{Operation: copyOperation(*operation), Lease: lease}, true, nil
	}
	return ClaimedOperation{}, false, nil
}

func (s *MemoryStore) RenewLease(ctx context.Context, claimed ClaimedOperation, until time.Time) (ClaimedOperation, error) {
	if err := ctx.Err(); err != nil {
		return ClaimedOperation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(claimed.Operation.ID)
	if err != nil {
		return ClaimedOperation{}, err
	}
	lease := s.leases[operation.ID]
	if operation.Status != OperationStatusRunning || !sameLease(lease, claimed.Lease) {
		return ClaimedOperation{}, ErrLeaseLost
	}
	lease.Until = until
	s.leases[operation.ID] = lease
	return ClaimedOperation{Operation: copyOperation(*operation), Lease: lease}, nil
}

func (s *MemoryStore) ReleaseLease(claimed ClaimedOperation, _ time.Time) error {
	s.mu.Lock()
	operation, err := s.find(claimed.Operation.ID)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if !sameLease(s.leases[operation.ID], claimed.Lease) {
		s.mu.Unlock()
		return ErrLeaseLost
	}
	if operation.Status == OperationStatusRunning && operation.Attempt > 0 {
		operation.Attempt--
	}
	operation.Status = OperationStatusQueued
	operation.NextRetryAt = time.Time{}
	delete(s.leases, operation.ID)
	s.mu.Unlock()
	s.notify()
	return nil
}

func (s *MemoryStore) CheckpointLeaseCreateResult(claimed ClaimedOperation, result provisioner.CreateWorkloadResult, _ time.Time) (ClaimedOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(claimed.Operation.ID)
	if err != nil {
		return ClaimedOperation{}, err
	}
	if !sameLease(s.leases[operation.ID], claimed.Lease) {
		return ClaimedOperation{}, ErrLeaseLost
	}
	if err := checkpointCreateResult(operation, result); err != nil {
		return ClaimedOperation{}, err
	}
	return ClaimedOperation{Operation: copyOperation(*operation), Lease: claimed.Lease}, nil
}

func (s *MemoryStore) MarkLeaseRetrying(claimed ClaimedOperation, errorCode string, nextRetryAt, _ time.Time) (Operation, error) {
	s.mu.Lock()
	operation, err := s.find(claimed.Operation.ID)
	if err != nil {
		s.mu.Unlock()
		return Operation{}, err
	}
	if !sameLease(s.leases[operation.ID], claimed.Lease) {
		s.mu.Unlock()
		return Operation{}, ErrLeaseLost
	}
	operation.Status = OperationStatusRetrying
	operation.LastErrorCode = normalizeStableErrorCode(errorCode)
	operation.NextRetryAt = nextRetryAt
	delete(s.leases, operation.ID)
	result := copyOperation(*operation)
	s.mu.Unlock()
	s.notify()
	return result, nil
}

func (s *MemoryStore) MarkLeaseFailed(claimed ClaimedOperation, errorCode string, _ time.Time) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(claimed.Operation.ID)
	if err != nil {
		return Operation{}, err
	}
	if !sameLease(s.leases[operation.ID], claimed.Lease) {
		return Operation{}, ErrLeaseLost
	}
	operation.Status = OperationStatusFailed
	operation.LastErrorCode = normalizeStableErrorCode(errorCode)
	delete(s.leases, operation.ID)
	return copyOperation(*operation), nil
}

func (s *MemoryStore) MarkLeaseSucceeded(claimed ClaimedOperation, result OperationResult, _ time.Time) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(claimed.Operation.ID)
	if err != nil {
		return Operation{}, err
	}
	if !sameLease(s.leases[operation.ID], claimed.Lease) {
		return Operation{}, ErrLeaseLost
	}
	return s.markSucceededLocked(operation, result)
}

func sameLease(actual, claimed Lease) bool {
	return actual.Owner == claimed.Owner && actual.Version == claimed.Version
}

func (s *MemoryStore) EnqueueCreate(command provisioner.CreateWorkloadCommand, maxAttempts int) (Operation, bool, error) {
	s.mu.Lock()
	operation, created, err := s.enqueueCreate(command, maxAttempts)
	s.mu.Unlock()
	if err != nil || !created {
		return operation, created, err
	}
	s.notify()
	return operation, true, nil
}

func (s *MemoryStore) EnqueueDelete(command provisioner.DeleteWorkloadCommand, maxAttempts int) (Operation, bool, error) {
	s.mu.Lock()
	operation, created, err := s.enqueueDelete(command, maxAttempts)
	s.mu.Unlock()
	if err != nil || !created {
		return operation, created, err
	}
	s.notify()
	return operation, true, nil
}

func (s *MemoryStore) Next(ctx context.Context) (Operation, error) {
	for {
		s.mu.Lock()
		for len(s.queue) > 0 {
			id := s.queue[0]
			s.queue = s.queue[1:]
			operation, ok := s.operations[id]
			if ok && operation.Status == OperationStatusQueued {
				copy := copyOperation(*operation)
				hasQueuedOperation := s.hasQueuedOperation()
				s.mu.Unlock()
				if hasQueuedOperation {
					s.notify()
				}
				return copy, nil
			}
		}
		s.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return Operation{}, err
		}

		select {
		case <-ctx.Done():
			return Operation{}, ctx.Err()
		case <-s.notification:
		}
	}
}

func (s *MemoryStore) Get(id string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(id)
	if err != nil {
		return Operation{}, err
	}
	return copyOperation(*operation), nil
}

func (s *MemoryStore) GetByRequestID(requestID string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, found := s.operationForRequest(requestID)
	if !found {
		return Operation{}, ErrOperationNotFound
	}
	return copyOperation(*operation), nil
}

func (s *MemoryStore) MarkRunning(id string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(id)
	if err != nil {
		return Operation{}, err
	}
	if operation.Status != OperationStatusQueued && operation.Status != OperationStatusRetrying {
		return Operation{}, ErrInvalidTransition
	}
	if operation.Status == OperationStatusQueued {
		s.removeQueuedID(id)
	}
	operation.Status = OperationStatusRunning
	operation.Attempt++
	return copyOperation(*operation), nil
}

func (s *MemoryStore) CheckpointCreateResult(id string, result provisioner.CreateWorkloadResult) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(id)
	if err != nil {
		return Operation{}, err
	}
	if err := checkpointCreateResult(operation, result); err != nil {
		return Operation{}, err
	}
	return copyOperation(*operation), nil
}

func checkpointCreateResult(operation *Operation, result provisioner.CreateWorkloadResult) error {
	if operation.Status != OperationStatusRunning || operation.Type != OperationTypeCreate || operation.CreateCommand == nil {
		return ErrInvalidTransition
	}
	if !validCreateWorkloadResult(result) {
		return ErrInvalidOperationResult
	}
	if operation.CreateCheckpoint != nil {
		if !sameCreateWorkloadResult(*operation.CreateCheckpoint, result) {
			return ErrCreateCheckpointConflict
		}
		return nil
	}
	checkpoint := copyCreateWorkloadResult(result)
	operation.CreateCheckpoint = &checkpoint
	return nil
}

func (s *MemoryStore) MarkRetrying(id, errorCode string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(id)
	if err != nil {
		return Operation{}, err
	}
	if operation.Status != OperationStatusRunning {
		return Operation{}, ErrInvalidTransition
	}
	operation.Status = OperationStatusRetrying
	operation.LastErrorCode = normalizeStableErrorCode(errorCode)
	return copyOperation(*operation), nil
}

func (s *MemoryStore) Requeue(id string) error {
	s.mu.Lock()
	operation, err := s.find(id)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if operation.Status != OperationStatusQueued && operation.Status != OperationStatusRunning && operation.Status != OperationStatusRetrying {
		s.mu.Unlock()
		return ErrInvalidTransition
	}
	if operation.Status == OperationStatusRunning && operation.Attempt > 0 {
		operation.Attempt--
	}
	operation.Status = OperationStatusQueued
	shouldNotify := !s.hasQueuedID(id)
	if shouldNotify {
		s.queue = append(s.queue, id)
	}
	s.mu.Unlock()
	if shouldNotify {
		s.notify()
	}
	return nil
}

func (s *MemoryStore) MarkSucceeded(id string, result OperationResult) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(id)
	if err != nil {
		return Operation{}, err
	}
	return s.markSucceededLocked(operation, result)
}

func (s *MemoryStore) markSucceededLocked(operation *Operation, result OperationResult) (Operation, error) {
	if operation.Status != OperationStatusRunning {
		return Operation{}, ErrInvalidTransition
	}
	if !operationResultMatchesType(operation.Type, result) {
		return Operation{}, ErrInvalidOperationResult
	}
	if operation.Type == OperationTypeCreate {
		if operation.CreateCheckpoint == nil {
			return Operation{}, ErrInvalidTransition
		}
		if !sameCreateWorkloadResult(*operation.CreateCheckpoint, *result.Create) {
			return Operation{}, ErrCreateCheckpointConflict
		}
		checkpoint := copyCreateWorkloadResult(*operation.CreateCheckpoint)
		result.Create = &checkpoint
		operation.CreateCheckpoint = nil
	}
	operation.Status = OperationStatusSucceeded
	operation.Result = copyOperationResult(result)
	delete(s.leases, operation.ID)
	return copyOperation(*operation), nil
}

func (s *MemoryStore) MarkFailed(id, errorCode string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(id)
	if err != nil {
		return Operation{}, err
	}
	if operation.Status != OperationStatusRunning {
		return Operation{}, ErrInvalidTransition
	}
	operation.Status = OperationStatusFailed
	operation.LastErrorCode = normalizeStableErrorCode(errorCode)
	return copyOperation(*operation), nil
}

func (s *MemoryStore) enqueueCreate(command provisioner.CreateWorkloadCommand, maxAttempts int) (Operation, bool, error) {
	if existing, ok := s.operationForRequest(command.RequestID); ok {
		if existing.Type == OperationTypeCreate && existing.CreateCommand != nil && sameCreateCommand(*existing.CreateCommand, command) {
			return copyOperation(*existing), false, nil
		}
		return Operation{}, false, ErrIdempotencyConflict
	}
	id, err := s.idGenerator()
	if err != nil {
		return Operation{}, false, err
	}
	if _, exists := s.operations[id]; exists {
		return Operation{}, false, ErrOperationIDConflict
	}
	operation, err := NewCreateOperation(id, command, maxAttempts)
	if err != nil {
		return Operation{}, false, err
	}
	s.add(operation)
	return copyOperation(operation), true, nil
}

func (s *MemoryStore) enqueueDelete(command provisioner.DeleteWorkloadCommand, maxAttempts int) (Operation, bool, error) {
	if existing, ok := s.operationForRequest(command.RequestID); ok {
		if existing.Type == OperationTypeDelete && existing.DeleteCommand != nil && *existing.DeleteCommand == command {
			return copyOperation(*existing), false, nil
		}
		return Operation{}, false, ErrIdempotencyConflict
	}
	id, err := s.idGenerator()
	if err != nil {
		return Operation{}, false, err
	}
	if _, exists := s.operations[id]; exists {
		return Operation{}, false, ErrOperationIDConflict
	}
	operation, err := NewDeleteOperation(id, command, maxAttempts)
	if err != nil {
		return Operation{}, false, err
	}
	s.add(operation)
	return copyOperation(operation), true, nil
}

func (s *MemoryStore) add(operation Operation) {
	stored := copyOperation(operation)
	s.operations[operation.ID] = &stored
	s.requestIDs[operation.RequestID] = operation.ID
	s.queue = append(s.queue, operation.ID)
}

func operationResultMatchesType(operationType OperationType, result OperationResult) bool {
	switch operationType {
	case OperationTypeCreate:
		return result.Create != nil && !result.DeleteCompleted
	case OperationTypeDelete:
		return result.Create == nil && result.DeleteCompleted
	default:
		return false
	}
}

func (s *MemoryStore) operationForRequest(requestID string) (*Operation, bool) {
	id, ok := s.requestIDs[requestID]
	if !ok {
		return nil, false
	}
	operation, ok := s.operations[id]
	return operation, ok
}

func (s *MemoryStore) find(id string) (*Operation, error) {
	operation, ok := s.operations[id]
	if !ok {
		return nil, ErrOperationNotFound
	}
	return operation, nil
}

func (s *MemoryStore) removeQueuedID(id string) {
	for index, queuedID := range s.queue {
		if queuedID == id {
			s.queue = append(s.queue[:index], s.queue[index+1:]...)
			return
		}
	}
}

func (s *MemoryStore) hasQueuedOperation() bool {
	for _, id := range s.queue {
		operation, ok := s.operations[id]
		if ok && operation.Status == OperationStatusQueued {
			return true
		}
	}
	return false
}

func (s *MemoryStore) hasQueuedID(id string) bool {
	for _, queuedID := range s.queue {
		if queuedID == id {
			return true
		}
	}
	return false
}

func (s *MemoryStore) notify() {
	select {
	case s.notification <- struct{}{}:
	default:
	}
}

func randomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func copyOperation(operation Operation) Operation {
	copy := operation
	if operation.CreateCommand != nil {
		command := copyCreateCommand(*operation.CreateCommand)
		copy.CreateCommand = &command
	}
	if operation.DeleteCommand != nil {
		command := *operation.DeleteCommand
		copy.DeleteCommand = &command
	}
	if operation.CreateCheckpoint != nil {
		checkpoint := copyCreateWorkloadResult(*operation.CreateCheckpoint)
		copy.CreateCheckpoint = &checkpoint
	}
	copy.Result = copyOperationResult(operation.Result)
	return copy
}

func copyOperationResult(result OperationResult) OperationResult {
	copy := result
	if result.Create != nil {
		create := copyCreateWorkloadResult(*result.Create)
		copy.Create = &create
	}
	return copy
}
