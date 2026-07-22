package operations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type MemoryStore struct {
	mu           sync.Mutex
	operations   map[string]*Operation
	requestIDs   map[string]string
	queue        []string
	notification chan struct{}
	idGenerator  IDGenerator
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
	}
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
				s.mu.Unlock()
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
	operation.LastErrorCode = errorCode
	return copyOperation(*operation), nil
}

func (s *MemoryStore) Requeue(id string) error {
	s.mu.Lock()
	operation, err := s.find(id)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if operation.Status != OperationStatusRunning && operation.Status != OperationStatusRetrying {
		s.mu.Unlock()
		return ErrInvalidTransition
	}
	operation.Status = OperationStatusQueued
	s.queue = append(s.queue, id)
	s.mu.Unlock()
	s.notify()
	return nil
}

func (s *MemoryStore) MarkSucceeded(id string, result OperationResult) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := s.find(id)
	if err != nil {
		return Operation{}, err
	}
	if operation.Status != OperationStatusRunning {
		return Operation{}, ErrInvalidTransition
	}
	operation.Status = OperationStatusSucceeded
	operation.Result = copyOperationResult(result)
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
	operation.LastErrorCode = errorCode
	return copyOperation(*operation), nil
}

func (s *MemoryStore) enqueueCreate(command provisioner.CreateWorkloadCommand, maxAttempts int) (Operation, bool, error) {
	if existing, ok := s.operationForRequest(command.RequestID); ok {
		if existing.Type == OperationTypeCreate && existing.CreateCommand != nil && *existing.CreateCommand == command {
			return copyOperation(*existing), false, nil
		}
		return Operation{}, false, ErrIdempotencyConflict
	}
	id, err := s.idGenerator()
	if err != nil {
		return Operation{}, false, err
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
		command := *operation.CreateCommand
		copy.CreateCommand = &command
	}
	if operation.DeleteCommand != nil {
		command := *operation.DeleteCommand
		copy.DeleteCommand = &command
	}
	copy.Result = copyOperationResult(operation.Result)
	return copy
}

func copyOperationResult(result OperationResult) OperationResult {
	copy := result
	if result.Create != nil {
		create := *result.Create
		copy.Create = &create
	}
	return copy
}
