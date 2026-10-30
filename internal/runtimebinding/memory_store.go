package runtimebinding

import (
	"strings"
	"sync"
	"time"
)

type MemoryStore struct {
	mu       sync.RWMutex
	bindings map[string]Binding
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{bindings: make(map[string]Binding)}
}

func (s *MemoryStore) SaveCreated(binding Binding) (Binding, bool, error) {
	if !validCreatedBinding(binding) {
		return Binding{}, false, ErrInvalidBinding
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, found := s.bindings[binding.InstanceID]
	if found {
		if !samePlacement(existing, binding) {
			return Binding{}, false, ErrConflict
		}
		if existing.State != StateCreated {
			return Binding{}, false, ErrInvalidTransition
		}
		return copyBinding(existing), false, nil
	}
	stored := copyBinding(binding)
	s.bindings[binding.InstanceID] = stored
	return copyBinding(stored), true, nil
}

func (s *MemoryStore) Get(instanceID string) (Binding, error) {
	if strings.TrimSpace(instanceID) == "" {
		return Binding{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	binding, found := s.bindings[instanceID]
	if !found {
		return Binding{}, ErrNotFound
	}
	return copyBinding(binding), nil
}

func (s *MemoryStore) MarkDeleting(instanceID string, updatedAt time.Time) (Binding, error) {
	if updatedAt.IsZero() {
		return Binding{}, ErrInvalidTransition
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, found := s.bindings[instanceID]
	if !found {
		return Binding{}, ErrNotFound
	}
	switch binding.State {
	case StateCreated:
		binding.State = StateDeleting
		binding.UpdatedAt = updatedAt
		s.bindings[instanceID] = binding
	case StateDeleting:
	default:
		return Binding{}, ErrInvalidTransition
	}
	return copyBinding(binding), nil
}

func (s *MemoryStore) RestoreCreated(instanceID string, updatedAt time.Time) (Binding, error) {
	if updatedAt.IsZero() {
		return Binding{}, ErrInvalidTransition
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, found := s.bindings[instanceID]
	if !found {
		return Binding{}, ErrNotFound
	}
	switch binding.State {
	case StateDeleting:
		binding.State = StateCreated
		binding.UpdatedAt = updatedAt
		binding.DeletedAt = nil
		s.bindings[instanceID] = binding
	case StateCreated:
	default:
		return Binding{}, ErrInvalidTransition
	}
	return copyBinding(binding), nil
}

func (s *MemoryStore) MarkDeleted(instanceID string, deletedAt time.Time) (Binding, error) {
	if deletedAt.IsZero() {
		return Binding{}, ErrInvalidTransition
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, found := s.bindings[instanceID]
	if !found {
		return Binding{}, ErrNotFound
	}
	switch binding.State {
	case StateDeleting:
		binding.State = StateDeleted
		binding.UpdatedAt = deletedAt
		binding.DeletedAt = &deletedAt
		s.bindings[instanceID] = binding
	case StateDeleted:
	default:
		return Binding{}, ErrInvalidTransition
	}
	return copyBinding(binding), nil
}
