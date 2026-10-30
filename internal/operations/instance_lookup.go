package operations

// Multiple creates with one instance identity are ambiguous. Cleanup must not
// guess which namespace generation belongs to the failed attempt.
func (s *MemoryStore) GetCreateByInstance(instanceID string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found *Operation
	for _, op := range s.operations {
		if op.Type != OperationTypeCreate || op.CreateCommand == nil || op.CreateCommand.InstanceID != instanceID {
			continue
		}
		if found != nil {
			return Operation{}, ErrIdempotencyConflict
		}
		found = op
	}
	if found == nil {
		return Operation{}, ErrOperationNotFound
	}
	return copyOperation(*found), nil
}
