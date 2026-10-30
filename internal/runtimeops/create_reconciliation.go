package runtimeops

import (
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func (s *Service) ReconcileCreate(command provisioner.CreateWorkloadCommand) (operations.Operation, bool, error) {
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	reconciler, ok := s.operations.(operations.CreateReconciler)
	if !ok {
		return operations.Operation{}, false, errors.New("operation store does not support create reconciliation")
	}
	// Do not apply current image policy, resolve secrets, or enqueue a new create.
	// The original input fingerprint identifies an accepted request independently
	// of policy changes; an unaccepted request becomes a durable terminal fence.
	return reconciler.ReconcileCreate(command, s.maxAttempts)
}
