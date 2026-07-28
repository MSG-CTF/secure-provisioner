package runtimebinding

import (
	"errors"
	"strings"
	"time"
)

type State string

const (
	StateCreated  State = "CREATED"
	StateDeleting State = "DELETING"
	StateDeleted  State = "DELETED"
)

var (
	ErrNotFound          = errors.New("runtime binding not found")
	ErrConflict          = errors.New("runtime binding conflict")
	ErrInvalidBinding    = errors.New("invalid runtime binding")
	ErrInvalidTransition = errors.New("invalid runtime binding transition")
)

type Binding struct {
	InstanceID        string
	TeamID            int64
	TargetID          string
	Namespace         string
	RuntimeWorkloadID string
	State             State
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         *time.Time
}

type Store interface {
	SaveCreated(Binding) (Binding, bool, error)
	Get(string) (Binding, error)
	MarkDeleting(string, time.Time) (Binding, error)
	RestoreCreated(string, time.Time) (Binding, error)
	MarkDeleted(string, time.Time) (Binding, error)
}

func validCreatedBinding(binding Binding) bool {
	return strings.TrimSpace(binding.InstanceID) != "" &&
		binding.TeamID > 0 &&
		strings.TrimSpace(binding.TargetID) != "" &&
		strings.TrimSpace(binding.Namespace) != "" &&
		strings.TrimSpace(binding.RuntimeWorkloadID) != "" &&
		binding.State == StateCreated &&
		!binding.CreatedAt.IsZero() &&
		!binding.UpdatedAt.IsZero() &&
		binding.DeletedAt == nil
}

func samePlacement(first, second Binding) bool {
	return first.InstanceID == second.InstanceID &&
		first.TeamID == second.TeamID &&
		first.TargetID == second.TargetID &&
		first.Namespace == second.Namespace &&
		first.RuntimeWorkloadID == second.RuntimeWorkloadID
}

func copyBinding(binding Binding) Binding {
	copied := binding
	if binding.DeletedAt != nil {
		deletedAt := *binding.DeletedAt
		copied.DeletedAt = &deletedAt
	}
	return copied
}
