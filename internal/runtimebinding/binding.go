package runtimebinding

import (
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
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
	InstanceID            string
	TeamID                int64
	TargetID              string
	Namespace             string
	NamespaceUID          string
	RuntimeWorkloadID     string
	IsolationProfile      string
	WorkloadProfile       string
	ContainerRequirements []isolation.ContainerRequirement
	InternalConnections   []isolation.InternalConnection
	OutboundMode          isolation.OutboundMode
	ResourceLimits        isolation.ResourceLimits
	State                 State
	CreatedAt             time.Time
	UpdatedAt             time.Time
	DeletedAt             *time.Time
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
		strings.TrimSpace(binding.NamespaceUID) != "" &&
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
		first.NamespaceUID == second.NamespaceUID &&
		first.RuntimeWorkloadID == second.RuntimeWorkloadID &&
		first.IsolationProfile == second.IsolationProfile &&
		first.WorkloadProfile == second.WorkloadProfile &&
		reflect.DeepEqual(first.ContainerRequirements, second.ContainerRequirements) &&
		reflect.DeepEqual(first.InternalConnections, second.InternalConnections) &&
		first.OutboundMode == second.OutboundMode &&
		first.ResourceLimits == second.ResourceLimits
}

func copyBinding(binding Binding) Binding {
	copied := binding
	if binding.ContainerRequirements != nil {
		copied.ContainerRequirements = make([]isolation.ContainerRequirement, len(binding.ContainerRequirements))
		for index, requirement := range binding.ContainerRequirements {
			copied.ContainerRequirements[index] = requirement
			if requirement.Ports != nil {
				copied.ContainerRequirements[index].Ports = append([]int{}, requirement.Ports...)
			}
			if requirement.WritablePaths != nil {
				copied.ContainerRequirements[index].WritablePaths = append([]isolation.WritablePath{}, requirement.WritablePaths...)
			}
		}
	}
	if binding.InternalConnections != nil {
		copied.InternalConnections = append([]isolation.InternalConnection{}, binding.InternalConnections...)
	}
	if binding.DeletedAt != nil {
		deletedAt := *binding.DeletedAt
		copied.DeletedAt = &deletedAt
	}
	return copied
}
