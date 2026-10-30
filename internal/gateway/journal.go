package gateway

import (
	"context"
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"time"
)

var ErrNotFound = errors.New("Gateway intent not found")
var ErrConflict = errors.New("Gateway intent identity conflict")
var ErrUpstreamIdentity = errors.New("Gateway upstream identity lost")

type Phase string

const (
	PhaseApplyPending  Phase = "APPLY_PENDING"
	PhaseApplied       Phase = "APPLIED"
	PhaseDeletePending Phase = "DELETE_PENDING"
	PhaseRouteDeleted  Phase = "ROUTE_DELETED"
	PhaseDeleted       Phase = "DELETED"
	PhaseConflictHold  Phase = "CONFLICT_HOLD"
)

type Record struct {
	Command     provisioner.CreateWorkloadCommand
	Result      provisioner.CreateWorkloadResult
	OperationID string
	Destination Destination
	ServiceUID  string
	Phase       Phase
	Route       Route
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
type Session interface {
	Load() (Record, error)
	Save(Record) error
}

// WithLock must serialize all mutations for one instance across processes.
// Save must commit before returning, including while this lock remains held.
type Journal interface {
	WithLock(context.Context, string, func(Session) error) error
	Get(context.Context, string) (Record, error)
	HasPendingCleanup(context.Context, string) (bool, error)
}
