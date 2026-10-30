package windowsruntime

import (
	"context"
	"errors"
	"time"
)

var ErrRecoveryNotReady = errors.New("Windows recovery requires a finished Broker execution")
var ErrRecoveryUnavailable = errors.New("Windows recovery store unavailable")

// RecoveryReceipt acknowledges a durable report from the authenticated image
// recovery controller. PENDING means Backend CLEANUP has not been delivered.
type RecoveryReceipt struct {
	TargetID        string    `json:"resource_target_id"`
	ExecutionID     string    `json:"execution_id"`
	EventID         string    `json:"event_id"`
	VMState         string    `json:"vm_state"`
	CleanupDelivery string    `json:"cleanup_delivery"`
	RecoveredAt     time.Time `json:"recovered_at"`
	Replayed        bool      `json:"replayed"`
}

type recoveryStore interface {
	ConfirmRecovery(context.Context, string, string, string) (RecoveryReceipt, error)
}

type RecoveryDelivery struct {
	Receipt RecoveryReceipt
	Record  Record
}

type recoveryDeliveryStore interface {
	ClaimRecovery(context.Context, string, time.Duration) (*RecoveryDelivery, error)
	CompleteRecovery(context.Context, string, string, bool, time.Time) error
}

func recoveryResultDelivered(record Record) bool {
	return validRecoveryRecord(record, record.TargetID) && record.Checker.ResultEventID != "" && !record.Checker.ResultPending
}

func (s *Service) ConfirmRecovery(ctx context.Context, targetID, executionID, eventID string) (RecoveryReceipt, error) {
	if !ValidID(targetID) || !ValidID(executionID) || !ValidID(eventID) {
		return RecoveryReceipt{}, ErrInvalidSubmission
	}
	store, ok := s.store.(recoveryStore)
	if !ok {
		return RecoveryReceipt{}, ErrRecoveryUnavailable
	}
	return store.ConfirmRecovery(ctx, targetID, executionID, eventID)
}

func validRecoveryRecord(record Record, targetID string) bool {
	return record.TargetID == targetID && record.Phase == "FINISHED" && !record.BrokerPending &&
		record.Checker != nil && record.Checker.Request != nil && record.Checker.Request.SelectionMode == "broker_pool"
}
