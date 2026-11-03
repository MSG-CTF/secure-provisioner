package windowsruntime

import (
	"context"
	"sort"
	"time"
)

type memoryRecoveryLease struct {
	owner       string
	until       time.Time
	nextAttempt time.Time
}

func (store *MemoryStore) ConfirmRecovery(ctx context.Context, targetID, executionID, eventID string) (RecoveryReceipt, error) {
	if err := ctx.Err(); err != nil {
		return RecoveryReceipt{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[executionID]
	if !exists {
		return RecoveryReceipt{}, ErrNotFound
	}
	if record.TargetID != targetID {
		return RecoveryReceipt{}, ErrConflict
	}
	if !validRecoveryRecord(record, targetID) {
		return RecoveryReceipt{}, ErrRecoveryNotReady
	}
	if record.Checker.ResultEventID == eventID {
		return RecoveryReceipt{}, ErrConflict
	}
	if previous, exists := store.recovery[executionID]; exists {
		if previous.EventID != eventID {
			return RecoveryReceipt{}, ErrConflict
		}
		previous.Replayed = true
		return previous, nil
	}
	for _, previous := range store.recovery {
		if previous.EventID == eventID {
			return RecoveryReceipt{}, ErrConflict
		}
	}
	receipt := RecoveryReceipt{TargetID: targetID, ExecutionID: executionID, EventID: eventID,
		VMState: "READY", CleanupDelivery: "PENDING", RecoveredAt: time.Now().UTC()}
	store.recovery[executionID] = receipt
	return receipt, nil
}

func (store *MemoryStore) ClaimRecovery(ctx context.Context, owner string, lease time.Duration) (*RecoveryDelivery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == "" || lease <= 0 {
		return nil, ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := time.Now().UTC()
	ids := make([]string, 0, len(store.recovery))
	for id := range store.recovery {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := store.recovery[ids[i]], store.recovery[ids[j]]
		if a.RecoveredAt.Equal(b.RecoveredAt) {
			return ids[i] < ids[j]
		}
		return a.RecoveredAt.Before(b.RecoveredAt)
	})
	for _, id := range ids {
		receipt := store.recovery[id]
		claim := store.recoveryLeases[id]
		record := store.records[id]
		if receipt.CleanupDelivery != "PENDING" || claim.until.After(now) || claim.nextAttempt.After(now) || !recoveryResultDelivered(record) {
			continue
		}
		claim.owner, claim.until = owner, now.Add(lease)
		store.recoveryLeases[id] = claim
		return &RecoveryDelivery{Receipt: receipt, Record: cloneRecord(record)}, nil
	}
	return nil, nil
}

func (store *MemoryStore) CompleteRecovery(ctx context.Context, executionID, owner string, delivered bool, retryAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	claim := store.recoveryLeases[executionID]
	if owner == "" || claim.owner != owner || !claim.until.After(time.Now().UTC()) {
		return ErrLeaseLost
	}
	receipt := store.recovery[executionID]
	if delivered {
		receipt.CleanupDelivery = "CONFIRMED"
		store.recovery[executionID] = receipt
	}
	claim.owner, claim.until, claim.nextAttempt = "", time.Time{}, retryAt
	store.recoveryLeases[executionID] = claim
	return nil
}
