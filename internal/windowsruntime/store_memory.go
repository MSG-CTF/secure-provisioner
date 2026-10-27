package windowsruntime

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

const maxStoredPayload = 10 * 1024 * 1024

type MemoryStore struct {
	mu       sync.Mutex
	records  map[string]Record
	requests map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record), requests: make(map[string]string)}
}

func validateStoredRecord(record Record) error {
	if !ValidID(record.ID) || !ValidID(record.RequestID) || !ValidID(record.TargetID) || record.Fingerprint == "" || len(record.Payload) > maxStoredPayload {
		return errors.New("invalid windows execution record")
	}
	return nil
}

func cloneRecord(record Record) Record {
	record.Payload = append([]byte(nil), record.Payload...)
	if record.Checker != nil {
		checker := *record.Checker
		checker.ResultBody = append([]byte(nil), record.Checker.ResultBody...)
		if record.Checker.Request != nil {
			request := *record.Checker.Request
			checker.Request = &request
		}
		record.Checker = &checker
	}
	record.StartedBody = append([]byte(nil), record.StartedBody...)
	record.FinishedBody = append([]byte(nil), record.FinishedBody...)
	if record.Connection != nil {
		connection := *record.Connection
		record.Connection = &connection
	}
	if record.Outcome != nil {
		outcome := *record.Outcome
		if outcome.Started != nil {
			started := *outcome.Started
			outcome.Started = &started
		}
		if outcome.StartedAt != nil {
			startedAt := *outcome.StartedAt
			outcome.StartedAt = &startedAt
		}
		if outcome.ExitCode != nil {
			code := *outcome.ExitCode
			outcome.ExitCode = &code
		}
		record.Outcome = &outcome
	}
	return record
}

func (store *MemoryStore) Submit(ctx context.Context, record Record) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	if err := validateStoredRecord(record); err != nil {
		return Record{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if id, exists := store.requests[record.RequestID]; exists {
		original := store.records[id]
		if original.TargetID != record.TargetID && !(record.TargetID == UnboundTargetID && original.Checker != nil && original.Checker.Request != nil && original.Checker.Request.SelectionMode == "broker_pool") || original.Fingerprint != record.Fingerprint {
			return Record{}, false, ErrConflict
		}
		return cloneRecord(original), false, nil
	}
	if _, exists := store.records[record.ID]; exists {
		return Record{}, false, ErrConflict
	}
	store.records[record.ID] = cloneRecord(record)
	store.requests[record.RequestID] = record.ID
	return cloneRecord(record), true, nil
}

func (store *MemoryStore) Get(ctx context.Context, id string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[id]
	if !exists {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (store *MemoryStore) GetByRequest(ctx context.Context, requestID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	id, exists := store.requests[requestID]
	if !exists {
		return Record{}, ErrNotFound
	}
	return cloneRecord(store.records[id]), nil
}

func claimable(record Record, now time.Time) bool {
	if record.NextAttempt.After(now) || (record.Owner != "" && record.LeaseUntil.After(now)) {
		return false
	}
	switch record.Phase {
	case "FETCH_PENDING", "QUEUED", "START_PENDING", "APPROVED", "CONNECTING", "RUNNING":
		return true
	case "FINISHED", "REJECTED":
		return record.BrokerPending || record.Checker != nil && record.Checker.ResultPending
	default:
		return false
	}
}

func occupiesVM(record Record, now time.Time) bool {
	if record.BrokerPending || (record.Owner != "" && record.LeaseUntil.After(now)) {
		return true
	}
	switch record.Phase {
	case "START_PENDING", "APPROVED", "CONNECTING", "RUNNING", "BLOCKED":
		return true
	default:
		return false
	}
}

func (store *MemoryStore) Claim(ctx context.Context, owner string, lease time.Duration) (*Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == "" || lease <= 0 {
		return nil, errors.New("windows execution claim requires an owner and positive lease")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := time.Now().UTC()
	candidates := make([]Record, 0, len(store.records))
	for _, record := range store.records {
		if claimable(record, now) {
			candidates = append(candidates, record)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CreatedAt.Equal(candidates[j].CreatedAt) {
			return candidates[i].ID < candidates[j].ID
		}
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})
	for _, candidate := range candidates {
		busy := false
		for id, other := range store.records {
			if candidate.TargetID != UnboundTargetID && id != candidate.ID && other.TargetID == candidate.TargetID && occupiesVM(other, now) {
				busy = true
				break
			}
		}
		if busy {
			continue
		}
		candidate.Owner = owner
		candidate.LeaseUntil = now.Add(lease)
		candidate.Attempt++
		candidate.UpdatedAt = now
		store.records[candidate.ID] = cloneRecord(candidate)
		copied := cloneRecord(candidate)
		return &copied, nil
	}
	return nil, nil
}

func (store *MemoryStore) BindTarget(ctx context.Context, id, owner, targetID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !ValidID(id) || owner == "" || !ValidID(targetID) || targetID == UnboundTargetID {
		return false, ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := time.Now().UTC()
	record, ok := store.records[id]
	if !ok || record.Owner != owner || !record.LeaseUntil.After(now) || record.Phase != "QUEUED" || record.TargetID != UnboundTargetID {
		return false, ErrLeaseLost
	}
	for otherID, other := range store.records {
		if otherID != id && other.TargetID == targetID && (occupiesVM(other, now) || other.Phase == "QUEUED" || other.Phase == "FETCH_PENDING") {
			return false, nil
		}
	}
	record.TargetID = targetID
	record.UpdatedAt = now
	store.records[id] = cloneRecord(record)
	return true, nil
}

func (store *MemoryStore) Save(ctx context.Context, record Record, expectedOwner string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.records[record.ID]
	if !exists || expectedOwner == "" || current.Owner != expectedOwner || !current.LeaseUntil.After(time.Now()) || current.Attempt != record.Attempt || (record.Owner != "" && record.Owner != expectedOwner) {
		return ErrLeaseLost
	}
	if record.RequestID != current.RequestID || record.TargetID != current.TargetID || record.Fingerprint != current.Fingerprint {
		return ErrConflict
	}
	if err := validateStoredRecord(record); err != nil {
		return err
	}
	record.LeaseUntil = current.LeaseUntil
	if record.Owner == "" {
		record.LeaseUntil = time.Time{}
	}
	store.records[record.ID] = cloneRecord(record)
	return nil
}

func (store *MemoryStore) Renew(ctx context.Context, id, owner string, lease time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.records[id]
	now := time.Now().UTC()
	if !exists || owner == "" || lease <= 0 || current.Owner != owner || !current.LeaseUntil.After(now) {
		return ErrLeaseLost
	}
	current.LeaseUntil = now.Add(lease)
	current.UpdatedAt = now
	store.records[id] = current
	return nil
}
