package windowsruntime

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"
)

// Polling queue state must not load or clone a submitted 10 MiB executable.
func (store *MemoryStore) GetMetadataByRequest(ctx context.Context, requestID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	id, exists := store.requests[requestID]
	if !exists {
		return Record{}, ErrNotFound
	}
	record := store.records[id]
	record.Payload = nil
	return cloneRecord(record), nil
}

func (store *PostgresStore) GetMetadataByRequest(ctx context.Context, requestID string) (Record, error) {
	const metadataSelect = `SELECT execution_id::text,request_id::text,target_id::text,
 fingerprint,phase,finished_pending,record_json,''::bytea,attempt,
 lease_owner,lease_until,next_attempt,created_at,updated_at
 FROM runtime_windows_executions WHERE request_id=$1`
	record, err := scanWindowsRecord(store.db.QueryRowContext(ctx, metadataSelect, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, storageError(ctx)
	}
	return record, nil
}

type queuedTeam struct {
	id, backend, team string
	createdAt         time.Time
}

func pendingTeam(record Record) (queuedTeam, bool) {
	if record.TargetID != UnboundTargetID || (record.Phase != "FETCH_PENDING" && record.Phase != "QUEUED") || record.Checker == nil || record.Checker.Request == nil || record.Checker.Request.SelectionMode != "broker_pool" || !ValidID(record.Checker.Request.TeamID) {
		return queuedTeam{}, false
	}
	backend := record.Checker.BackendID
	if backend == "" {
		backend = "default"
	}
	return queuedTeam{record.ID, backend, record.Checker.Request.TeamID, record.CreatedAt}, true
}

// Each Backend admits at most one outstanding Windows request per team. Rank
// distinct teams in the same FIFO order used by Claim, without exposing IDs.
func teamQueuePosition(entries []queuedTeam, executionID string) int {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].createdAt.Equal(entries[j].createdAt) {
			return entries[i].id < entries[j].id
		}
		return entries[i].createdAt.Before(entries[j].createdAt)
	})
	positions := map[string]int{}
	for _, entry := range entries {
		key := entry.backend + ":" + entry.team
		position, exists := positions[key]
		if !exists {
			position = len(positions) + 1
			positions[key] = position
		}
		if entry.id == executionID {
			return position
		}
	}
	return 0
}

func (s *Service) withQueueState(ctx context.Context, record Record) Record {
	record.QueueState, record.QueuePosition = "", nil
	if record.Checker == nil || record.Checker.Request == nil || record.Checker.Request.SelectionMode != "broker_pool" {
		return record
	}
	switch record.Phase {
	case "FETCH_PENDING", "QUEUED":
		if record.TargetID == UnboundTargetID {
			record.QueueState = "QUEUED"
		} else {
			record.QueueState = "PREPARING"
		}
	case "START_PENDING", "APPROVED", "CONNECTING":
		record.QueueState = "PREPARING"
	case "RUNNING":
		record.QueueState = "RUNNING"
	}
	if record.QueueState == "QUEUED" {
		if reader, ok := s.store.(interface {
			QueuePosition(context.Context, string) (int, error)
		}); ok {
			if position, err := reader.QueuePosition(ctx, record.ID); err == nil && position > 0 {
				record.QueuePosition = &position
			}
		}
	}
	return record
}

func (store *MemoryStore) QueuePosition(ctx context.Context, executionID string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entries := make([]queuedTeam, 0)
	for _, record := range store.records {
		if entry, ok := pendingTeam(record); ok {
			entries = append(entries, entry)
		}
	}
	return teamQueuePosition(entries, executionID), nil
}

func (store *PostgresStore) QueuePosition(ctx context.Context, executionID string) (int, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT execution_id::text,
 COALESCE(NULLIF(record_json#>>'{checker,backend_id}',''),'default'),
 COALESCE(record_json#>>'{checker,request,team_id}',''),created_at
 FROM runtime_windows_executions WHERE target_id=$1
 AND phase IN ('FETCH_PENDING','QUEUED')
 AND record_json#>>'{checker,request,selection_mode}'='broker_pool'
 ORDER BY created_at,execution_id`, UnboundTargetID)
	if err != nil {
		return 0, storageError(ctx)
	}
	defer rows.Close()
	entries := make([]queuedTeam, 0)
	for rows.Next() {
		var entry queuedTeam
		if err := rows.Scan(&entry.id, &entry.backend, &entry.team, &entry.createdAt); err != nil {
			return 0, storageError(ctx)
		}
		if ValidID(entry.team) {
			entries = append(entries, entry)
		}
	}
	if rows.Err() != nil {
		return 0, storageError(ctx)
	}
	return teamQueuePosition(entries, executionID), nil
}
