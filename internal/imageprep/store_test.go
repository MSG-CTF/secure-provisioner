package imageprep

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"sync"
	"time"
)

// Test persistence implements the same copy/fencing boundaries as PostgreSQL.
type MemoryStore struct {
	mu           sync.Mutex
	records      map[string]Record
	observations map[string]Observation
	locks        map[string]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]Record{}, observations: map[string]Observation{}, locks: map[string]Record{}}
}
func clone[T any](v T) T { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
func (s *MemoryStore) Find(_ context.Context, scope, endpoint, id string) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.Scope == scope && r.Endpoint == endpoint && r.Operation.RequestID == id {
			return clone(r), true, nil
		}
	}
	return Record{}, false, nil
}
func (s *MemoryStore) Insert(ctx context.Context, r Record) (Record, error) {
	if old, found, _ := s.Find(ctx, r.Scope, r.Endpoint, r.Operation.RequestID); found {
		if old.Fingerprint != r.Fingerprint {
			return Record{}, ErrConflict
		}
		return old, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[r.Operation.ID] = clone(r)
	return clone(r), nil
}
func (s *MemoryStore) Get(_ context.Context, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return clone(r), nil
}
func (s *MemoryStore) Claim(_ context.Context, now time.Time, d time.Duration) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.records {
		if (r.Operation.Status == "QUEUED" || r.Operation.Status == "RUNNING") && !r.Next.After(now) && !r.LeaseUntil.After(now) {
			r.Lease = uuid.NewString()
			r.LeaseUntil = now.Add(d)
			s.records[id] = clone(r)
			return clone(r), true, nil
		}
	}
	return Record{}, false, nil
}
func (s *MemoryStore) Save(_ context.Context, r Record, release bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records[r.Operation.ID].Lease != r.Lease {
		return ErrLeaseLost
	}
	if release {
		r.Lease = ""
		r.LeaseUntil = time.Time{}
	}
	s.records[r.Operation.ID] = clone(r)
	return nil
}
func (s *MemoryStore) Watch(_ context.Context) ([]Query, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []Query{}
	seen := map[string]bool{}
	for _, r := range s.records {
		q := Query{Architecture: r.Request.Architecture, Images: r.Request.Images(), TargetIDs: r.Request.TargetIDs}
		key := fingerprint(q)
		if !seen[key] {
			result = append(result, clone(q))
			seen[key] = true
		}
	}
	return result, nil
}
func (s *MemoryStore) PutObservation(_ context.Context, o Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observations[o.TargetID+o.ImageSetID] = clone(o)
	return nil
}
func (s *MemoryStore) Observation(_ context.Context, target, id string) (Observation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.observations[target+id]
	return clone(o), ok, nil
}
func (s *MemoryStore) LockNode(_ context.Context, node, owner string, now time.Time, d time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks[node].LeaseUntil.After(now) {
		return false, nil
	}
	s.locks[node] = Record{Lease: owner, LeaseUntil: now.Add(d)}
	return true, nil
}
func (s *MemoryStore) UnlockNode(_ context.Context, node, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks[node].Lease == owner {
		delete(s.locks, node)
	}
	return nil
}
