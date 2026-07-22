package k3s

import (
	"context"
	"sync"
)

type workloadLockSet struct {
	mu      sync.Mutex
	entries map[workloadKey]*workloadLockEntry
}

type workloadKey struct {
	targetID   string
	instanceID string
}

type workloadLockEntry struct {
	token chan struct{}
	refs  int
}

func newWorkloadLockSet() *workloadLockSet {
	return &workloadLockSet{entries: make(map[workloadKey]*workloadLockEntry)}
}

func workloadLockKey(targetID, instanceID string) workloadKey {
	return workloadKey{targetID: targetID, instanceID: instanceID}
}

func (s *workloadLockSet) acquire(ctx context.Context, key workloadKey) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	entry := s.entries[key]
	if entry == nil {
		entry = &workloadLockEntry{token: make(chan struct{}, 1)}
		entry.token <- struct{}{}
		s.entries[key] = entry
	}
	entry.refs++
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		s.releaseRef(key, entry)
		return nil, ctx.Err()
	case <-entry.token:
		if err := ctx.Err(); err != nil {
			entry.token <- struct{}{}
			s.releaseRef(key, entry)
			return nil, err
		}
		var once sync.Once
		return func() {
			once.Do(func() {
				entry.token <- struct{}{}
				s.releaseRef(key, entry)
			})
		}, nil
	}
}

func (s *workloadLockSet) releaseRef(key workloadKey, entry *workloadLockEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry.refs--
	if entry.refs == 0 && s.entries[key] == entry {
		delete(s.entries, key)
	}
}
