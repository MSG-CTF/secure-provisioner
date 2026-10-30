package imageprep

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type interruptedStore struct {
	Store
	calls atomic.Int32
}

func (s *interruptedStore) Claim(ctx context.Context, now time.Time, d time.Duration) (Record, bool, error) {
	if s.calls.Add(1) == 1 {
		return Record{}, false, errors.New("temporary observation database error")
	}
	return s.Store.Claim(ctx, now, d)
}
func TestPreparationWorkerRecoversStoreFailureWithoutStoppingRuntime(t *testing.T) {
	s, store, _, _, _ := fixture(t)
	s.Config.Concurrency = 1
	s.Store = &interruptedStore{Store: store}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	op, err := s.Create(ctx, "backend", testRequest())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	for {
		select {
		case err := <-done:
			t.Fatalf("preparation failure stopped runtime: %v", err)
		case <-ctx.Done():
			t.Fatal("worker never recovered")
		case <-time.After(20 * time.Millisecond):
			current, err := s.Get(ctx, "backend", op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.Status == "SUCCEEDED" {
				cancel()
				<-done
				return
			}
		}
	}
}
