package windowsruntime

import (
	"context"
	"errors"
)

var ErrTargetDiscoveryUnavailable = errors.New("Windows target discovery unavailable")

func (s *Service) ListTargets(ctx context.Context, limit int, after string) (VMPage, error) {
	source, ok := s.broker.(interface {
		List(context.Context, int, string) (VMPage, error)
	})
	if !ok {
		return VMPage{}, ErrTargetDiscoveryUnavailable
	}
	return source.List(ctx, limit, after)
}

func (s *Service) TargetConnection(ctx context.Context, id string) (Connection, error) {
	if !ValidID(id) {
		return Connection{}, &APIError{Code: "BROKER_INVALID_REQUEST"}
	}
	return s.broker.Connection(ctx, id)
}
