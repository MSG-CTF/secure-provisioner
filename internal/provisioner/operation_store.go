package provisioner

import (
	"context"
	"time"
)

const (
	createPriority = 10
	deletePriority = 100
)

type ClaimOptions struct {
	WorkerID      string
	Now           time.Time
	LeaseDuration time.Duration
}

type operationStore interface {
	acceptCreate(context.Context, CreateRequest, time.Time) (Operation, Instance, bool, error)
	acceptDelete(context.Context, string, string, time.Time) (Operation, Instance, bool, error)
	claim(context.Context, ClaimOptions) (Operation, bool, error)
	retryOperation(string, string, time.Time, string, time.Time) error
	renewLease(string, string, time.Time) error
	getInstance(string) (Instance, error)
	getOperation(string) (Operation, bool)
	incrementAttempt(string, time.Time)
	finishOperation(string, string, OperationStatus, string, time.Time) error
	updateInstance(string, func(*Instance), time.Time) (Instance, error)
	expiredInstances(time.Time) []string
	close() error
}
