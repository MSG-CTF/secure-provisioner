package k3s

import (
	"context"
	"errors"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (a *Adapter) CleanupFailedCreate(ctx context.Context, command provisioner.CreateWorkloadCommand, cleanup provisioner.CreateCleanup) error {
	if cleanup.NamespaceUID == "" {
		return newRuntimeError("RUNTIME_IDENTITY_MISMATCH", false, nil)
	}
	unlock, err := a.workloadLocks.acquire(ctx, workloadLockKey(command.TargetID, command.InstanceID))
	if err != nil {
		return provisioner.WithCreateCleanupPending(operationCancelledError(err), cleanup)
	}
	defer unlock()
	cluster, err := a.registry.Lookup(command.TargetID)
	if err == nil {
		var namespace string
		namespace, err = NamespaceForInstance(command.InstanceID)
		if err == nil {
			desired := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace,
				UID: types.UID(cleanup.NamespaceUID), Labels: ownershipLabels(command)}}
			cleanupCtx, cancel := context.WithTimeout(ctx, a.config.RollbackTimeout)
			defer cancel()
			err = rollbackNamespace(cleanupCtx, cluster.Client, desired, a.config.PollInterval)
		}
	}
	if err != nil {
		return provisioner.WithCreateCleanupPending(newRuntimeError("ROLLBACK_FAILED", rollbackErrorRetryable(err), err), cleanup)
	}
	return provisioner.WithCreateCleanupCompleted(operations.NewExecutionError(cleanup.FailureCode, false, errors.New("failed create resources removed")))
}
