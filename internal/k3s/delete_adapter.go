package k3s

import (
	"context"
	"strconv"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DeleteAdapterConfig struct {
	DeleteTimeout time.Duration
	PollInterval  time.Duration
}

type DeleteAdapter struct {
	registry      *Registry
	config        DeleteAdapterConfig
	workloadLocks *workloadLockSet
}

func NewDeleteAdapter(registry *Registry, config DeleteAdapterConfig) (*DeleteAdapter, error) {
	if registry == nil || config.DeleteTimeout <= 0 || config.PollInterval <= 0 {
		return nil, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	return &DeleteAdapter{
		registry:      registry,
		config:        config,
		workloadLocks: newWorkloadLockSet(),
	}, nil
}

func NewDeleteAdapterForCreateAdapter(create *Adapter, config DeleteAdapterConfig) (*DeleteAdapter, error) {
	if create == nil {
		return nil, newRuntimeError("CONFIG_INVALID", false, nil)
	}
	adapter, err := NewDeleteAdapter(create.registry, config)
	if err != nil {
		return nil, err
	}
	adapter.workloadLocks = create.workloadLocks
	return adapter, nil
}

func (a *DeleteAdapter) DeleteWorkload(ctx context.Context, command provisioner.DeleteWorkloadCommand, binding runtimebinding.Binding) error {
	if !deleteMatchesBinding(command, binding) {
		return newRuntimeError("INSTANCE_BINDING_MISMATCH", false, nil)
	}
	release, err := a.workloadLocks.acquire(ctx, workloadLockKey(binding.TargetID, binding.InstanceID))
	if err != nil {
		return operationCancelledError(err)
	}
	defer release()

	cluster, err := a.registry.LookupForMaintenance(binding.TargetID)
	if err != nil {
		return err
	}
	namespace, err := cluster.Client.CoreV1().Namespaces().Get(ctx, binding.Namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return operationCancelledError(ctx.Err())
		}
		return newRuntimeError("TARGET_TEMPORARILY_UNAVAILABLE", true, err)
	}
	if !namespaceOwnedByBinding(namespace.Labels, binding) {
		return newRuntimeError("RUNTIME_OWNERSHIP_MISMATCH", false, nil)
	}

	propagation := metav1.DeletePropagationForeground
	err = cluster.Client.CoreV1().Namespaces().Delete(ctx, binding.Namespace, metav1.DeleteOptions{PropagationPolicy: &propagation})
	if err != nil && !apierrors.IsNotFound(err) {
		if ctx.Err() != nil {
			return operationCancelledError(ctx.Err())
		}
		return newRuntimeError("TARGET_TEMPORARILY_UNAVAILABLE", true, err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, a.config.DeleteTimeout)
	defer cancel()
	ticker := time.NewTicker(a.config.PollInterval)
	defer ticker.Stop()
	for {
		_, getErr := cluster.Client.CoreV1().Namespaces().Get(waitCtx, binding.Namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			return nil
		}
		if getErr != nil {
			if waitCtx.Err() != nil {
				if ctx.Err() != nil {
					return operationCancelledError(ctx.Err())
				}
				return newRuntimeError("NAMESPACE_DELETE_TIMEOUT", true, waitCtx.Err())
			}
			return newRuntimeError("TARGET_TEMPORARILY_UNAVAILABLE", true, getErr)
		}
		select {
		case <-ctx.Done():
			return operationCancelledError(ctx.Err())
		case <-waitCtx.Done():
			return newRuntimeError("NAMESPACE_DELETE_TIMEOUT", true, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func deleteMatchesBinding(command provisioner.DeleteWorkloadCommand, binding runtimebinding.Binding) bool {
	return command.InstanceID == binding.InstanceID &&
		command.TeamID == binding.TeamID &&
		command.RuntimeType == provisioner.RuntimeTypeKubernetes &&
		command.TargetID == binding.TargetID &&
		command.RuntimeWorkloadID == binding.RuntimeWorkloadID
}

func namespaceOwnedByBinding(labels map[string]string, binding runtimebinding.Binding) bool {
	return labels["app.kubernetes.io/managed-by"] == "secure-provisioner" &&
		labels["msgctf.io/instance-id"] == binding.InstanceID &&
		labels["msgctf.io/team-id"] == strconv.FormatInt(binding.TeamID, 10)
}
