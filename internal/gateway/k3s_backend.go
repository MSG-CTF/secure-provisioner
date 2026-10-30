package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CreateBackend interface {
	CreateWorkload(context.Context, provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error)
}
type DeleteBackend interface {
	DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error
}
type KubernetesBackend struct {
	Registry     *k3s.Registry
	Create       CreateBackend
	Delete       DeleteBackend
	TCPTransport PublicTransport
}

// Reject unknown or disabled targets before the request enters the durable
// create queue. A reconcile_create fence can then prove it was never accepted.
func (b *KubernetesBackend) ValidateCreateCommand(c provisioner.CreateWorkloadCommand) error {
	if c.RuntimeType != provisioner.RuntimeTypeKubernetes {
		return nil
	}
	cluster, err := b.Registry.LookupForCreate(c.TargetID)
	if err != nil {
		var rejected *k3s.RuntimeError
		if errors.As(err, &rejected) {
			return operations.NewExecutionError(rejected.Code(), rejected.Retryable(), err)
		}
		return err
	}
	return cluster.Supports(c.Policy)
}

func (b *KubernetesBackend) Enabled(id string) bool {
	c, err := b.Registry.LookupForMaintenance(id)
	return err == nil && c.Config.Gateway != nil && c.Config.Gateway.Enabled
}
func (b *KubernetesBackend) CreateWorkloadForOperation(ctx context.Context, c provisioner.CreateWorkloadCommand, id string) (provisioner.CreateWorkloadResult, error) {
	if aware, ok := b.Create.(interface {
		CreateWorkloadForOperation(context.Context, provisioner.CreateWorkloadCommand, string) (provisioner.CreateWorkloadResult, error)
	}); ok {
		return aware.CreateWorkloadForOperation(ctx, c, id)
	}
	return b.Create.CreateWorkload(ctx, c)
}
func (b *KubernetesBackend) DeleteWorkload(ctx context.Context, c provisioner.DeleteWorkloadCommand, binding runtimebinding.Binding) error {
	return b.Delete.DeleteWorkload(ctx, c, binding)
}

// A removed Gateway route already has a durable cleanup intent. Give the
// namespace controller time to work without occupying a lifecycle worker for
// the full deletion timeout. The caller retains the route journal and binding
// and retries until DeleteWorkload actually confirms namespace absence.
// Ordinary deletes without a Gateway journal keep their original timeout.
func (b *KubernetesBackend) DeleteWorkloadStep(ctx context.Context, c provisioner.DeleteWorkloadCommand, binding runtimebinding.Binding) error {
	stepCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := b.Delete.DeleteWorkload(stepCtx, c, binding)
	if errors.Is(err, context.DeadlineExceeded) && stepCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
		return operations.NewProgressPendingError("GATEWAY_WORKLOAD_DELETE_PENDING", err)
	}
	return err
}
func (b *KubernetesBackend) CleanupFailedCreate(ctx context.Context, c provisioner.CreateWorkloadCommand, cleanup provisioner.CreateCleanup) error {
	if cleaner, ok := b.Create.(k3s.FailedCreateCleaner); ok {
		return cleaner.CleanupFailedCreate(ctx, c, cleanup)
	}
	return errors.New("workload cleanup unavailable")
}
func (b *KubernetesBackend) Destination(ctx context.Context, c provisioner.CreateWorkloadCommand, result provisioner.CreateWorkloadResult) (Destination, string, error) {
	cluster, err := b.Registry.LookupForMaintenance(c.TargetID)
	if err != nil {
		return Destination{}, "", err
	}
	if cluster.Config.Gateway == nil || !cluster.Config.Gateway.Enabled || cluster.Config.ExposureMode != k3s.ExposureModeNodePort {
		return Destination{}, "", errors.New("Gateway requires opted-in NodePort target")
	}
	ip, err := PublicIP(cluster.Config.Gateway.UpstreamIP)
	if err != nil {
		return Destination{}, "", err
	}
	if len(result.Endpoints) != 1 {
		return Destination{}, "", errors.New("Gateway requires one public endpoint")
	}
	namespace, err := k3s.NamespaceForInstance(c.InstanceID)
	if err != nil {
		return Destination{}, "", err
	}
	services, err := cluster.Client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{LabelSelector: "msgctf.io/instance-id=" + c.InstanceID})
	if err != nil {
		return Destination{}, "", err
	}
	endpoint := result.Endpoints[0]
	found := 0
	var port int
	var uid string
	for _, service := range services.Items {
		if service.Spec.Type != corev1.ServiceTypeNodePort || service.Labels["msgctf.io/container-name"] != endpoint.ContainerName {
			continue
		}
		if service.Labels["msgctf.io/team-id"] != string(c.TeamID) || service.Labels["app.kubernetes.io/managed-by"] != "secure-provisioner" {
			return Destination{}, "", errors.New("Service owner mismatch")
		}
		for _, p := range service.Spec.Ports {
			if int(p.Port) == endpoint.Port && p.NodePort > 0 {
				found++
				port = int(p.NodePort)
				uid = string(service.UID)
			}
		}
	}
	if found != 1 || uid == "" {
		return Destination{}, "", errors.New("allocated NodePort identity unavailable")
	}
	protocol := "http"
	if endpoint.Protocol == "TCP" {
		protocol = "tcp"
	} else if endpoint.Protocol != "HTTP" {
		return Destination{}, "", errors.New("unsupported Gateway protocol")
	}
	destination := Destination{TargetIP: ip, TargetPort: port, Protocol: protocol}
	if protocol == "tcp" && b.TCPTransport != TransportLegacy {
		destination.PublicTransport = b.TCPTransport
		destination.OwnerTeamID = string(c.TeamID)
		if !destination.validDraft() {
			return Destination{}, "", errors.New("invalid Gateway TCP contract owner or transport")
		}
	}
	return destination, uid, nil
}
func (b *KubernetesBackend) Verify(ctx context.Context, r Record) error {
	return b.verify(ctx, r, true)
}
func (b *KubernetesBackend) VerifyPortClaim(ctx context.Context, r Record) error {
	return b.verify(ctx, r, false)
}
func (b *KubernetesBackend) verify(ctx context.Context, r Record, requireReady bool) error {
	cluster, err := b.Registry.LookupForMaintenance(r.Command.TargetID)
	if err != nil {
		return err
	}
	namespace, err := k3s.NamespaceForInstance(r.Command.InstanceID)
	if err != nil {
		return err
	}
	ns, err := cluster.Client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return ErrUpstreamIdentity
	}
	if err != nil {
		return err
	}
	if string(ns.UID) != r.Result.NamespaceUID || ns.Labels["msgctf.io/instance-id"] != r.Command.InstanceID || ns.Labels["msgctf.io/team-id"] != string(r.Command.TeamID) || ns.Labels["app.kubernetes.io/managed-by"] != "secure-provisioner" || ns.DeletionTimestamp != nil {
		return ErrUpstreamIdentity
	}
	services, err := cluster.Client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{LabelSelector: "msgctf.io/instance-id=" + r.Command.InstanceID})
	if err != nil {
		return err
	}
	for _, s := range services.Items {
		if len(r.Result.Endpoints) == 1 && string(s.UID) == r.ServiceUID && s.Spec.Type == corev1.ServiceTypeNodePort && s.DeletionTimestamp == nil && s.Labels["msgctf.io/team-id"] == string(r.Command.TeamID) && s.Labels["app.kubernetes.io/managed-by"] == "secure-provisioner" && s.Labels["msgctf.io/container-name"] == r.Result.Endpoints[0].ContainerName {
			for _, p := range s.Spec.Ports {
				if int(p.NodePort) == r.Destination.TargetPort && int(p.Port) == r.Result.Endpoints[0].Port && (p.Protocol == "" || p.Protocol == corev1.ProtocolTCP) {
					if !requireReady {
						return nil
					}
					pods, podErr := cluster.Client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "msgctf.io/instance-id=" + r.Command.InstanceID})
					if podErr != nil {
						return podErr
					}
					return containersReady(r.Command, pods.Items)
				}
			}
		}
	}
	return ErrUpstreamIdentity
}

func containersReady(command provisioner.CreateWorkloadCommand, pods []corev1.Pod) error {
	for _, expected := range command.Containers {
		ready := false
		for _, pod := range pods {
			if pod.DeletionTimestamp != nil || pod.Labels["msgctf.io/team-id"] != string(command.TeamID) || pod.Labels["app.kubernetes.io/managed-by"] != "secure-provisioner" {
				continue
			}
			podReady := false
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					podReady = true
				}
			}
			if !podReady {
				continue
			}
			for _, container := range pod.Spec.Containers {
				if container.Name != expected.Name || container.Image != expected.Image {
					continue
				}
				for _, status := range pod.Status.ContainerStatuses {
					if status.Name == expected.Name && status.Ready && status.State.Running != nil {
						ready = true
					}
				}
			}
		}
		if !ready {
			return errors.New("Gateway workload container not ready")
		}
	}
	return nil
}

// Quiesce stops pods while keeping Service objects, hence NodePort allocation.
// Termination is not reported until the later namespace deletion is confirmed.
func (b *KubernetesBackend) Quiesce(ctx context.Context, r Record) error {
	cluster, err := b.Registry.LookupForMaintenance(r.Command.TargetID)
	if err != nil {
		return err
	}
	namespace, err := k3s.NamespaceForInstance(r.Command.InstanceID)
	if err != nil {
		return err
	}
	ns, err := cluster.Client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(ns.UID) != r.Result.NamespaceUID || ns.Labels["msgctf.io/team-id"] != string(r.Command.TeamID) || ns.Labels["msgctf.io/instance-id"] != r.Command.InstanceID || ns.Labels["app.kubernetes.io/managed-by"] != "secure-provisioner" {
		return errors.New("namespace generation changed")
	}
	deployments, err := cluster.Client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{LabelSelector: "msgctf.io/instance-id=" + r.Command.InstanceID})
	if err != nil {
		return err
	}
	for _, d := range deployments.Items {
		if d.Labels["msgctf.io/team-id"] != string(r.Command.TeamID) || d.Labels["app.kubernetes.io/managed-by"] != "secure-provisioner" {
			return errors.New("Deployment owner mismatch")
		}
		if d.Spec.Replicas != nil && *d.Spec.Replicas == 0 {
			continue
		}
		zero := int32(0)
		d.Spec.Replicas = &zero
		if _, err = cluster.Client.AppsV1().Deployments(namespace).Update(ctx, &d, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	pods, err := cluster.Client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "msgctf.io/instance-id=" + r.Command.InstanceID})
	if err != nil {
		return err
	}
	if len(pods.Items) > 0 {
		return operations.NewProgressPendingError("GATEWAY_WORKLOAD_STOP_PENDING", fmt.Errorf("%d workload pods still terminating", len(pods.Items)))
	}
	return nil
}
