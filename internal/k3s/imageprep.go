package k3s

import (
	"context"
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"strings"
	"syscall"
)

type ImageInventory struct{ Registry *Registry }

func (i ImageInventory) Known(target string) bool {
	_, err := i.Registry.LookupForMaintenance(target)
	return err == nil
}
func (i ImageInventory) Enabled(target, arch string) bool {
	c, err := i.Registry.LookupForCreate(target)
	return err == nil && strings.EqualFold(c.Config.Architecture, arch)
}
func (i ImageInventory) Nodes(ctx context.Context, target, arch string) ([]imageprep.Node, error) {
	c, err := i.Registry.LookupForCreate(target)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(c.Config.Architecture, arch) {
		return nil, imageprep.ErrPolicy
	}
	list, err := c.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, imageInventoryError(err)
	}
	nodes := []imageprep.Node{}
	for _, n := range list.Items {
		if imageNodeEligible(n, arch) {
			nodes = append(nodes, imageprep.Node{TargetID: target, UID: string(n.UID), Name: n.Name, BootID: n.Status.NodeInfo.BootID, MachineID: n.Status.NodeInfo.MachineID, Architecture: arch})
		}
	}
	return nodes, nil
}

func imageInventoryError(err error) error {
	code := "AGENT_UNAVAILABLE"
	var network net.Error
	switch {
	case apierrors.IsTooManyRequests(err):
		code = "RATE_LIMITED"
	case apierrors.IsServiceUnavailable(err) || apierrors.IsInternalError(err):
		code = "REGISTRY_UNAVAILABLE"
	case apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || (errors.As(err, &network) && network.Timeout()):
		code = "NETWORK_TIMEOUT"
	}
	return imageprep.Failure{Code: code}
}
func imageNodeEligible(n corev1.Node, arch string) bool {
	if n.Spec.Unschedulable || n.DeletionTimestamp != nil || n.Status.NodeInfo.OperatingSystem != "linux" || !strings.EqualFold(n.Status.NodeInfo.Architecture, arch) || n.Status.NodeInfo.BootID == "" || n.Status.NodeInfo.MachineID == "" {
		return false
	}
	for _, taint := range n.Spec.Taints {
		if taint.Effect == corev1.TaintEffectNoSchedule || taint.Effect == corev1.TaintEffectNoExecute {
			return false
		}
	}
	for _, condition := range n.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func applyImagePreference(resources ResourceSet, names []string) {
	if len(names) == 0 {
		return
	}
	for _, deployment := range resources.Deployments {
		pod := &deployment.Spec.Template.Spec
		if pod.Affinity == nil {
			pod.Affinity = &corev1.Affinity{}
		}
		if pod.Affinity.NodeAffinity == nil {
			pod.Affinity.NodeAffinity = &corev1.NodeAffinity{}
		}
		pod.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution = append(pod.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution, corev1.PreferredSchedulingTerm{Weight: 100, Preference: corev1.NodeSelectorTerm{MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: names}}}})
	}
}
