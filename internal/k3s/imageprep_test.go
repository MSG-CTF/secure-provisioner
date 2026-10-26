package k3s

import (
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"strings"
	"testing"
)

func TestImageInventoryErrorsClassifyTransientWithoutExposingRawDetails(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{apierrors.NewTimeoutError("SECRET timeout", 1), "NETWORK_TIMEOUT"}, {apierrors.NewTooManyRequests("SECRET rate", 1), "RATE_LIMITED"}, {apierrors.NewServiceUnavailable("SECRET upstream"), "REGISTRY_UNAVAILABLE"}, {apierrors.NewUnauthorized("SECRET credential"), "AGENT_UNAVAILABLE"}} {
		err := imageInventoryError(tc.err)
		if imageprep.ErrorCode(err) != tc.want || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("inventory error=%v expected=%s", err, tc.want)
		}
	}
}

func TestImagePreparationPlacementKeepsRequiredPlatformAndOptionalPreference(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Architecture = "AMD64"
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	pod := &resources.Deployments[0].Spec.Template.Spec
	if pod.NodeSelector["kubernetes.io/os"] != "linux" || pod.NodeSelector["kubernetes.io/arch"] != "amd64" {
		t.Fatal("missing required platform")
	}
	applyImagePreference(resources, []string{"node-a"})
	if pod.Affinity == nil || pod.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil || len(pod.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatal("readiness must remain soft")
	}
	command.Architecture = "ARM64"
	if _, err := BuildResourceSet(validCluster("aws-dev"), command); err == nil {
		t.Fatal("target platform mismatch accepted")
	}
}

func TestPreparationEligibilityRejectsCordonedTaintedAndWrongPlatform(t *testing.T) {
	n := corev1.Node{Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "linux", Architecture: "amd64", BootID: "boot", MachineID: "machine"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	if !imageNodeEligible(n, "AMD64") {
		t.Fatal("ready node rejected")
	}
	n.Spec.Unschedulable = true
	if imageNodeEligible(n, "AMD64") {
		t.Fatal("cordon accepted")
	}
	n.Spec.Unschedulable = false
	n.Spec.Taints = []corev1.Taint{{Key: "dedicated", Effect: corev1.TaintEffectNoSchedule}}
	if imageNodeEligible(n, "AMD64") {
		t.Fatal("taint accepted")
	}
	n.Spec.Taints = nil
	if imageNodeEligible(n, "ARM64") {
		t.Fatal("wrong platform accepted")
	}
}
