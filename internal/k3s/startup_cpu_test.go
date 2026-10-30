package k3s

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
)

func startupFixture(t *testing.T) (provisioner.CreateWorkloadCommand, ResourceSet, *corev1.Pod, *appsv1.ReplicaSet) {
	t.Helper()
	command := validCreateCommand("aws-dev")
	command.PolicyRequest.WorkloadProfile = isolation.WorkloadProfileWeb
	command.SteadyCPUMillicores = 300
	resources, err := BuildResourceSet(nodePortGVisorCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	d := resources.Deployments[0]
	d.UID, d.Generation, d.ResourceVersion = "deployment-uid", 1, "1"
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "owned-rs", Namespace: d.Namespace, UID: "rs-uid",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: ptr.To(true)}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "owned-pod", Namespace: d.Namespace, UID: "pod-uid", ResourceVersion: "1", Generation: 1,
		Labels: copyLabels(d.Spec.Template.Labels), Annotations: copyLabels(d.Spec.Template.Annotations),
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: ptr.To(true)}}},
		Spec: *d.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	return command, resources, pod, rs
}

func TestStartupTemplateStaysSteadyAndPreservesAuthorConfiguration(t *testing.T) {
	c, resources, _, _ := startupFixture(t)
	baseline := c
	baseline.SteadyCPUMillicores = 0
	base, err := BuildResourceSet(nodePortGVisorCluster("aws-dev"), baseline)
	if err != nil {
		t.Fatal(err)
	}
	want := base.Deployment.Spec.Template.Spec.DeepCopy()
	want.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("300m")
	want.Containers[0].Resources.Limits[corev1.ResourceCPU] = resource.MustParse("300m")
	if !apiequality.Semantic.DeepEqual(*want, resources.Deployment.Spec.Template.Spec) {
		t.Fatal("changed configuration outside CPU")
	}
	quota := resources.ResourceQuota.Spec.Hard[corev1.ResourceRequestsCPU]
	if quota.MilliValue() != 500 {
		t.Fatal("peak quota lost")
	}
	if resources.ExpectedSpecHash == base.ExpectedSpecHash {
		t.Fatal("CPU lifecycle is missing from identity")
	}
	changed := c
	changed.ResourceLimits.CPUMillicores = 1000
	changed.Policy = resolvedPolicyForCommand(changed, "SMALL_SINGLE")
	second, err := BuildResourceSet(nodePortGVisorCluster("aws-dev"), changed)
	if err != nil {
		t.Fatal(err)
	}
	if second.ExpectedSpecHash == resources.ExpectedSpecHash {
		t.Fatal("peak change retained identity")
	}
}

func TestStartupCPUResizeConfirmsAppliedResourcesWithoutRestart(t *testing.T) {
	command, resources, pod, rs := startupFixture(t)
	client := fake.NewSimpleClientset(resources.Deployment.DeepCopy(), pod.DeepCopy(), rs)
	var transitions []int64
	client.PrependReactor("update", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "resize" {
			t.Fatal("used full pod update")
		}
		candidate := action.(k8stesting.UpdateAction).GetObject().(*corev1.Pod).DeepCopy()
		if candidate.UID != pod.UID || candidate.ResourceVersion != pod.ResourceVersion {
			t.Fatal("lost fencing")
		}
		candidate.Generation++
		cpu := candidate.Spec.Containers[0].Resources.Limits.Cpu().MilliValue()
		transitions = append(transitions, cpu)
		candidate.Status.ObservedGeneration = candidate.Generation
		candidate.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		candidate.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: candidate.Spec.Containers[0].Name,
			ContainerID: "containerd://same-process", RestartCount: 0, Resources: candidate.Spec.Containers[0].Resources.DeepCopy()}}
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), candidate, candidate.Namespace); err != nil {
			t.Fatal(err)
		}
		return true, candidate, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := prepareStartupCPU(ctx, client, resources.Deployments, resources.ExpectedSpecHashes, command, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(transitions, []int64{500, 300}) {
		t.Fatalf("transitions = %v", transitions)
	}
	current, _ := client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if !steadyCPUObserved(current, 300) || current.Status.ContainerStatuses[0].RestartCount != 0 {
		t.Fatal("steady resources not observed")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "update" && action.GetResource().Resource == "deployments" {
			t.Fatal("modified immutable template")
		}
	}
}

func TestStartupWaitsForKubeletAndRejectsOwnershipOrOtherChanges(t *testing.T) {
	for _, kind := range []string{"stale status", "replacement owner", "other image", "host network", "memory", "service token"} {
		t.Run(kind, func(t *testing.T) {
			command, resources, pod, rs := startupFixture(t)
			pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: pod.Spec.Containers[0].Name, Resources: pod.Spec.Containers[0].Resources.DeepCopy()}}
			switch kind {
			case "replacement owner":
				rs.UID = types.UID("replacement")
			case "other image":
				pod.Spec.Containers[0].Image = "unapproved"
			case "host network":
				pod.Spec.HostNetwork = true
			case "memory":
				pod.Spec.Containers[0].Resources.Limits[corev1.ResourceMemory] = resource.MustParse("1Gi")
			case "service token":
				pod.Spec.AutomountServiceAccountToken = ptr.To(true)
			}
			client := fake.NewSimpleClientset(resources.Deployment, pod, rs)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
			defer cancel()
			err := prepareStartupCPU(ctx, client, resources.Deployments, resources.ExpectedSpecHashes, command, time.Millisecond)
			if err == nil {
				t.Fatal("unsafe state accepted")
			}
			if kind == "stale status" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestStartupCommandReplayRequiresIndependentApproval(t *testing.T) {
	command, _, _, _ := startupFixture(t)
	cluster := nodePortGVisorCluster("aws-dev")
	a := &Adapter{config: AdapterConfig{StartupCPUProfiles: map[string]provisioner.StartupCPUProfile{
		command.Containers[0].Image: {Steady: 300, Peak: 500},
	}}}
	if err := a.validateStartupCPU(cluster, command); err != nil {
		t.Fatal(err)
	}
	command.SteadyCPUMillicores = 250
	if a.validateStartupCPU(cluster, command) == nil {
		t.Fatal("unapproved steady CPU accepted")
	}
	command.SteadyCPUMillicores = 300
	cluster.Config.ExposureMode = ""
	if a.validateStartupCPU(cluster, command) == nil {
		t.Fatal("early ingress exposure accepted")
	}
}
