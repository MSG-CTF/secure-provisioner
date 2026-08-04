package k3s

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"
)

func TestBuildResourceSetAppliesNonNegotiablePodBaseline(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	if resources.ServiceAccount == nil || resources.ServiceAccount.Name != "challenge-runtime" {
		t.Fatalf("service account = %#v", resources.ServiceAccount)
	}
	if resources.ServiceAccount.AutomountServiceAccountToken == nil || *resources.ServiceAccount.AutomountServiceAccountToken {
		t.Fatal("service account token automount must be false")
	}
	if !reflect.DeepEqual(resources.ServiceAccount.Labels, resources.Namespace.Labels) {
		t.Fatalf("service account labels = %#v, namespace labels = %#v", resources.ServiceAccount.Labels, resources.Namespace.Labels)
	}

	deployment := resources.Deployments[0]
	if deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Fatalf("strategy = %q, want Recreate", deployment.Spec.Strategy.Type)
	}
	if deployment.Spec.RevisionHistoryLimit == nil || *deployment.Spec.RevisionHistoryLimit != 1 {
		t.Fatalf("revision history limit = %v, want 1", deployment.Spec.RevisionHistoryLimit)
	}
	pod := deployment.Spec.Template.Spec
	if pod.ServiceAccountName != resources.ServiceAccount.Name {
		t.Fatalf("service account name = %q", pod.ServiceAccountName)
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatal("pod token automount must be false")
	}
	if pod.HostNetwork || pod.HostPID || pod.HostIPC {
		t.Fatal("host namespaces must be false")
	}
	if pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot ||
		pod.SecurityContext.RunAsUser == nil || *pod.SecurityContext.RunAsUser != 10001 {
		t.Fatalf("pod security context = %#v", pod.SecurityContext)
	}
	if pod.SecurityContext.SeccompProfile == nil || pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("pod seccomp = %#v", pod.SecurityContext.SeccompProfile)
	}

	container := pod.Containers[0]
	security := container.SecurityContext
	if security == nil || security.RunAsNonRoot == nil || !*security.RunAsNonRoot || security.RunAsUser == nil || *security.RunAsUser != 10001 {
		t.Fatalf("container identity security context = %#v", security)
	}
	if security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem ||
		security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation ||
		security.Privileged == nil || *security.Privileged {
		t.Fatalf("container privilege security context = %#v", security)
	}
	if security.Capabilities == nil || !reflect.DeepEqual(security.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(security.Capabilities.Add) != 0 {
		t.Fatalf("container capabilities = %#v", security.Capabilities)
	}
	if security.SeccompProfile == nil || security.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("container seccomp = %#v", security.SeccompProfile)
	}
	if len(pod.Volumes) != 0 || len(container.VolumeMounts) != 0 {
		t.Fatalf("unapproved volumes/mounts = %#v / %#v", pod.Volumes, container.VolumeMounts)
	}
}

func TestBuildResourceSetCreatesOnlyApprovedSizedWritablePathsWithCollisionSafeNames(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Policy.Containers[0].WritablePaths = []isolation.WritablePath{
		{Path: "/tmp/cache.a", SizeMiB: 17},
		{Path: "/tmp/cache-a", SizeMiB: 19},
	}
	command.Policy.Containers[1].WritablePaths = []isolation.WritablePath{{Path: "/work", SizeMiB: 23}}
	command.Policy.Containers[0], command.Policy.Containers[1] = command.Policy.Containers[1], command.Policy.Containers[0]

	first, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.ServiceAccount, second.ServiceAccount) || !reflect.DeepEqual(first.Deployments, second.Deployments) {
		t.Fatal("security resource rendering is not deterministic")
	}

	wantByContainer := map[string]map[string]string{
		"web":      {"/tmp/cache.a": "17Mi", "/tmp/cache-a": "19Mi"},
		"internal": {"/work": "23Mi"},
	}
	for _, deployment := range first.Deployments {
		pod := deployment.Spec.Template.Spec
		container := pod.Containers[0]
		want := wantByContainer[container.Name]
		if len(pod.Volumes) != len(want) || len(container.VolumeMounts) != len(want) {
			t.Fatalf("%s volumes/mounts = %d/%d, want %d", container.Name, len(pod.Volumes), len(container.VolumeMounts), len(want))
		}
		volumes := make(map[string]corev1.Volume, len(pod.Volumes))
		for _, volume := range pod.Volumes {
			if problems := validation.IsDNS1123Label(volume.Name); len(problems) > 0 {
				t.Fatalf("volume name %q is not DNS-compatible: %v", volume.Name, problems)
			}
			if _, duplicate := volumes[volume.Name]; duplicate {
				t.Fatalf("duplicate volume name %q", volume.Name)
			}
			if volume.EmptyDir == nil || volume.EmptyDir.SizeLimit == nil || volume.HostPath != nil {
				t.Fatalf("volume = %#v, want sized emptyDir only", volume)
			}
			volumes[volume.Name] = volume
		}
		mountPaths := make([]string, 0, len(container.VolumeMounts))
		for _, mount := range container.VolumeMounts {
			mountPaths = append(mountPaths, mount.MountPath)
			volume, found := volumes[mount.Name]
			if !found {
				t.Fatalf("mount %q references missing volume %q", mount.MountPath, mount.Name)
			}
			wantSize, approved := want[mount.MountPath]
			if !approved {
				t.Fatalf("unapproved mount rendered: %#v", mount)
			}
			if volume.EmptyDir.SizeLimit.Cmp(resource.MustParse(wantSize)) != 0 {
				t.Fatalf("%s size = %s, want %s", mount.MountPath, volume.EmptyDir.SizeLimit.String(), wantSize)
			}
		}
		sort.Strings(mountPaths)
		wantPaths := make([]string, 0, len(want))
		for path := range want {
			wantPaths = append(wantPaths, path)
		}
		sort.Strings(wantPaths)
		if !reflect.DeepEqual(mountPaths, wantPaths) {
			t.Fatalf("%s mount paths = %#v, want %#v", container.Name, mountPaths, wantPaths)
		}
	}
}

func TestBuildResourceSetRejectsWritablePathsBeyondContainerEphemeralAllocation(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Policy.Containers[0].WritablePaths = []isolation.WritablePath{{Path: "/tmp", SizeMiB: 514}}

	_, err := BuildResourceSet(validCluster("aws-dev"), command)
	if runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
		t.Fatalf("error = %v, want INVALID_CREATE_COMMAND", err)
	}
}

func TestBuildResourceSetAcceptsWritablePathsAtEachContainerEphemeralBoundary(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Policy.Containers[0].WritablePaths = []isolation.WritablePath{{Path: "/tmp", SizeMiB: 513}}
	command.Policy.Containers[1].WritablePaths = []isolation.WritablePath{{Path: "/work", SizeMiB: 512}}
	command.Policy.Containers[0], command.Policy.Containers[1] = command.Policy.Containers[1], command.Policy.Containers[0]

	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	wantByContainer := map[string]string{"web": "513Mi", "internal": "512Mi"}
	for _, deployment := range resources.Deployments {
		pod := deployment.Spec.Template.Spec
		if len(pod.Volumes) != 1 || pod.Volumes[0].EmptyDir == nil || pod.Volumes[0].EmptyDir.SizeLimit == nil {
			t.Fatalf("%s volumes = %#v", deployment.Name, pod.Volumes)
		}
		want := resource.MustParse(wantByContainer[deployment.Name])
		if pod.Volumes[0].EmptyDir.SizeLimit.Cmp(want) != 0 {
			t.Fatalf("%s writable size = %s, want %s", deployment.Name, pod.Volumes[0].EmptyDir.SizeLimit.String(), want.String())
		}
	}
}

func TestBuildResourceSetRejectsUnsafeOrUnresolvableResolvedPolicy(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*isolation.ResolvedPolicy)
	}{
		{name: "token automount", mutate: func(policy *isolation.ResolvedPolicy) { policy.Baseline.AutomountServiceAccountToken = true }},
		{name: "root allowed", mutate: func(policy *isolation.ResolvedPolicy) { policy.Baseline.RunAsNonRoot = false }},
		{name: "writable root", mutate: func(policy *isolation.ResolvedPolicy) { policy.Baseline.ReadOnlyRootFilesystem = false }},
		{name: "privilege escalation", mutate: func(policy *isolation.ResolvedPolicy) { policy.Baseline.AllowPrivilegeEscalation = true }},
		{name: "privileged", mutate: func(policy *isolation.ResolvedPolicy) { policy.Baseline.Privileged = true }},
		{name: "capability retained", mutate: func(policy *isolation.ResolvedPolicy) { policy.Baseline.DropAllCapabilities = false }},
		{name: "seccomp disabled", mutate: func(policy *isolation.ResolvedPolicy) { policy.Baseline.SeccompRuntimeDefault = false }},
		{name: "root UID", mutate: func(policy *isolation.ResolvedPolicy) { policy.Containers[0].RunAsUser = 0 }},
		{name: "unknown container", mutate: func(policy *isolation.ResolvedPolicy) { policy.Containers[0].Name = "missing" }},
		{name: "unapproved port", mutate: func(policy *isolation.ResolvedPolicy) { policy.Containers[0].Ports = []int{9090} }},
		{name: "resource mismatch", mutate: func(policy *isolation.ResolvedPolicy) { policy.ResourceLimits.MemoryMiB++ }},
		{name: "relative path", mutate: func(policy *isolation.ResolvedPolicy) {
			policy.Containers[0].WritablePaths = []isolation.WritablePath{{Path: "tmp", SizeMiB: 1}}
		}},
		{name: "unclean path", mutate: func(policy *isolation.ResolvedPolicy) {
			policy.Containers[0].WritablePaths = []isolation.WritablePath{{Path: "/tmp/../etc", SizeMiB: 1}}
		}},
		{name: "host secret path", mutate: func(policy *isolation.ResolvedPolicy) {
			policy.Containers[0].WritablePaths = []isolation.WritablePath{{Path: "/var/run/secrets/token", SizeMiB: 1}}
		}},
		{name: "overlapping path", mutate: func(policy *isolation.ResolvedPolicy) {
			policy.Containers[0].WritablePaths = []isolation.WritablePath{{Path: "/tmp", SizeMiB: 1}, {Path: "/tmp/cache", SizeMiB: 1}}
		}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			command := validCreateCommand("aws-dev")
			testCase.mutate(&command.Policy)
			_, err := BuildResourceSet(validCluster("aws-dev"), command)
			if runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
				t.Fatalf("error = %v, want INVALID_CREATE_COMMAND", err)
			}
		})
	}
}

func TestAdapterRejectsUnsafeResolvedPathBeforeAnyKubernetesAction(t *testing.T) {
	command := validCreateCommand("aws-dev")
	command.Policy.Containers[0].WritablePaths = []isolation.WritablePath{{Path: "/proc/self", SizeMiB: 1}}
	client := fake.NewSimpleClientset()
	registry := adapterRegistry(t, []ClusterConfig{validClusterConfig("aws-dev", ProviderAWS, "unused-kubeconfig")}, client)
	adapter := newTestAdapter(t, registry)

	_, err := adapter.CreateWorkload(context.Background(), command)
	if runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
		t.Fatalf("error = %v, want INVALID_CREATE_COMMAND", err)
	}
	if actions := client.Actions(); len(actions) != 0 {
		t.Fatalf("Kubernetes actions before policy rejection = %#v", actions)
	}
}
