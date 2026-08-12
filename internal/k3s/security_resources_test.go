package k3s

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
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

func TestBuildResourceSetDerivesRunAsGroupFromEachMappedNonRootUID(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	command.Policy.Containers[0].RunAsUser = 101
	command.Policy.Containers[1].RunAsUser = 20002
	command.Policy.Containers[0], command.Policy.Containers[1] = command.Policy.Containers[1], command.Policy.Containers[0]

	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	wantGroup := map[string]int64{"web": 101, "internal": 20002}
	for _, deployment := range resources.Deployments {
		pod := deployment.Spec.Template.Spec
		container := pod.Containers[0]
		want := wantGroup[container.Name]
		if pod.SecurityContext == nil || pod.SecurityContext.RunAsGroup == nil || *pod.SecurityContext.RunAsGroup != want {
			t.Fatalf("%s pod runAsGroup = %#v, want %d", container.Name, pod.SecurityContext, want)
		}
		security := container.SecurityContext
		if security == nil || security.RunAsGroup == nil || *security.RunAsGroup != want {
			t.Fatalf("%s container runAsGroup = %#v, want %d", container.Name, security, want)
		}
		if pod.SecurityContext.RunAsUser == nil || *pod.SecurityContext.RunAsUser != want ||
			security.RunAsUser == nil || *security.RunAsUser != want {
			t.Fatalf("%s UID/GID derivation diverged: pod=%#v container=%#v", container.Name, pod.SecurityContext, security)
		}
	}
}

func TestBuildResourceSetUsesStrictSupplementalGroupsPolicyWithoutAdditionalGroups(t *testing.T) {
	resources, err := BuildResourceSet(validCluster("aws-dev"), validMultiCreateCommand("aws-dev"))
	if err != nil {
		t.Fatal(err)
	}

	for _, deployment := range resources.Deployments {
		security := deployment.Spec.Template.Spec.SecurityContext
		if security == nil || security.SupplementalGroupsPolicy == nil ||
			*security.SupplementalGroupsPolicy != corev1.SupplementalGroupsPolicyStrict {
			t.Fatalf("%s supplemental groups policy = %#v, want Strict", deployment.Name, security)
		}
		if security.SupplementalGroups != nil {
			t.Fatalf("%s supplemental groups = %#v, want nil", deployment.Name, security.SupplementalGroups)
		}
		if security.FSGroup != nil {
			t.Fatalf("%s fsGroup = %v, want nil", deployment.Name, *security.FSGroup)
		}
	}
}

func TestBuildResourceSetSpecHashTracksIdentityUsedForDerivedGroup(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	initial, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	command.Policy.Containers[0].RunAsUser = 101
	revised, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	if revised.ExpectedSpecHashes["web"] == initial.ExpectedSpecHashes["web"] {
		t.Fatal("approved UID and derived group change did not change web spec hash")
	}
	if revised.ExpectedSpecHashes["internal"] != initial.ExpectedSpecHashes["internal"] {
		t.Fatal("web identity change changed internal spec hash")
	}
	pod := revised.Deployments[0].Spec.Template.Spec
	if pod.SecurityContext.RunAsGroup == nil || *pod.SecurityContext.RunAsGroup != 101 ||
		pod.Containers[0].SecurityContext.RunAsGroup == nil || *pod.Containers[0].SecurityContext.RunAsGroup != 101 {
		t.Fatalf("revised derived group = pod %#v, container %#v", pod.SecurityContext, pod.Containers[0].SecurityContext)
	}
}

func TestDeploymentSpecVerificationIncludesDerivedRunAsGroup(t *testing.T) {
	resources, err := BuildResourceSet(validCluster("aws-dev"), validCreateCommand("aws-dev"))
	if err != nil {
		t.Fatal(err)
	}
	desired := resources.Deployment

	withoutPodGroup := desired.DeepCopy()
	withoutPodGroup.Spec.Template.Spec.SecurityContext.RunAsGroup = nil
	if sameDeploymentSpec(withoutPodGroup, desired) {
		t.Fatal("deployment verification accepted a missing pod runAsGroup")
	}

	withoutContainerGroup := desired.DeepCopy()
	withoutContainerGroup.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup = nil
	if sameDeploymentSpec(withoutContainerGroup, desired) {
		t.Fatal("deployment verification accepted a missing container runAsGroup")
	}
}

func TestDeploymentSpecVerificationIncludesStrictSupplementalGroupsPolicy(t *testing.T) {
	resources, err := BuildResourceSet(validCluster("aws-dev"), validCreateCommand("aws-dev"))
	if err != nil {
		t.Fatal(err)
	}
	desired := resources.Deployment

	missingPolicy := desired.DeepCopy()
	missingPolicy.Spec.Template.Spec.SecurityContext.SupplementalGroupsPolicy = nil
	if sameDeploymentSpec(missingPolicy, desired) {
		t.Fatal("deployment verification accepted a missing supplemental groups policy")
	}

	changedPolicy := desired.DeepCopy()
	changedPolicy.Spec.Template.Spec.SecurityContext.SupplementalGroupsPolicy = new(corev1.SupplementalGroupsPolicy)
	*changedPolicy.Spec.Template.Spec.SecurityContext.SupplementalGroupsPolicy = corev1.SupplementalGroupsPolicyMerge
	if sameDeploymentSpec(changedPolicy, desired) {
		t.Fatal("deployment verification accepted supplemental groups policy Merge")
	}
}

func TestBuildResourceSetCreatesQuotaAndLimitRangeFromSingleContainerPolicy(t *testing.T) {
	command := validCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	if resources.ResourceQuota == nil {
		t.Fatal("resource quota is nil")
	}
	if resources.LimitRange == nil {
		t.Fatal("limit range is nil")
	}
	if resources.ResourceQuota.Namespace != resources.Namespace.Name || resources.LimitRange.Namespace != resources.Namespace.Name {
		t.Fatalf("protection namespaces = %q/%q, want %q", resources.ResourceQuota.Namespace, resources.LimitRange.Namespace, resources.Namespace.Name)
	}
	if !reflect.DeepEqual(resources.ResourceQuota.Labels, resources.Namespace.Labels) || !reflect.DeepEqual(resources.LimitRange.Labels, resources.Namespace.Labels) {
		t.Fatal("quota and limit range must carry exact ownership labels")
	}

	assertResourceList(t, resources.ResourceQuota.Spec.Hard, map[corev1.ResourceName]string{
		corev1.ResourceRequestsCPU:                          "500m",
		corev1.ResourceLimitsCPU:                            "500m",
		corev1.ResourceRequestsMemory:                       "512Mi",
		corev1.ResourceLimitsMemory:                         "512Mi",
		corev1.ResourceRequestsEphemeralStorage:             "1Gi",
		corev1.ResourceLimitsEphemeralStorage:               "1Gi",
		corev1.ResourcePods:                                 "1",
		corev1.ResourceServices:                             "1",
		corev1.ResourceServicesLoadBalancers:                "0",
		corev1.ResourceServicesNodePorts:                    "0",
		corev1.ResourceName("count/deployments.apps"):       "1",
		corev1.ResourceName("count/replicasets.apps"):       "2",
		corev1.ResourceName("count/secrets"):                "0",
		corev1.ResourceName("count/configmaps"):             "0",
		corev1.ResourceName("count/persistentvolumeclaims"): "0",
	})

	if len(resources.LimitRange.Spec.Limits) != 1 {
		t.Fatalf("limit range = %#v, want one container rule", resources.LimitRange.Spec)
	}
	containerLimit := resources.LimitRange.Spec.Limits[0]
	if containerLimit.Type != corev1.LimitTypeContainer {
		t.Fatalf("limit type = %q, want Container", containerLimit.Type)
	}
	wantPerContainer := map[corev1.ResourceName]string{
		corev1.ResourceCPU:              "500m",
		corev1.ResourceMemory:           "512Mi",
		corev1.ResourceEphemeralStorage: "1Gi",
	}
	assertResourceList(t, containerLimit.Default, wantPerContainer)
	assertResourceList(t, containerLimit.DefaultRequest, wantPerContainer)
	assertResourceList(t, containerLimit.Max, wantPerContainer)
}

func TestBuildResourceSetUsesExactAggregateQuotaAndRemainderSafeContainerDefaults(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	resources, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	assertResourceList(t, resources.ResourceQuota.Spec.Hard, map[corev1.ResourceName]string{
		corev1.ResourceRequestsCPU:                          "501m",
		corev1.ResourceLimitsCPU:                            "501m",
		corev1.ResourceRequestsMemory:                       "513Mi",
		corev1.ResourceLimitsMemory:                         "513Mi",
		corev1.ResourceRequestsEphemeralStorage:             "1025Mi",
		corev1.ResourceLimitsEphemeralStorage:               "1025Mi",
		corev1.ResourcePods:                                 "2",
		corev1.ResourceServices:                             "2",
		corev1.ResourceServicesLoadBalancers:                "0",
		corev1.ResourceServicesNodePorts:                    "0",
		corev1.ResourceName("count/deployments.apps"):       "2",
		corev1.ResourceName("count/replicasets.apps"):       "4",
		corev1.ResourceName("count/secrets"):                "0",
		corev1.ResourceName("count/configmaps"):             "0",
		corev1.ResourceName("count/persistentvolumeclaims"): "0",
	})

	containerLimit := resources.LimitRange.Spec.Limits[0]
	wantMaximumSlice := map[corev1.ResourceName]string{
		corev1.ResourceCPU:              "251m",
		corev1.ResourceMemory:           "257Mi",
		corev1.ResourceEphemeralStorage: "513Mi",
	}
	assertResourceList(t, containerLimit.Default, wantMaximumSlice)
	assertResourceList(t, containerLimit.DefaultRequest, wantMaximumSlice)
	assertResourceList(t, containerLimit.Max, wantMaximumSlice)
	for _, deployment := range resources.Deployments {
		container := deployment.Spec.Template.Spec.Containers[0]
		for name, maximum := range containerLimit.Max {
			if got := container.Resources.Limits[name]; got.Cmp(maximum) > 0 {
				t.Fatalf("%s %s limit = %s, exceeds LimitRange max %s", container.Name, name, got.String(), maximum.String())
			}
		}
	}
}

func TestBuildResourceSetForbidsTokenSecretsAndOtherUnapprovedObjectsWithoutBlockingServiceAccount(t *testing.T) {
	resources, err := BuildResourceSet(validCluster("aws-dev"), validCreateCommand("aws-dev"))
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []corev1.ResourceName{
		corev1.ResourceName("count/secrets"),
		corev1.ResourceName("count/configmaps"),
		corev1.ResourceName("count/persistentvolumeclaims"),
	} {
		got, found := resources.ResourceQuota.Spec.Hard[name]
		if !found || !got.IsZero() {
			t.Fatalf("quota %q = %s, found %t; want explicit zero", name, got.String(), found)
		}
	}
	if resources.ServiceAccount == nil || resources.ServiceAccount.AutomountServiceAccountToken == nil || *resources.ServiceAccount.AutomountServiceAccountToken {
		t.Fatal("service account must exist with token automount disabled")
	}
	for _, deployment := range resources.Deployments {
		automount := deployment.Spec.Template.Spec.AutomountServiceAccountToken
		if automount == nil || *automount {
			t.Fatalf("deployment %q must disable service account token automount", deployment.Name)
		}
	}
}

func TestBuildResourceSetRendersQuotaAndLimitRangeDeterministically(t *testing.T) {
	command := validMultiCreateCommand("aws-dev")
	first, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildResourceSet(validCluster("aws-dev"), command)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(first.ResourceQuota, second.ResourceQuota) || !reflect.DeepEqual(first.LimitRange, second.LimitRange) {
		t.Fatalf("resource controls are not deterministic:\nfirst = %#v / %#v\nsecond = %#v / %#v", first.ResourceQuota, first.LimitRange, second.ResourceQuota, second.LimitRange)
	}
}

func TestBuildResourceSetRejectsResourcePolicyTamperingInsteadOfRenderingCommandValues(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*provisioner.CreateWorkloadCommand)
	}{
		{name: "policy total", mutate: func(command *provisioner.CreateWorkloadCommand) {
			command.Policy.ResourceLimits.CPUMillicores++
		}},
		{name: "command total", mutate: func(command *provisioner.CreateWorkloadCommand) {
			command.ResourceLimits.EphemeralStorageMiB++
		}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			command := validMultiCreateCommand("aws-dev")
			testCase.mutate(&command)

			resources, err := BuildResourceSet(validCluster("aws-dev"), command)
			if runtimeErrorCode(t, err) != "INVALID_CREATE_COMMAND" {
				t.Fatalf("error = %v, want INVALID_CREATE_COMMAND", err)
			}
			if resources.ResourceQuota != nil || resources.LimitRange != nil {
				t.Fatalf("resource controls rendered from tampered policy: %#v", resources)
			}
		})
	}
}

func assertResourceList(t *testing.T, got corev1.ResourceList, want map[corev1.ResourceName]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("resource list has %d entries, want %d: %#v", len(got), len(want), got)
	}
	for name, value := range want {
		quantity, found := got[name]
		if !found {
			t.Errorf("resource %q is missing", name)
			continue
		}
		wantQuantity := resource.MustParse(value)
		if quantity.Cmp(wantQuantity) != 0 {
			t.Errorf("resource %q = %s, want %s", name, quantity.String(), value)
		}
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
		{name: "missing workload profile", mutate: func(policy *isolation.ResolvedPolicy) { policy.WorkloadProfileRef = isolation.ProfileRef{} }},
		{name: "Web with sandbox runtime", mutate: func(policy *isolation.ResolvedPolicy) { policy.RuntimeClassName = "gvisor" }},
		{name: "Web with TCP endpoint", mutate: func(policy *isolation.ResolvedPolicy) { policy.EndpointProtocol = isolation.EndpointProtocolTCP }},
		{name: "Web with Pwn exposure", mutate: func(policy *isolation.ResolvedPolicy) { policy.ExposureRequirement = isolation.ExposureNodePortOnly }},
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
		{name: "device path", mutate: func(policy *isolation.ResolvedPolicy) {
			policy.Containers[0].WritablePaths = []isolation.WritablePath{{Path: "/dev/shm", SizeMiB: 1}}
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

func TestBuildResourceSetRejectsNonCanonicalPwnExecutionPolicy(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*isolation.ResolvedPolicy)
	}{
		{name: "missing gVisor", mutate: func(policy *isolation.ResolvedPolicy) { policy.RuntimeClassName = "" }},
		{name: "HTTP endpoint", mutate: func(policy *isolation.ResolvedPolicy) { policy.EndpointProtocol = isolation.EndpointProtocolHTTP }},
		{name: "unrestricted exposure", mutate: func(policy *isolation.ResolvedPolicy) { policy.ExposureRequirement = isolation.ExposureAnySupported }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			command := validPwnCreateCommand("aws-dev")
			testCase.mutate(&command.Policy)
			_, err := BuildResourceSet(nodePortGVisorCluster("aws-dev"), command)
			if code := runtimeErrorCode(t, err); code != "INVALID_CREATE_COMMAND" {
				t.Fatalf("code = %q, want INVALID_CREATE_COMMAND", code)
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
