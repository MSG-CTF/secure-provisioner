package isolation_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
)

func TestStaticResolverComposesWebOnStandardWithFixedOutbound(t *testing.T) {
	request := validRequest()

	got, err := isolation.NewStaticResolver().Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if got.IsolationRef != (isolation.ProfileRef{Name: "STANDARD", Version: "v2"}) ||
		got.WorkloadProfileRef != (isolation.ProfileRef{Name: "WEB", Version: "v1"}) ||
		got.RuntimeClassName != "" ||
		got.EndpointProtocol != isolation.EndpointProtocolHTTP ||
		got.ExposureRequirement != isolation.ExposureAnySupported ||
		got.OutboundMode != isolation.OutboundNone {
		t.Fatalf("resolved Web policy = %#v", got)
	}
	if got.ResourceLimits != request.ResourceLimits {
		t.Fatalf("resource limits = %#v, want %#v", got.ResourceLimits, request.ResourceLimits)
	}
}

func TestStaticResolverResolvesStandardPolicyWithoutAllowingBaselineOverrides(t *testing.T) {
	got, err := isolation.NewStaticResolver().Resolve(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Baseline.RunAsNonRoot || !got.Baseline.ReadOnlyRootFilesystem || !got.Baseline.DropAllCapabilities {
		t.Fatalf("baseline = %#v", got.Baseline)
	}
	if got.Baseline.AutomountServiceAccountToken || got.Baseline.AllowPrivilegeEscalation || got.Baseline.Privileged {
		t.Fatalf("unsafe baseline = %#v", got.Baseline)
	}
	if !got.Baseline.SeccompRuntimeDefault {
		t.Fatalf("seccomp baseline = %#v", got.Baseline)
	}
}

func TestStaticResolverComposesPwnOnStandard(t *testing.T) {
	got, err := isolation.NewStaticResolver().Resolve(validPwnRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got.IsolationRef != (isolation.ProfileRef{Name: "STANDARD", Version: "v2"}) ||
		got.WorkloadProfileRef != (isolation.ProfileRef{Name: "PWN", Version: "v1"}) ||
		got.RuntimeClassName != "gvisor" ||
		got.EndpointProtocol != isolation.EndpointProtocolTCP ||
		got.ExposureRequirement != isolation.ExposureNodePortOnly ||
		got.OutboundMode != isolation.OutboundNone {
		t.Fatalf("resolved Pwn policy = %#v", got)
	}
}

func TestStaticResolverRejectsUnknownWorkloadProfile(t *testing.T) {
	for _, profile := range []isolation.WorkloadProfile{"", "web", "KERNEL"} {
		t.Run(string(profile), func(t *testing.T) {
			request := validRequest()
			request.WorkloadProfile = profile
			assertRejected(t, request)
		})
	}
}

func TestStaticResolverAcceptsSchedulerDefinedPositiveResourceLimits(t *testing.T) {
	request := validRequest()
	request.ResourceLimits = isolation.ResourceLimits{
		CPUMillicores: 350, MemoryMiB: 384, EphemeralStorageMiB: 700,
	}

	got, err := isolation.NewStaticResolver().Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if got.ResourceLimits != request.ResourceLimits {
		t.Fatalf("resource limits = %#v, want %#v", got.ResourceLimits, request.ResourceLimits)
	}
}

func TestStaticResolverRejectsNonPositiveResourceLimits(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*isolation.ResourceLimits)
	}{
		{name: "cpu", mutate: func(limits *isolation.ResourceLimits) { limits.CPUMillicores = 0 }},
		{name: "memory", mutate: func(limits *isolation.ResourceLimits) { limits.MemoryMiB = -1 }},
		{name: "ephemeral storage", mutate: func(limits *isolation.ResourceLimits) { limits.EphemeralStorageMiB = 0 }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := validRequest()
			testCase.mutate(&request.ResourceLimits)
			assertRejected(t, request)
		})
	}
}

func TestStaticResolverRejectsRootUID(t *testing.T) {
	request := validRequest()
	request.Containers[0].RunAsUser = 0
	assertRejected(t, request)
}

func TestStaticResolverRejectsReservedWritablePaths(t *testing.T) {
	for _, path := range []string{"/proc", "/proc/self", "/sys", "/sys/kernel", "/dev", "/dev/shm", "/var/run/secrets", "/var/run/secrets/kubernetes.io"} {
		t.Run(path, func(t *testing.T) {
			request := validRequest()
			request.Containers[0].WritablePaths = []isolation.WritablePath{{Path: path, SizeMiB: 1}}
			assertRejected(t, request)
		})
	}
}

func TestStaticResolverRejectsWebWithoutExposedContainer(t *testing.T) {
	request := validRequest()
	for index := range request.Containers {
		request.Containers[index].Expose = false
	}
	assertRejected(t, request)
}

func TestStaticResolverRejectsPwnWithoutExactlyOneExposedContainer(t *testing.T) {
	for _, exposed := range []int{0, 2} {
		t.Run(fmt.Sprintf("exposed-%d", exposed), func(t *testing.T) {
			request := validPwnRequest()
			request.Containers = append(request.Containers, isolation.ContainerRequirement{
				Name: "sidecar", Ports: []int{9000}, RunAsUser: 10002,
			})
			request.Containers[0].Expose = exposed > 0
			request.Containers[1].Expose = exposed > 1
			assertRejected(t, request)
		})
	}
}

func TestStaticResolverRejectsPwnWithMultipleExposedPorts(t *testing.T) {
	request := validPwnRequest()
	request.Containers[0].Ports = []int{31337, 31338}
	assertRejected(t, request)
}

func TestStaticResolverRestrictsPwnWritablePathsToTmp(t *testing.T) {
	for _, writablePath := range []string{"/var/tmp", "/tmp2"} {
		t.Run(writablePath, func(t *testing.T) {
			request := validPwnRequest()
			request.Containers[0].WritablePaths = []isolation.WritablePath{{Path: writablePath, SizeMiB: 8}}
			assertRejected(t, request)
		})
	}

	request := validPwnRequest()
	request.Containers[0].WritablePaths = []isolation.WritablePath{{Path: "/tmp/cache", SizeMiB: 8}}
	if _, err := isolation.NewStaticResolver().Resolve(request); err != nil {
		t.Fatalf("Resolve() rejected /tmp descendant: %v", err)
	}
}

func TestStaticResolverRejectsDuplicateOrNestedWritablePaths(t *testing.T) {
	for _, paths := range [][]isolation.WritablePath{
		{{Path: "/tmp", SizeMiB: 8}, {Path: "/tmp", SizeMiB: 8}},
		{{Path: "/tmp", SizeMiB: 8}, {Path: "/tmp/cache", SizeMiB: 8}},
	} {
		request := validRequest()
		request.Containers[0].WritablePaths = paths
		assertRejected(t, request)
	}
}

func TestStaticResolverRejectsRetiredInternalConnections(t *testing.T) {
	for _, connections := range [][]isolation.InternalConnection{
		{},
		{{SourceContainer: "web", DestinationContainer: "api", Protocol: isolation.ProtocolTCP, Port: 8080}},
	} {
		request := validRequest()
		request.InternalConnections = connections
		assertRejected(t, request)
	}
}

func TestStaticResolverAllowsNoInternalConnections(t *testing.T) {
	request := validRequest()
	request.InternalConnections = nil
	if _, err := isolation.NewStaticResolver().Resolve(request); err != nil {
		t.Fatalf("Resolve() rejected omitted internal connections: %v", err)
	}
}

func TestStaticResolverRejectsEmptyContainerSet(t *testing.T) {
	request := validRequest()
	request.Containers = nil
	request.InternalConnections = nil
	assertRejected(t, request)
}

func validRequest() isolation.Request {
	return isolation.Request{
		WorkloadProfile: isolation.WorkloadProfileWeb,
		Containers: []isolation.ContainerRequirement{
			{Name: "web", Ports: []int{8080}, Expose: true, RunAsUser: 101, WritablePaths: []isolation.WritablePath{{Path: "/tmp", SizeMiB: 64}}},
			{Name: "api", Ports: []int{8080}, RunAsUser: 10001},
		},

		ResourceLimits: isolation.ResourceLimits{CPUMillicores: 350, MemoryMiB: 384, EphemeralStorageMiB: 700},
	}
}

func validPwnRequest() isolation.Request {
	return isolation.Request{
		WorkloadProfile: isolation.WorkloadProfilePwn,
		Containers: []isolation.ContainerRequirement{{
			Name: "challenge", Ports: []int{31337}, Expose: true, RunAsUser: 10001,
			WritablePaths: []isolation.WritablePath{{Path: "/tmp", SizeMiB: 64}},
		}},
		ResourceLimits: isolation.ResourceLimits{CPUMillicores: 175, MemoryMiB: 192, EphemeralStorageMiB: 320},
	}
}

func assertRejected(t *testing.T, request isolation.Request) {
	t.Helper()
	_, err := isolation.NewStaticResolver().Resolve(request)
	if !errors.Is(err, isolation.ErrPolicyRejected) {
		t.Fatalf("Resolve() error = %v, want ErrPolicyRejected", err)
	}
}
