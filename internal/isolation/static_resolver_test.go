package isolation_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
)

func TestStaticResolverResolvesStandardPolicyWithoutAllowingBaselineOverrides(t *testing.T) {
	resolver := isolation.NewStaticResolver()
	got, err := resolver.Resolve(validRequest())
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

func TestStaticResolverComposesWebOnStandard(t *testing.T) {
	request := validRequest()

	got, err := isolation.NewStaticResolver().Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if got.WorkloadProfileRef != request.WorkloadProfileRef ||
		got.RuntimeClassName != "" ||
		got.EndpointProtocol != isolation.EndpointProtocolHTTP ||
		got.ExposureRequirement != isolation.ExposureAnySupported {
		t.Fatalf("resolved Web policy = %#v", got)
	}
}

func TestStaticResolverComposesPwnOnStandard(t *testing.T) {
	request := validPwnRequest()

	got, err := isolation.NewStaticResolver().Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if got.WorkloadProfileRef != request.WorkloadProfileRef ||
		got.RuntimeClassName != "gvisor" ||
		got.EndpointProtocol != isolation.EndpointProtocolTCP ||
		got.ExposureRequirement != isolation.ExposureNodePortOnly {
		t.Fatalf("resolved Pwn policy = %#v", got)
	}
}

func TestStaticResolverRejectsUnknownProfiles(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*isolation.Request)
	}{
		{name: "isolation", mutate: func(request *isolation.Request) {
			request.IsolationRef.Name = "UNRESTRICTED"
		}},
		{name: "workload", mutate: func(request *isolation.Request) {
			request.WorkloadProfileRef.Name = "KERNEL"
		}},
		{name: "resource", mutate: func(request *isolation.Request) {
			request.ResourceRef.Version = "v2"
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := validRequest()
			testCase.mutate(&request)
			assertRejected(t, request)
		})
	}
}

func TestStaticResolverRejectsResourceProfileNumericMismatch(t *testing.T) {
	request := validRequest()
	request.ResourceLimits.MemoryMiB++
	assertRejected(t, request)
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
			request.ResourceRef = isolation.ProfileRef{Name: "SMALL_MULTI", Version: "v1"}
			request.ResourceLimits = isolation.ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256}
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

func TestStaticResolverRejectsInternalConnectionWithUnknownContainerOrPort(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*isolation.Request)
	}{
		{name: "source", mutate: func(request *isolation.Request) {
			request.InternalConnections[0].SourceContainer = "worker"
		}},
		{name: "destination", mutate: func(request *isolation.Request) {
			request.InternalConnections[0].DestinationContainer = "worker"
		}},
		{name: "destination port", mutate: func(request *isolation.Request) {
			request.Containers[1].Ports = []int{8080}
			request.InternalConnections[0].Port = 9090
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := validRequest()
			testCase.mutate(&request)
			assertRejected(t, request)
		})
	}
}

func TestStaticResolverRejectsInternalConnectionWithoutDeclaredDestinationPort(t *testing.T) {
	request := validRequest()
	request.Containers[0].Ports = nil
	request.Containers[1].Ports = nil
	assertRejected(t, request)
}

func TestStaticResolverRejectsEmptyContainerSet(t *testing.T) {
	request := validRequest()
	request.Containers = nil
	request.InternalConnections = nil
	assertRejected(t, request)
}

func TestStaticResolverRejectsPublicInternet(t *testing.T) {
	request := validRequest()
	request.OutboundMode = isolation.OutboundPublicInternet
	assertRejected(t, request)
}

func validRequest() isolation.Request {
	return isolation.Request{
		ChallengeID:        "web-chall2",
		IsolationRef:       isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
		WorkloadProfileRef: isolation.ProfileRef{Name: "WEB", Version: "v1"},
		ResourceRef:        isolation.ProfileRef{Name: "SMALL_MULTI", Version: "v1"},
		Containers: []isolation.ContainerRequirement{
			{Name: "web", Ports: []int{8080}, Expose: true, RunAsUser: 101, WritablePaths: []isolation.WritablePath{{Path: "/tmp", SizeMiB: 64}}},
			{Name: "api", Ports: []int{8080}, RunAsUser: 10001},
		},
		InternalConnections: []isolation.InternalConnection{{
			SourceContainer: "web", DestinationContainer: "api", Protocol: isolation.ProtocolTCP, Port: 8080,
		}},
		OutboundMode:   isolation.OutboundNone,
		ResourceLimits: isolation.ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256},
	}
}

func validPwnRequest() isolation.Request {
	return isolation.Request{
		ChallengeID:        "pwn-buffer-01",
		IsolationRef:       isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
		WorkloadProfileRef: isolation.ProfileRef{Name: "PWN", Version: "v1"},
		ResourceRef:        isolation.ProfileRef{Name: "SMALL_SINGLE", Version: "v1"},
		Containers: []isolation.ContainerRequirement{{
			Name: "challenge", Ports: []int{31337}, Expose: true, RunAsUser: 10001,
			WritablePaths: []isolation.WritablePath{{Path: "/tmp", SizeMiB: 64}},
		}},
		OutboundMode:   isolation.OutboundNone,
		ResourceLimits: isolation.ResourceLimits{CPUMillicores: 100, MemoryMiB: 128, EphemeralStorageMiB: 128},
	}
}

func assertRejected(t *testing.T, request isolation.Request) {
	t.Helper()
	_, err := isolation.NewStaticResolver().Resolve(request)
	if !errors.Is(err, isolation.ErrPolicyRejected) {
		t.Fatalf("Resolve() error = %v, want ErrPolicyRejected", err)
	}
}
