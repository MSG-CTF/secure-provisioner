package isolation_test

import (
	"errors"
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

func TestStaticResolverRejectsUnknownProfiles(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*isolation.Request)
	}{
		{name: "isolation", mutate: func(request *isolation.Request) {
			request.IsolationRef.Name = "UNRESTRICTED"
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
	for _, path := range []string{"/proc", "/proc/self", "/sys", "/sys/kernel", "/var/run/secrets", "/var/run/secrets/kubernetes.io"} {
		t.Run(path, func(t *testing.T) {
			request := validRequest()
			request.Containers[0].WritablePaths = []isolation.WritablePath{{Path: path, SizeMiB: 1}}
			assertRejected(t, request)
		})
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

func TestStaticResolverRejectsPublicInternet(t *testing.T) {
	request := validRequest()
	request.OutboundMode = isolation.OutboundPublicInternet
	assertRejected(t, request)
}

func validRequest() isolation.Request {
	return isolation.Request{
		ChallengeID:  "web-chall2",
		IsolationRef: isolation.ProfileRef{Name: "STANDARD", Version: "v1"},
		ResourceRef:  isolation.ProfileRef{Name: "SMALL_MULTI", Version: "v1"},
		Containers: []isolation.ContainerRequirement{
			{Name: "web", RunAsUser: 101, WritablePaths: []isolation.WritablePath{{Path: "/tmp", SizeMiB: 64}}},
			{Name: "api", RunAsUser: 10001},
		},
		InternalConnections: []isolation.InternalConnection{{
			SourceContainer: "web", DestinationContainer: "api", Protocol: isolation.ProtocolTCP, Port: 8080,
		}},
		OutboundMode:   isolation.OutboundNone,
		ResourceLimits: isolation.ResourceLimits{CPUMillicores: 200, MemoryMiB: 256, EphemeralStorageMiB: 256},
	}
}

func assertRejected(t *testing.T, request isolation.Request) {
	t.Helper()
	_, err := isolation.NewStaticResolver().Resolve(request)
	if !errors.Is(err, isolation.ErrPolicyRejected) {
		t.Fatalf("Resolve() error = %v, want ErrPolicyRejected", err)
	}
}
