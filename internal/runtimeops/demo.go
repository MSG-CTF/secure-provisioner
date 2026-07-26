package runtimeops

import (
	"context"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

const (
	DemoInstanceID = "018f3f1e-21b8-7a91-a30b-63b3400fd001"
	DemoTargetID   = "aws-apne2-k3s"
	DemoTeamID     = int64(18)
)

const demoNamespace = "ctf-018f3f1e21b87a91a30b63b3400fd001"

func NewDemoService() (*Service, error) {
	bindings := runtimebinding.NewMemoryStore()
	now := time.Now().UTC()
	_, _, err := bindings.SaveCreated(runtimebinding.Binding{
		InstanceID:        DemoInstanceID,
		TeamID:            DemoTeamID,
		TargetID:          DemoTargetID,
		Namespace:         demoNamespace,
		RuntimeWorkloadID: DemoTargetID + "/" + demoNamespace + "/challenge",
		State:             runtimebinding.StateCreated,
		CreatedAt:         now.Add(-37 * time.Minute),
		UpdatedAt:         now,
	})
	if err != nil {
		return nil, err
	}
	return NewService(
		demoCreateAdapter{},
		demoStatusSource{},
		demoDeleteAdapter{},
		bindings,
		operations.NewMemoryStore(nil),
		Config{
			MaxAttempts: 3,
			Worker: operations.WorkerConfig{
				Concurrency: 1,
				Backoff:     func(attempt int) time.Duration { return time.Duration(attempt) * 25 * time.Millisecond },
			},
		},
	)
}

type demoCreateAdapter struct{}

func (demoCreateAdapter) CreateWorkload(context.Context, provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	return provisioner.CreateWorkloadResult{}, provisioner.ErrRuntimeUnavailable
}

type demoDeleteAdapter struct{}

func (demoDeleteAdapter) DeleteWorkload(context.Context, provisioner.DeleteWorkloadCommand, runtimebinding.Binding) error {
	return nil
}

type demoStatusSource struct{}

func (demoStatusSource) Get(_ context.Context, binding runtimebinding.Binding) (k3s.RuntimeStatus, error) {
	startedAt := time.Now().UTC().Add(-36 * time.Minute)
	phase := "READY"
	if binding.State == runtimebinding.StateDeleting {
		phase = "TERMINATING"
	}
	return k3s.RuntimeStatus{
		InstanceID:        binding.InstanceID,
		TargetID:          binding.TargetID,
		RuntimeWorkloadID: binding.RuntimeWorkloadID,
		Phase:             phase,
		EndpointReady:     binding.State == runtimebinding.StateCreated,
		MetricsAvailable:  true,
		ObservedAt:        time.Now().UTC(),
		Containers: []k3s.ContainerRuntimeStatus{
			{
				PodName:      "challenge-7b8f64cd8f-kw2gz",
				Name:         "challenge",
				State:        "RUNNING",
				Ready:        true,
				RestartCount: 0,
				StartedAt:    &startedAt,
				Requests: k3s.ResourceValues{
					CPUMillicores:       100,
					MemoryMiB:           128,
					EphemeralStorageMiB: 256,
				},
				Limits: k3s.ResourceValues{
					CPUMillicores:       500,
					MemoryMiB:           512,
					EphemeralStorageMiB: 1024,
				},
				Usage: &k3s.ResourceUsage{CPUMillicores: 86, MemoryMiB: 146},
			},
			{
				PodName:      "challenge-7b8f64cd8f-kw2gz",
				Name:         "log-guard",
				State:        "RUNNING",
				Ready:        true,
				RestartCount: 1,
				StartedAt:    &startedAt,
				Requests: k3s.ResourceValues{
					CPUMillicores:       25,
					MemoryMiB:           32,
					EphemeralStorageMiB: 64,
				},
				Limits: k3s.ResourceValues{
					CPUMillicores:       100,
					MemoryMiB:           128,
					EphemeralStorageMiB: 256,
				},
				Usage: &k3s.ResourceUsage{CPUMillicores: 12, MemoryMiB: 31},
			},
		},
	}, nil
}
