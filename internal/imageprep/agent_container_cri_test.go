package imageprep

import (
	"context"
	"io"
	"testing"
)

// A container mounts the K3s binary/data and CRI socket, not host crictl.yaml.
// K3s otherwise selects a nonexistent applet-relative config even with explicit endpoints.
type containerCRICommands struct{ delegate Commands }

func (c containerCRICommands) Run(ctx context.Context, output io.Writer, args ...string) error {
	if len(args) > 0 && args[0] == "crictl" {
		explicit := false
		for i := 1; i+1 < len(args); i++ {
			if args[i] == "--config" && args[i+1] == "/dev/null" {
				explicit = true
			}
		}
		if !explicit {
			return Failure{Code: "AGENT_UNAVAILABLE"}
		}
	}
	return c.delegate.Run(ctx, output, args...)
}

func TestAgentContainerPullAndCacheReuseWithoutHostCRIConfig(t *testing.T) {
	agent, fixture, _ := agentFixture()
	agent.Commands = containerCRICommands{delegate: fixture}
	request := AgentRequest{Image: fixture.image, Architecture: "AMD64", Pull: true}
	evidence, err := agent.Prepare(context.Background(), request)
	if err != nil || !evidence.Complete || fixture.pulls != 1 {
		t.Fatalf("container cold preparation failed: complete=%v err=%v pulls=%d", evidence.Complete, err, fixture.pulls)
	}
	evidence, err = agent.Prepare(context.Background(), request)
	if err != nil || !evidence.Complete || fixture.pulls != 1 {
		t.Fatalf("container cache reuse failed: complete=%v err=%v pulls=%d", evidence.Complete, err, fixture.pulls)
	}
}
