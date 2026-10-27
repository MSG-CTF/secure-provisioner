package imageprep

import (
	"context"
	"errors"
)

// FileTransport takes a fresh validated snapshot for each agent operation. The
// operator must publish complete configurations by rename in a protected directory.
// Unreadable or invalid updates deny execution instead of retaining stale trust.
type FileTransport struct {
	path       string
	kubernetes func(context.Context, AgentTarget, Node, AgentRequest) (Evidence, error)
}

func NewFileTransport(path string, kubernetes func(context.Context, AgentTarget, Node, AgentRequest) (Evidence, error)) (*FileTransport, error) {
	t := &FileTransport{path: path, kubernetes: kubernetes}
	if _, err := t.snapshot(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *FileTransport) snapshot() (*Transport, error) {
	data, err := readTrustedAgentConfig(t.path)
	if err != nil {
		return nil, errors.New("cannot read trusted image agent configuration")
	}
	transport, err := ParseAgentTargets(data)
	if err != nil {
		return nil, err
	}
	transport.Kubernetes = t.kubernetes
	return transport, nil
}

func (t *FileTransport) Run(ctx context.Context, node Node, image string, pull bool) (Evidence, error) {
	transport, err := t.snapshot()
	if err != nil {
		return Evidence{}, Failure{Code: "AGENT_UNAVAILABLE"}
	}
	return transport.Run(ctx, node, image, pull)
}
