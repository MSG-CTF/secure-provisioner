package imageprep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"k8s.io/apimachinery/pkg/util/validation"
	"os/exec"
	"path/filepath"
	"regexp"
)

type AgentTarget struct {
	Namespace  string `json:"namespace,omitempty"`
	AgentImage string `json:"agent_image,omitempty"`
	TargetID   string `json:"target_id"`
	NodeName   string `json:"node_name"`
	NodeUID    string `json:"node_uid"`
	MachineID  string `json:"machine_id,omitempty"`
	Mode       string `json:"mode"`
	Command    string `json:"command,omitempty"`
	SSHHost    string `json:"ssh_host,omitempty"`
	SSHConfig  string `json:"ssh_config,omitempty"`
}
type Transport struct {
	Nodes      []AgentTarget                                                            `json:"nodes"`
	Kubernetes func(context.Context, AgentTarget, Node, AgentRequest) (Evidence, error) `json:"-"`
}

func ParseAgentTargets(data []byte) (*Transport, error) {
	var t Transport
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if len(data) > 1<<20 || d.Decode(&t) != nil || d.Decode(new(any)) != io.EOF || len(t.Nodes) == 0 {
		return nil, errors.New("invalid trusted image agent configuration")
	}
	seen := map[string]bool{}
	host := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	for _, n := range t.Nodes {
		key := n.TargetID + "/" + n.NodeName
		if !validID(n.TargetID) || !validID(n.NodeUID) || (n.MachineID != "" && !validID(n.MachineID)) || n.NodeName == "" || seen[key] {
			return nil, errors.New("invalid trusted image agent identity")
		}
		seen[key] = true
		switch n.Mode {
		case "kubernetes":
			if len(validation.IsDNS1123Label(n.Namespace)) != 0 || !ValidImage(n.AgentImage) || n.Command != "" || n.SSHHost != "" || n.SSHConfig != "" {
				return nil, errors.New("invalid trusted Kubernetes agent configuration")
			}
		case "local":
			if !filepath.IsAbs(n.Command) || n.SSHHost != "" || n.SSHConfig != "" {
				return nil, errors.New("invalid local agent command")
			}
		case "ssh":
			if !host.MatchString(n.SSHHost) || !filepath.IsAbs(n.SSHConfig) || n.Command != "" {
				return nil, errors.New("invalid trusted SSH configuration")
			}
		default:
			return nil, errors.New("invalid agent transport")
		}
	}
	return &t, nil
}
func (t *Transport) Run(ctx context.Context, n Node, image string, pull bool) (Evidence, error) {
	var selected *AgentTarget
	for i := range t.Nodes {
		candidate := &t.Nodes[i]
		if candidate.TargetID == n.TargetID && candidate.NodeName == n.Name && candidate.NodeUID == n.UID && (candidate.MachineID == "" || candidate.MachineID == n.MachineID) {
			selected = candidate
			break
		}
	}
	if selected == nil {
		return Evidence{}, Failure{Code: "AGENT_UNAVAILABLE"}
	}
	if selected.Mode == "kubernetes" {
		if t.Kubernetes == nil {
			return Evidence{}, Failure{Code: "AGENT_UNAVAILABLE"}
		}
		e, err := t.Kubernetes(ctx, *selected, n, AgentRequest{Image: image, Architecture: n.Architecture, Pull: pull})
		if err != nil {
			return Evidence{}, err
		}
		if n.MachineID == "" || e.MachineID != n.MachineID || !validEvidence(n, image, e) {
			return Evidence{}, Failure{Code: "NODE_IDENTITY_MISMATCH"}
		}
		return e, nil
	}
	input, err := json.Marshal(AgentRequest{Image: image, Architecture: n.Architecture, Pull: pull})
	if err != nil {
		return Evidence{}, err
	}
	var cmd *exec.Cmd
	if selected.Mode == "local" {
		cmd = exec.CommandContext(ctx, selected.Command)
	} else {
		cmd = exec.CommandContext(ctx, "ssh", "-F", selected.SSHConfig, "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=10", "-T", "--", selected.SSHHost, "sudo -n /usr/local/libexec/runtime-image-agent")
	}
	cmd.Stdin = bytes.NewReader(input)
	out := &boundedBuffer{Limit: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Evidence{}, Failure{Code: "NETWORK_TIMEOUT"}
		}
		return Evidence{}, Failure{Code: "AGENT_UNAVAILABLE"}
	}
	var reply AgentResponse
	d := json.NewDecoder(bytes.NewReader(out.Bytes()))
	d.DisallowUnknownFields()
	if d.Decode(&reply) != nil || d.Decode(new(any)) != io.EOF {
		return Evidence{}, Failure{Code: "AGENT_UNAVAILABLE"}
	}
	if reply.ErrorCode != "" {
		return Evidence{}, Failure{Code: ErrorCode(Failure{Code: reply.ErrorCode})}
	}
	if reply.Evidence == nil || n.MachineID == "" || reply.Evidence.MachineID != n.MachineID || !validEvidence(n, image, *reply.Evidence) {
		return Evidence{}, Failure{Code: "NODE_IDENTITY_MISMATCH"}
	}
	return *reply.Evidence, nil
}
