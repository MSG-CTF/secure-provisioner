package imageprep

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"slices"
	"strings"
)

const socket = "/run/k3s/containerd/containerd.sock"

type AgentIdentity struct {
	NodeUID      string
	MachineID    string
	BootID       string
	OS           string
	Architecture string
}
type AgentRequest struct {
	Image        string `json:"image"`
	Architecture string `json:"architecture"`
	Pull         bool   `json:"pull"`
}
type AgentResponse struct {
	Evidence  *Evidence `json:"evidence,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
}
type Commands interface {
	Run(context.Context, io.Writer, ...string) error
}
type Agent struct {
	Commands Commands
	Identity func() (AgentIdentity, error)
}
type ExecCommands struct{ Binary string }
type boundedBuffer struct {
	bytes.Buffer
	Limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > b.Limit {
		return 0, errors.New("output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func (c ExecCommands) Run(ctx context.Context, out io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	cmd.Stdout = out
	stderr := &boundedBuffer{Limit: 64 << 10}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Failure{Code: "NETWORK_TIMEOUT"}
		}
		message := strings.ToLower(stderr.String())
		code := "AGENT_UNAVAILABLE"
		switch {
		case strings.Contains(message, "no space left"), strings.Contains(message, "resource exhausted"):
			code = "RESOURCE_EXHAUSTED"
		case strings.Contains(message, "unauthorized"), strings.Contains(message, "denied"), strings.Contains(message, "401"), strings.Contains(message, "403"):
			code = "REGISTRY_UNAUTHORIZED"
		case strings.Contains(message, "429"), strings.Contains(message, "too many requests"):
			code = "RATE_LIMITED"
		case strings.Contains(message, "manifest unknown"), strings.Contains(message, "not found"), strings.Contains(message, "404"):
			code = "MANIFEST_NOT_FOUND"
		case strings.Contains(message, "500"), strings.Contains(message, "502"), strings.Contains(message, "503"), strings.Contains(message, "504"):
			code = "REGISTRY_UNAVAILABLE"
		case strings.Contains(message, "timeout"), strings.Contains(message, "connection reset"), strings.Contains(message, "connection refused"), strings.Contains(message, "temporary failure"):
			code = "NETWORK_TIMEOUT"
		}
		return Failure{Code: code}
	}
	return nil
}
func (a *Agent) Prepare(ctx context.Context, r AgentRequest) (Evidence, error) {
	if !ValidImage(r.Image) || !validArchitecture(r.Architecture) {
		return Evidence{}, ErrInvalid
	}
	identity, err := a.Identity()
	if err != nil || identity.NodeUID == "" || identity.MachineID == "" || identity.BootID == "" {
		return Evidence{}, Failure{Code: "NODE_IDENTITY_MISMATCH"}
	}
	if identity.OS != "linux" || identity.Architecture != r.Architecture {
		return Evidence{}, Failure{Code: "PLATFORM_MISMATCH"}
	}
	resolved, err := a.verify(ctx, r)
	if err != nil && r.Pull && ErrorCode(err) != "PLATFORM_MISMATCH" {
		if err := a.Commands.Run(ctx, io.Discard, "crictl", "--runtime-endpoint", "unix://"+socket, "--image-endpoint", "unix://"+socket, "pull", r.Image); err != nil {
			return Evidence{}, err
		}
		resolved, err = a.verify(ctx, r)
	}
	if err != nil {
		return Evidence{}, err
	}
	final, err := a.Identity()
	if err != nil || final != identity {
		return Evidence{}, Failure{Code: "NODE_IDENTITY_MISMATCH"}
	}
	return Evidence{NodeUID: identity.NodeUID, MachineID: identity.MachineID, BootID: identity.BootID, OS: identity.OS, Architecture: identity.Architecture, Image: r.Image, ResolvedDigest: resolved, Complete: true}, nil
}

type descriptor struct {
	Digest   string `json:"digest"`
	Size     int64  `json:"size"`
	Platform struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform"`
}
type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	Manifests     []descriptor `json:"manifests"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
	ArtifactType  string       `json:"artifactType"`
}
type countedHash struct {
	writer io.Writer
	size   int64
}

func (w *countedHash) Write(p []byte) (int, error) {
	n, e := w.writer.Write(p)
	w.size += int64(n)
	return n, e
}
func (a *Agent) blob(ctx context.Context, d descriptor, keep bool) ([]byte, error) {
	if !DigestPattern.MatchString(d.Digest) || d.Size < 0 {
		return nil, Failure{Code: "CONTENT_INCOMPLETE"}
	}
	h := sha256.New()
	buffer := &boundedBuffer{Limit: 8 << 20}
	var destination io.Writer = h
	if keep {
		destination = io.MultiWriter(h, buffer)
	}
	counter := &countedHash{writer: destination}
	if err := a.Commands.Run(ctx, counter, "ctr", "--address", socket, "--namespace", "k8s.io", "content", "get", d.Digest); err != nil {
		return nil, Failure{Code: "CONTENT_INCOMPLETE"}
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.Digest || (d.Size > 0 && counter.size != d.Size) {
		return nil, Failure{Code: "CONTENT_INCOMPLETE"}
	}
	return buffer.Bytes(), nil
}
func (a *Agent) verify(ctx context.Context, r AgentRequest) (string, error) {
	inspected := &boundedBuffer{Limit: 1 << 20}
	if err := a.Commands.Run(ctx, inspected, "crictl", "--runtime-endpoint", "unix://"+socket, "--image-endpoint", "unix://"+socket, "inspecti", r.Image); err != nil {
		return "", Failure{Code: "CONTENT_INCOMPLETE"}
	}
	var status struct {
		Status struct {
			ID          string   `json:"id"`
			RepoDigests []string `json:"repoDigests"`
		} `json:"status"`
	}
	if json.Unmarshal(inspected.Bytes(), &status) != nil || !slices.Contains(status.Status.RepoDigests, r.Image) {
		return "", Failure{Code: "CONTENT_INCOMPLETE"}
	}
	_, root, _ := strings.Cut(r.Image, "@")
	d := descriptor{Digest: root}
	payload, err := a.blob(ctx, d, true)
	if err != nil {
		return "", err
	}
	var m manifest
	if json.Unmarshal(payload, &m) != nil || m.SchemaVersion != 2 || m.ArtifactType != "" {
		return "", Failure{Code: "CONTENT_INCOMPLETE"}
	}
	if len(m.Manifests) > 0 {
		selected := []descriptor{}
		for _, child := range m.Manifests {
			if child.Platform.OS == "linux" && strings.ToUpper(child.Platform.Architecture) == r.Architecture && child.Platform.Variant == "" {
				selected = append(selected, child)
			}
		}
		if len(selected) != 1 {
			return "", Failure{Code: "PLATFORM_MISMATCH"}
		}
		d = selected[0]
		payload, err = a.blob(ctx, d, true)
		if err != nil {
			return "", err
		}
		m = manifest{}
		if json.Unmarshal(payload, &m) != nil || len(m.Manifests) > 0 || m.SchemaVersion != 2 || m.ArtifactType != "" {
			return "", Failure{Code: "CONTENT_INCOMPLETE"}
		}
	}
	config, err := a.blob(ctx, m.Config, true)
	if err != nil {
		return "", err
	}
	if status.Status.ID != m.Config.Digest {
		return "", Failure{Code: "CONTENT_INCOMPLETE"}
	}
	var platform struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	}
	if json.Unmarshal(config, &platform) != nil || platform.OS != "linux" || strings.ToUpper(platform.Architecture) != r.Architecture || platform.Variant != "" {
		return "", Failure{Code: "PLATFORM_MISMATCH"}
	}
	for _, layer := range m.Layers {
		if _, err := a.blob(ctx, layer, false); err != nil {
			return "", err
		}
	}
	return d.Digest, nil
}
