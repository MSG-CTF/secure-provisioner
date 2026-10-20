// Package vm runs an operator-approved Compose profile on an exclusive, warm VM.
// The guest helper accepts structured actions; callers never supply shell commands.
package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/k3s"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
)

type Container struct {
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	Ports       []int    `json:"ports"`
	PublicPorts []int    `json:"public_ports"`
	EnvNames    []string `json:"env_names"`
	SecretNames []string `json:"secret_names"`
}
type Target struct {
	ID         string                 `json:"target_id"`
	Host       string                 `json:"ssh_host"`
	Port       int                    `json:"ssh_port"`
	User       string                 `json:"ssh_user"`
	Identity   string                 `json:"identity_file"`
	KnownHosts string                 `json:"known_hosts_file"`
	Profile    string                 `json:"profile_sha256"`
	PublicURL  string                 `json:"public_url"`
	Limits     httpapi.ResourceLimits `json:"resource_limits"`
	Containers []Container            `json:"containers"`
}
type catalog struct {
	SchemaVersion int      `json:"schema_version"`
	Targets       []Target `json:"targets"`
}
type Reply struct {
	OK               bool             `json:"ok"`
	Code             string           `json:"code"`
	CleanupCompleted bool             `json:"cleanup_completed"`
	Ready            bool             `json:"ready"`
	Deleted          bool             `json:"deleted"`
	Containers       []GuestContainer `json:"containers"`
}
type GuestContainer struct {
	Name     string `json:"name"`
	Running  bool   `json:"running"`
	Ready    bool   `json:"ready"`
	Restarts int32  `json:"restarts"`
}
type Transport interface {
	Call(context.Context, Target, map[string]any) (Reply, error)
}
type SSHTransport struct{}

func (SSHTransport) Call(ctx context.Context, t Target, body map[string]any) (Reply, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return Reply{}, err
	}
	cmd := exec.CommandContext(ctx, "ssh", "-T", "-p", fmt.Sprint(t.Port), "-i", t.Identity, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+t.KnownHosts, "-o", "HostKeyAlias="+t.ID, "-o", "ConnectTimeout=8", t.User+"@"+t.Host, "sudo -n /usr/local/libexec/msgctf-vm-agent")
	cmd.Stdin = bytes.NewReader(raw)
	// Never relay SSH diagnostics or Docker output: they can contain environment values.
	var out limitedBuffer
	cmd.Stdout = &out
	if err = cmd.Run(); err != nil {
		return Reply{}, errors.New("VM transport unavailable")
	}
	var reply Reply
	if json.Unmarshal(out.Bytes(), &reply) != nil {
		return Reply{}, errors.New("invalid VM response")
	}
	return reply, nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errors.New("VM response too large")
	}
	return b.Buffer.Write(p)
}

type Router struct {
	targets   map[string]Target
	transport Transport
	secrets   k3s.SecretResolver
	create    runtimeops.CreateAdapter
	status    runtimeops.StatusSource
	delete    runtimeops.DeleteAdapter
}

func Load(path string, secrets k3s.SecretResolver, create runtimeops.CreateAdapter, status runtimeops.StatusSource, del runtimeops.DeleteAdapter) (*Router, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("VM catalog too large")
	}
	var c catalog
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return nil, err
	}
	if c.SchemaVersion != 1 || len(c.Targets) == 0 {
		return nil, errors.New("invalid VM catalog")
	}
	r := &Router{targets: map[string]Target{}, transport: SSHTransport{}, secrets: secrets, create: create, status: status, delete: del}
	safe := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	for _, t := range c.Targets {
		if !safe.MatchString(t.ID) || !safe.MatchString(t.Host) || !safe.MatchString(t.User) || t.Port < 1 || t.Port > 65535 || !filepath.IsAbs(t.Identity) || !filepath.IsAbs(t.KnownHosts) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(t.Profile) || len(t.Containers) == 0 || t.Limits.CPUMillicores <= 0 || t.Limits.MemoryMiB <= 0 || t.Limits.EphemeralStorageMiB <= 0 {
			return nil, errors.New("invalid dedicated VM target")
		}
		if _, ok := r.targets[t.ID]; ok {
			return nil, errors.New("duplicate VM target")
		}
		r.targets[t.ID] = t
	}
	return r, nil
}
func (r *Router) Apply(req *httpapi.CreateWorkloadRequest) error {
	t, ok := r.targets[req.Target.TargetID]
	if req.Target.RuntimeType != httpapi.RuntimeTypeVM {
		if ok {
			return errors.New("VM target requires VM type")
		}
		return nil
	}
	if !ok || req.IsolationProfile != "WEB" || req.Workload.ResourceLimits != t.Limits || len(req.Workload.Containers) != len(t.Containers) {
		return errors.New("VM profile mismatch")
	}
	seen := map[string]bool{}
	for _, got := range req.Workload.Containers {
		i := slices.IndexFunc(t.Containers, func(c Container) bool { return c.Name == got.Name })
		if i < 0 || seen[got.Name] {
			return errors.New("VM container mismatch")
		}
		seen[got.Name] = true
		want := t.Containers[i]
		pub := got.ExposedPorts
		if pub == nil && got.Expose {
			pub = got.Ports
		}
		scratchHint := len(got.WritablePaths) == 0 || (len(got.WritablePaths) == 1 && got.WritablePaths[0].Path == "/tmp" && got.WritablePaths[0].SizeMiB == 64)
		if got.Image != want.Image || !slices.Equal(got.Ports, want.Ports) || !slices.Equal(pub, want.PublicPorts) || !scratchHint || (len(want.SecretNames) > 0 && got.SecretRef == "") {
			return errors.New("VM container mismatch")
		}
	}
	req.VMProfile = t.Profile
	return nil
}
func (r *Router) Resolve(req isolation.Request) (isolation.ResolvedPolicy, error) {
	if req.VMProfile == "" {
		return isolation.NewStaticResolver().Resolve(req)
	}
	for _, t := range r.targets {
		if t.Profile == req.VMProfile {
			return isolation.ResolvedPolicy{IsolationRef: isolation.ProfileRef{Name: "DEDICATED_VM", Version: t.Profile}, WorkloadProfileRef: isolation.ProfileRef{Name: "WEB", Version: "v1"}, Containers: req.Containers, ResourceLimits: req.ResourceLimits, EndpointProtocol: isolation.EndpointProtocolHTTP, OutboundMode: isolation.OutboundNone}, nil
		}
	}
	return isolation.ResolvedPolicy{}, errors.New("unknown VM profile")
}
func namespace(id string) string { return "ctf-" + strings.ReplaceAll(id, "-", "") }
func identity(c provisioner.CreateWorkloadCommand) string {
	h := sha256.Sum256([]byte(c.TargetID + "\n" + c.InstanceID + "\n" + string(c.TeamID) + "\n" + c.RequestFingerprint))
	return hex.EncodeToString(h[:])
}
func workID(target, id string) string { return target + "/" + namespace(id) + "/compose" }
func (r *Router) call(ctx context.Context, t Target, body map[string]any) (Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	x, err := r.transport.Call(ctx, t, body)
	if err != nil {
		return Reply{}, operations.NewExecutionError("VM_UNAVAILABLE", true, nil)
	}
	if !x.OK {
		// A daemon restart or interrupted helper must not permanently fail a
		// partially completed delete. Retrying retains the same owner generation.
		retryable := x.Code == "VM_DOCKER_FAILED" || x.Code == "VM_AGENT_FAILED"
		err := operations.NewExecutionError(x.Code, retryable, nil)
		if x.CleanupCompleted {
			return x, provisioner.WithCreateCleanupCompleted(err)
		}
		return x, err
	}
	return x, nil
}
func (r *Router) CreateWorkload(ctx context.Context, c provisioner.CreateWorkloadCommand) (provisioner.CreateWorkloadResult, error) {
	return r.CreateWorkloadForOperation(ctx, c, "")
}
func (r *Router) CreateWorkloadForOperation(ctx context.Context, c provisioner.CreateWorkloadCommand, operationID string) (result provisioner.CreateWorkloadResult, err error) {
	t, ok := r.targets[c.TargetID]
	if !ok {
		if c.RuntimeType == provisioner.RuntimeTypeVM {
			// A queued create may have reached the guest before a catalog change.
			// Keep its generation pending until the operator restores that target.
			return provisioner.CreateWorkloadResult{}, provisioner.WithCreateCleanupPending(operations.NewExecutionError("TARGET_NOT_FOUND", true, nil), provisioner.CreateCleanup{NamespaceUID: identity(c), RuntimeWorkloadID: workID(c.TargetID, c.InstanceID), FailureCode: "VM_CREATE_FAILED"})
		}
		if x, ok := r.create.(interface {
			CreateWorkloadForOperation(context.Context, provisioner.CreateWorkloadCommand, string) (provisioner.CreateWorkloadResult, error)
		}); ok {
			return x.CreateWorkloadForOperation(ctx, c, operationID)
		}
		return r.create.CreateWorkload(ctx, c)
	}
	started := false
	defer func() {
		if err != nil && !started {
			err = provisioner.WithCreateCleanupPending(err, provisioner.CreateCleanup{NamespaceUID: identity(c), RuntimeWorkloadID: workID(t.ID, c.InstanceID), FailureCode: "VM_CREATE_FAILED"})
		}
	}()
	if c.RuntimeType != provisioner.RuntimeTypeVM || c.PolicyRequest.VMProfile != t.Profile {
		return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("VM_POLICY_REJECTED", false, nil)
	}
	env := map[string]map[string]string{}
	shared := map[string]string{}
	for _, container := range c.Containers {
		i := slices.IndexFunc(t.Containers, func(x Container) bool { return x.Name == container.Name })
		if i < 0 {
			return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("VM_POLICY_REJECTED", false, nil)
		}
		want := t.Containers[i]
		values := maps.Clone(container.Env)
		if values == nil {
			values = map[string]string{}
		}
		if container.SecretRef != "" {
			if r.secrets == nil {
				return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("SECRET_RESOLUTION_FAILED", false, nil)
			}
			secret, err := r.secrets.Resolve(ctx, container.SecretRef, container.Name, container.Image)
			if err != nil {
				return provisioner.CreateWorkloadResult{}, err
			}
			if len(secret) != len(want.SecretNames) {
				return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("SECRET_SCOPE_MISMATCH", false, nil)
			}
			for key, value := range secret {
				if !slices.Contains(want.SecretNames, key) || value == "" {
					return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("SECRET_SCOPE_MISMATCH", false, nil)
				}
				if old, ok := shared[key]; ok && old != value {
					return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("SECRET_SCOPE_MISMATCH", false, nil)
				}
				shared[key] = value
				if _, ok := values[key]; ok {
					return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("SECRET_SCOPE_MISMATCH", false, nil)
				}
				values[key] = value
			}
		}
		if len(values) != len(want.EnvNames) {
			return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("ENVIRONMENT_MISMATCH", false, nil)
		}
		for _, key := range want.EnvNames {
			if _, ok := values[key]; !ok {
				return provisioner.CreateWorkloadResult{}, operations.NewExecutionError("ENVIRONMENT_MISMATCH", false, nil)
			}
		}
		env[container.Name] = values
	}
	uid := identity(c)
	body := map[string]any{"action": "create", "instance_id": c.InstanceID, "team_id": c.TeamID, "uid": uid, "profile_sha256": t.Profile, "target_id": t.ID, "env": env}
	started = true
	reply, err := r.call(ctx, t, body)
	if err != nil {
		if !reply.CleanupCompleted {
			return provisioner.CreateWorkloadResult{}, provisioner.WithCreateCleanupPending(err, provisioner.CreateCleanup{NamespaceUID: uid, RuntimeWorkloadID: workID(t.ID, c.InstanceID), FailureCode: "VM_CREATE_FAILED"})
		}
		return provisioner.CreateWorkloadResult{}, err
	}
	if !reply.Ready {
		return provisioner.CreateWorkloadResult{}, provisioner.WithCreateCleanupPending(operations.NewExecutionError("VM_NOT_READY", false, nil), provisioner.CreateCleanup{NamespaceUID: uid, RuntimeWorkloadID: workID(t.ID, c.InstanceID), FailureCode: "VM_CREATE_FAILED"})
	}
	endpoints := []provisioner.WorkloadEndpoint{}
	for _, container := range t.Containers {
		for _, port := range container.PublicPorts {
			endpoints = append(endpoints, provisioner.WorkloadEndpoint{ContainerName: container.Name, Port: port, Protocol: isolation.EndpointProtocolHTTP, ServiceURL: t.PublicURL})
		}
	}
	return provisioner.CreateWorkloadResult{RuntimeWorkloadID: workID(t.ID, c.InstanceID), NamespaceUID: uid, ServiceURL: t.PublicURL, Endpoints: endpoints}, nil
}
func (r *Router) DeleteWorkload(ctx context.Context, c provisioner.DeleteWorkloadCommand, b runtimebinding.Binding) error {
	t, ok := r.targets[b.TargetID]
	if !ok {
		if c.RuntimeType == provisioner.RuntimeTypeVM {
			return operations.NewExecutionError("TARGET_NOT_FOUND", true, nil)
		}
		return r.delete.DeleteWorkload(ctx, c, b)
	}
	if c.RuntimeType != provisioner.RuntimeTypeVM || c.TeamID != b.TeamID || c.TargetID != b.TargetID || c.InstanceID != b.InstanceID || c.RuntimeWorkloadID != b.RuntimeWorkloadID {
		return operations.NewExecutionError("RUNTIME_OWNERSHIP_MISMATCH", false, nil)
	}
	x, err := r.call(ctx, t, map[string]any{"action": "delete", "instance_id": b.InstanceID, "team_id": b.TeamID, "uid": b.NamespaceUID, "target_id": b.TargetID})
	if err != nil {
		return err
	}
	if !x.Deleted {
		return operations.NewExecutionError("VM_DELETE_INCOMPLETE", true, nil)
	}
	return nil
}
func (r *Router) Get(ctx context.Context, b runtimebinding.Binding) (k3s.RuntimeStatus, error) {
	t, ok := r.targets[b.TargetID]
	if !ok {
		if strings.HasPrefix(b.IsolationProfile, "DEDICATED_VM@") {
			return k3s.RuntimeStatus{}, operations.NewExecutionError("TARGET_NOT_FOUND", true, nil)
		}
		return r.status.Get(ctx, b)
	}
	x, err := r.call(ctx, t, map[string]any{"action": "status", "instance_id": b.InstanceID, "team_id": b.TeamID, "uid": b.NamespaceUID, "target_id": b.TargetID})
	if err != nil {
		return k3s.RuntimeStatus{}, err
	}
	phase := "RUNNING"
	if x.Ready {
		phase = "READY"
	}
	if x.Deleted {
		phase = "TERMINATED"
	}
	out := k3s.RuntimeStatus{InstanceID: b.InstanceID, TeamID: b.TeamID, TargetID: b.TargetID, RuntimeWorkloadID: b.RuntimeWorkloadID, Phase: phase, EndpointReady: x.Ready, ObservedAt: time.Now().UTC(), Node: k3s.NodeRuntimeStatus{Ready: true}}
	for _, c := range x.Containers {
		state := "TERMINATED"
		if c.Running {
			state = "RUNNING"
		}
		out.Containers = append(out.Containers, k3s.ContainerRuntimeStatus{PodName: namespace(b.InstanceID), Name: c.Name, State: state, Ready: c.Ready, RestartCount: c.Restarts})
	}
	return out, nil
}
func (r *Router) CleanupFailedCreate(ctx context.Context, c provisioner.CreateWorkloadCommand, x provisioner.CreateCleanup) error {
	if _, ok := r.targets[c.TargetID]; ok {
		return r.DeleteWorkload(ctx, provisioner.DeleteWorkloadCommand{InstanceID: c.InstanceID, TeamID: c.TeamID, TargetID: c.TargetID, RuntimeType: c.RuntimeType, RuntimeWorkloadID: x.RuntimeWorkloadID}, runtimebinding.Binding{InstanceID: c.InstanceID, TeamID: c.TeamID, TargetID: c.TargetID, RuntimeWorkloadID: x.RuntimeWorkloadID, NamespaceUID: x.NamespaceUID})
	}
	if c.RuntimeType == provisioner.RuntimeTypeVM {
		return operations.NewExecutionError("TARGET_NOT_FOUND", true, nil)
	}
	if cleaner, ok := r.create.(k3s.FailedCreateCleaner); ok {
		return cleaner.CleanupFailedCreate(ctx, c, x)
	}
	return operations.NewExecutionError("ROLLBACK_FAILED", false, nil)
}
