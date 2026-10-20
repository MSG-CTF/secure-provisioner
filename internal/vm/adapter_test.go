package vm

import (
	"context"
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
	"testing"
)

func target() Target {
	return Target{ID: "exclusive-vm", Profile: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PublicURL: "http://192.0.2.1:18080", Limits: httpapi.ResourceLimits{CPUMillicores: 2000, MemoryMiB: 4000, EphemeralStorageMiB: 2048}, Containers: []Container{{Name: "portal", Image: "ghcr.io/example/portal@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ports: []int{8080}, PublicPorts: []int{8080}, EnvNames: []string{"PORT"}}}}
}

func TestRemovedTargetKeepsExactGenerationPending(t *testing.T) {
	r := &Router{targets: map[string]Target{}}
	c := provisioner.CreateWorkloadCommand{RuntimeType: provisioner.RuntimeTypeVM, TargetID: "removed-vm", InstanceID: "00000000-0000-4000-8000-000000000001", TeamID: "00000000-0000-4000-8000-000000000002", RequestFingerprint: "accepted-request"}
	_, err := r.CreateWorkload(context.Background(), c)
	var pending interface {
		PendingCreateCleanup() provisioner.CreateCleanup
	}
	if !errors.As(err, &pending) || pending.PendingCreateCleanup().NamespaceUID != identity(c) {
		t.Fatal("missing catalog target lost the accepted generation", err)
	}
	if err := r.CleanupFailedCreate(context.Background(), c, pending.PendingCreateCleanup()); err == nil {
		t.Fatal("unreachable target was reported cleaned")
	}
	if _, err := r.Get(context.Background(), runtimebinding.Binding{TargetID: c.TargetID, IsolationProfile: "DEDICATED_VM@profile"}); err == nil {
		t.Fatal("VM status fell through to the Kubernetes adapter")
	}
}
func request() httpapi.CreateWorkloadRequest {
	t := target()
	return httpapi.CreateWorkloadRequest{IsolationProfile: "WEB", Target: httpapi.RuntimeTarget{RuntimeType: httpapi.RuntimeTypeVM, TargetID: t.ID}, Workload: httpapi.RuntimeWorkload{ResourceLimits: t.Limits, Containers: []httpapi.RuntimeContainer{{Name: "portal", Image: t.Containers[0].Image, Ports: []int{8080}, Expose: true, Env: map[string]string{"PORT": "8080"}}}}}
}
func TestExactVMProfileAdmission(t *testing.T) {
	cfg := target()
	r := &Router{targets: map[string]Target{cfg.ID: cfg}}
	good := request()
	if err := r.Apply(&good); err != nil || good.VMProfile != cfg.Profile {
		t.Fatal("exact profile rejected", err)
	}
	for _, change := range []func(*httpapi.CreateWorkloadRequest){
		func(x *httpapi.CreateWorkloadRequest) { x.Target.RuntimeType = httpapi.RuntimeTypeKubernetes },
		func(x *httpapi.CreateWorkloadRequest) { x.Target.TargetID = "another-vm" },
		func(x *httpapi.CreateWorkloadRequest) {
			x.Workload.Containers[0].Image = "ghcr.io/attacker/image@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		func(x *httpapi.CreateWorkloadRequest) { x.Workload.ResourceLimits.CPUMillicores = 100 },
		func(x *httpapi.CreateWorkloadRequest) { x.Workload.Containers[0].Ports = []int{4400} },
	} {
		x := request()
		change(&x)
		if r.Apply(&x) == nil {
			t.Fatal("modified VM request was admitted")
		}
	}
	if _, err := r.Resolve(isolation.Request{VMProfile: "unknown"}); err == nil {
		t.Fatal("unknown profile admitted")
	}
}

func TestSchedulerScratchHintDoesNotOverrideGuestProfile(t *testing.T) {
	cfg := target()
	r := &Router{targets: map[string]Target{cfg.ID: cfg}}
	req := request()
	req.Workload.Containers[0].WritablePaths = []httpapi.WritablePath{{Path: "/tmp", SizeMiB: 64}}
	if err := r.Apply(&req); err != nil {
		t.Fatal("scheduler scratch hint rejected", err)
	}
	req.Workload.Containers[0].WritablePaths = []httpapi.WritablePath{{Path: "/etc/ssh", SizeMiB: 64}}
	if err := r.Apply(&req); err == nil {
		t.Fatal("arbitrary host-style path accepted")
	}
}

type calls struct{ count int }

func (c *calls) Call(context.Context, Target, map[string]any) (Reply, error) {
	c.count++
	return Reply{OK: true, Deleted: true}, nil
}
func TestDeleteRequiresAllBindingIdentities(t *testing.T) {
	cfg := target()
	transport := &calls{}
	r := &Router{targets: map[string]Target{cfg.ID: cfg}, transport: transport}
	b := runtimebinding.Binding{InstanceID: "00000000-0000-4000-8000-000000000001", TeamID: "00000000-0000-4000-8000-000000000002", TargetID: cfg.ID, NamespaceUID: "owner-generation", RuntimeWorkloadID: "vm/workload"}
	c := provisioner.DeleteWorkloadCommand{RuntimeType: provisioner.RuntimeTypeVM, InstanceID: b.InstanceID, TeamID: "00000000-0000-4000-8000-000000000003", TargetID: b.TargetID, RuntimeWorkloadID: b.RuntimeWorkloadID}
	if r.DeleteWorkload(context.Background(), c, b) == nil || transport.count != 0 {
		t.Fatal("foreign team reached VM")
	}
	c.TeamID = b.TeamID
	if err := r.DeleteWorkload(context.Background(), c, b); err != nil || transport.count != 1 {
		t.Fatal("valid deletion did not reach VM", err)
	}
}
