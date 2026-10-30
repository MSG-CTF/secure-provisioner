package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

func draftLifecycleFixture() (provisioner.CreateWorkloadCommand, *fakeBackend) {
	c := provisioner.CreateWorkloadCommand{InstanceID: "instance-1", TargetID: "target", TeamID: provisioner.TeamID(draftTeamID), RuntimeType: provisioner.RuntimeTypeKubernetes, Containers: []provisioner.WorkloadContainer{{Name: "pwn", Ports: []int{1337}, Expose: true}}}
	b := &fakeBackend{result: provisioner.CreateWorkloadResult{RuntimeWorkloadID: "target/ns/id", NamespaceUID: "ns-uid", Endpoints: []provisioner.WorkloadEndpoint{{ContainerName: "pwn", Port: 1337, Protocol: "TCP"}}}, destination: Destination{TargetIP: "8.8.8.8", TargetPort: 31042, Protocol: "tcp", PublicTransport: TransportPlain, OwnerTeamID: draftTeamID}}
	return c, b
}

func TestDraftIntentReplayIgnoresChangedConfigurationAfterLostResponse(t *testing.T) {
	command, backend := draftLifecycleFixture()
	want := backend.destination
	var puts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got Destination
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got != want {
			t.Errorf("saved request changed: got=%+v want=%+v err=%v", got, want, err)
		}
		if puts.Add(1) == 1 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		_ = json.NewEncoder(w).Encode(Route{InstanceID: "instance-1", Hostname: "abc.gate.msgctf.kr", Port: 42817, Protocol: "tcp", CreatedAt: time.Now(), PublicTransport: TransportPlain, OwnerTeamID: draftTeamID, OwnerAccessEnforced: true})
	}))
	defer server.Close()
	client := contractTestClient(t, server)
	journal := &memoryJournal{}
	a := NewAdapter(backend, client, journal)
	if _, err := a.CreateWorkloadForOperation(context.Background(), command, "op1"); err == nil {
		t.Fatal("lost response succeeded")
	}
	r, err := journal.Get(context.Background(), "instance-1")
	if err != nil || r.Phase != PhaseApplyPending {
		t.Fatal(r, err)
	}
	raw, _ := json.Marshal(r)
	var restored Record
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	// A new process may have a different configuration; only the saved intent
	// may determine a retry's contract, owner, and transport.
	backend.destination.PublicTransport = TransportTLS
	backend.destination.OwnerTeamID = "00000000-0000-4000-8000-000000000003"
	a = NewAdapter(backend, client, &memoryJournal{records: map[string]Record{"instance-1": restored}})
	result, err := a.CreateWorkloadForOperation(context.Background(), command, "op1")
	if err != nil || result.ServiceURL != "tcp://abc.gate.msgctf.kr:42817" || backend.creates != 1 || puts.Load() != 2 {
		t.Fatalf("result=%+v err=%v creates=%d puts=%d", result, err, backend.creates, puts.Load())
	}
	if restored.Destination != want {
		t.Fatal("saved intent mutated", restored.Destination)
	}
}

func TestDraftCreateFailuresPreserveClaimsAndDistinguishOwnerConflict(t *testing.T) {
	for _, tc := range []struct {
		code              string
		permanent         bool
		phase             Phase
		quiesces, deletes int
	}{
		{"GATEWAY_PORT_POOL_EXHAUSTED", false, PhaseApplyPending, 0, 0},
		{"GATEWAY_PORT_ALLOCATION_CONFLICT", false, PhaseApplyPending, 0, 0},
		{"GATEWAY_OWNER_ACCESS_NOT_CONFIGURED", false, PhaseApplyPending, 0, 0},
		{"GATEWAY_OWNER_CONFLICT", true, PhaseConflictHold, 1, 0},
		{"GATEWAY_TRANSPORT_NOT_SUPPORTED", true, PhaseDeleted, 1, 1},
	} {
		t.Run(tc.code, func(t *testing.T) {
			command, backend := draftLifecycleFixture()
			journal := &memoryJournal{}
			remote := &fakeRoutes{putError: &APIError{Code: tc.code, Permanent: tc.permanent}}
			a := NewAdapter(backend, remote, journal)
			_, err := a.CreateWorkloadForOperation(context.Background(), command, "op1")
			code, _ := operations.ClassifyExecutionError(err)
			if err == nil || code != tc.code {
				t.Fatalf("failed route/code changed: %v", err)
			}
			r, readErr := journal.Get(context.Background(), "instance-1")
			if readErr != nil || r.Phase != tc.phase || backend.quiesces != tc.quiesces || backend.deletes != tc.deletes || remote.deletes != tc.deletes {
				t.Fatalf("phase=%s err=%v quiesces=%d deletes=%d routeDeletes=%d", r.Phase, readErr, backend.quiesces, backend.deletes, remote.deletes)
			}
			var hold interface{ HoldRetry() bool }
			if tc.phase != PhaseDeleted && (!errors.As(err, &hold) || !hold.HoldRetry()) {
				t.Fatalf("uncertain route was not held: %v", err)
			}
			if tc.phase == PhaseApplyPending {
				remote.putError = nil
				if _, err := a.CreateWorkloadForOperation(context.Background(), command, "op1"); err != nil || backend.creates != 1 || remote.last != backend.destination {
					t.Fatalf("retry changed resources/intent: %v", err)
				}
			}
			if tc.phase == PhaseConflictHold {
				binding := runtimebinding.Binding{InstanceID: command.InstanceID, TargetID: command.TargetID, TeamID: command.TeamID, RuntimeWorkloadID: backend.result.RuntimeWorkloadID, NamespaceUID: backend.result.NamespaceUID}
				if err := a.DeleteWorkload(context.Background(), provisioner.DeleteWorkloadCommand{InstanceID: command.InstanceID}, binding); err == nil || remote.deletes != 0 || backend.deletes != 0 {
					t.Fatalf("foreign owner route was deleted: err=%v routeDeletes=%d workloadDeletes=%d", err, remote.deletes, backend.deletes)
				}
			}
		})
	}
}

func TestDraftAgainstStrictV1FailsAfterCleanupWithoutLegacyFallback(t *testing.T) {
	command, backend := draftLifecycleFixture()
	var puts, deletes atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		puts.Add(1)
		var d Destination
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil || d.PublicTransport != TransportPlain || d.OwnerTeamID != draftTeamID {
			t.Errorf("draft stripped its contract: %+v %v", d, err)
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":{"code":"VALIDATION_ERROR"}}`))
	}))
	defer server.Close()
	journal := &memoryJournal{}
	result, err := NewAdapter(backend, contractTestClient(t, server), journal).CreateWorkloadForOperation(context.Background(), command, "op1")
	code, retryable := operations.ClassifyExecutionError(err)
	if err == nil || code != "GATEWAY_VALIDATION_ERROR" || retryable || result.ServiceURL != "" || puts.Load() != 1 || deletes.Load() != 1 || backend.deletes != 1 {
		t.Fatalf("unsupported draft downgraded or leaked resources: result=%+v err=%v puts=%d routeDeletes=%d workloadDeletes=%d", result, err, puts.Load(), deletes.Load(), backend.deletes)
	}
}

func TestDraftCleanupFailureDoesNotReleaseWorkloadOrBackendPort(t *testing.T) {
	command, backend := draftLifecycleFixture()
	journal := &memoryJournal{}
	remote := &fakeRoutes{}
	a := NewAdapter(backend, remote, journal)
	if _, err := a.CreateWorkloadForOperation(context.Background(), command, "op1"); err != nil {
		t.Fatal(err)
	}
	before, _ := journal.Get(context.Background(), command.InstanceID)
	remote.deleteFailure, remote.deleteCode = true, "GATEWAY_ROUTE_CLEANUP_PENDING"
	binding := runtimebinding.Binding{InstanceID: command.InstanceID, TargetID: command.TargetID, TeamID: command.TeamID, RuntimeWorkloadID: backend.result.RuntimeWorkloadID, NamespaceUID: backend.result.NamespaceUID}
	err := a.DeleteWorkload(context.Background(), provisioner.DeleteWorkloadCommand{InstanceID: command.InstanceID}, binding)
	if err == nil || backend.deletes != 0 {
		t.Fatalf("cleanup prematurely released backend: %v", err)
	}
	after, _ := journal.Get(context.Background(), command.InstanceID)
	if after.Phase != PhaseDeletePending || !reflect.DeepEqual(before.Destination, after.Destination) {
		t.Fatal("cleanup changed intent", after)
	}
	remote.deleteFailure = false
	if err := a.DeleteWorkload(context.Background(), provisioner.DeleteWorkloadCommand{InstanceID: command.InstanceID}, binding); err != nil || backend.deletes != 1 {
		t.Fatal(err, backend.deletes)
	}
}

func TestRejectedDraftAcknowledgementQuiescesWithoutDeletingForeignRoute(t *testing.T) {
	for _, scenario := range []string{"unprotected", "foreign-owner", "wrong-mode", "malformed-json", "accepted-without-ack", "no-content"} {
		t.Run(scenario, func(t *testing.T) {
			command, backend := draftLifecycleFixture()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					t.Error("unconfirmed/foreign route was deleted")
					w.WriteHeader(204)
					return
				}
				if scenario == "accepted-without-ack" {
					w.WriteHeader(http.StatusAccepted)
					return
				}
				if scenario == "no-content" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if scenario == "malformed-json" {
					_, _ = w.Write([]byte(`<html>invalid response</html>`))
					return
				}
				route := Route{InstanceID: command.InstanceID, Hostname: "abc.gate.msgctf.kr", Port: 42817, Protocol: "tcp", CreatedAt: time.Now(), PublicTransport: TransportPlain, OwnerTeamID: draftTeamID, OwnerAccessEnforced: true}
				switch scenario {
				case "unprotected":
					route.OwnerAccessEnforced = false
				case "foreign-owner":
					route.OwnerTeamID = "00000000-0000-4000-8000-000000000003"
				case "wrong-mode":
					route.PublicTransport, route.TLS = TransportTLS, true
				}
				_ = json.NewEncoder(w).Encode(route)
			}))
			defer server.Close()
			journal := &memoryJournal{}
			a := NewAdapter(backend, contractTestClient(t, server), journal)
			result, err := a.CreateWorkloadForOperation(context.Background(), command, "op1")
			code, _ := operations.ClassifyExecutionError(err)
			r, readErr := journal.Get(context.Background(), command.InstanceID)
			if code != "GATEWAY_CONTRACT_UNCONFIRMED" || r.Phase != PhaseConflictHold || backend.quiesces != 1 || backend.deletes != 0 || result.ServiceURL != "" || readErr != nil {
				t.Fatalf("unconfirmed route kept active: code=%s phase=%s quiesces=%d deletes=%d result=%+v readErr=%v", code, r.Phase, backend.quiesces, backend.deletes, result, readErr)
			}
			binding := runtimebinding.Binding{InstanceID: command.InstanceID, TargetID: command.TargetID, TeamID: command.TeamID, RuntimeWorkloadID: backend.result.RuntimeWorkloadID, NamespaceUID: backend.result.NamespaceUID}
			if err := a.DeleteWorkload(context.Background(), provisioner.DeleteWorkloadCommand{InstanceID: command.InstanceID}, binding); err == nil || backend.deletes != 0 {
				t.Fatal("unconfirmed contract released workload", err)
			}
		})
	}
}
