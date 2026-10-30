package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestClientOriginValidatesHTTPSIdentityAndAuthentication(t *testing.T) {
	host := "0123456789abcdef0123456789abcdef.gate.msgctf.kr"
	for _, tc := range []struct {
		name    string
		changes map[string]any
		valid   bool
	}{
		{"correct", nil, true}, {"plaintext", map[string]any{"tls": false}, false}, {"missing_tls", map[string]any{"tls": nil}, false},
		{"wrong_id", map[string]any{"instance_id": "other"}, false}, {"foreign_host", map[string]any{"hostname": "foreign.invalid", "url": "https://foreign.invalid"}, false},
		{"wrong_url", map[string]any{"url": "http://" + host}, false}, {"wrong_port", map[string]any{"port": 80}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/v1/routes/instance-1/origin" || r.Header.Get("Authorization") != "Bearer origin-test-token" {
					t.Errorf("unexpected request")
				}
				body := map[string]any{"instance_id": "instance-1", "hostname": host, "port": 443, "tls": true, "url": "https://" + host}
				for k, v := range tc.changes {
					body[k] = v
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer srv.Close()
			file := filepath.Join(t.TempDir(), "token")
			_ = os.WriteFile(file, []byte("origin-test-token"), 0600)
			client, err := NewClient(srv.URL, file, 90*time.Second, srv.Client().Transport)
			if err != nil {
				t.Fatal(err)
			}
			origin, err := client.PublicOrigin(context.Background(), "instance-1")
			if (err == nil) != tc.valid || (tc.valid && origin != "https://"+host) {
				t.Fatalf("origin=%q err=%v", origin, err)
			}
		})
	}
}

type originRoutes struct {
	fakeRoutes
	origin    string
	originErr error
	putOrigin string
}

func (r *originRoutes) PublicOrigin(context.Context, string) (string, error) {
	return r.origin, r.originErr
}

func (r *originRoutes) Put(ctx context.Context, id string, destination Destination) (Route, error) {
	route, err := r.fakeRoutes.Put(ctx, id, destination)
	if err != nil {
		return route, err
	}
	origin := r.origin
	if r.putOrigin != "" {
		origin = r.putOrigin
	}
	route.URL = &origin
	return route, nil
}

func TestPublicOriginSurvivesJournalRestoreAndCleansMismatchedPublishedRoute(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore", true: "changed_hostname"}[mismatch], func(t *testing.T) {
			command := provisioner.CreateWorkloadCommand{InstanceID: "origin-1", TargetID: "target", RuntimeType: provisioner.RuntimeTypeKubernetes, Containers: []provisioner.WorkloadContainer{{Name: "web", Ports: []int{8080}, Expose: true, PublicOriginEnv: "PUBLIC_ORIGIN", Env: map[string]string{"APP_ENV": "production"}}}}
			remote := &originRoutes{origin: "https://0123456789abcdef0123456789abcdef.gate.msgctf.kr"}
			if mismatch {
				remote.putOrigin = "https://different.gate.msgctf.kr"
			}
			backend := &fakeBackend{destination: Destination{TargetIP: "8.8.8.8", TargetPort: 31042, Protocol: "http"}, result: provisioner.CreateWorkloadResult{RuntimeWorkloadID: "target/ctf-origin/challenge", NamespaceUID: "namespace-uid"}}
			journal := &memoryJournal{}
			adapter := NewAdapter(backend, remote, journal)
			_, err := adapter.CreateWorkloadForOperation(context.Background(), command, "op")
			if mismatch {
				if err == nil || remote.deletes != 1 || backend.deletes != 1 || journal.records[command.InstanceID].Phase != PhaseDeleted {
					t.Fatal("origin mismatch left a route or workload")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(journal.records[command.InstanceID])
			var restored Record
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			restarted := NewAdapter(backend, remote, &memoryJournal{records: map[string]Record{command.InstanceID: restored}})
			if _, err := restarted.CreateWorkloadForOperation(context.Background(), command, "op"); err != nil {
				t.Fatal(err)
			}
			if backend.creates != 1 || remote.puts != 1 || backend.lastCommand.Containers[0].Env["PUBLIC_ORIGIN"] != remote.origin {
				t.Fatal("restart changed origin or repeated workload creation")
			}
		})
	}
}

func TestPublicOriginBindingDoesNotMutateCallerAndFailsBeforeWorkloadOnUnavailableOrigin(t *testing.T) {
	command := provisioner.CreateWorkloadCommand{InstanceID: "instance-1", TargetID: "target", RuntimeType: provisioner.RuntimeTypeKubernetes, Containers: []provisioner.WorkloadContainer{{Name: "web", Ports: []int{8080}, Expose: true, PublicOriginEnv: "PUBLIC_ORIGIN", Env: map[string]string{"APP_ENV": "production"}}}}
	remote := &originRoutes{origin: "https://0123456789abcdef0123456789abcdef.gate.msgctf.kr"}
	backend := &fakeBackend{}
	adapter := NewAdapter(backend, remote, &memoryJournal{})
	bound, err := adapter.bindPublicOrigin(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed := command.Containers[0].Env["PUBLIC_ORIGIN"]; changed {
		t.Fatal("caller map mutated")
	}
	if bound.Containers[0].Env["PUBLIC_ORIGIN"] != remote.origin || !publicOriginMatches(bound, Route{Protocol: "http", TLS: true, Port: 443, URL: &remote.origin}) {
		t.Fatal("trusted origin was not bound")
	}
	if publicOriginMatches(bound, Route{Protocol: "tcp", TLS: true, Port: 443}) {
		t.Fatal("TCP route accepted as HTTP origin")
	}
	remote.originErr = errors.New("unavailable")
	if _, err := adapter.CreateWorkloadForOperation(context.Background(), command, "op"); err == nil {
		t.Fatal("missing origin allowed workload creation")
	}
	if backend.creates != 0 || remote.puts != 0 {
		t.Fatal("workload or route published before origin resolution")
	}
}
