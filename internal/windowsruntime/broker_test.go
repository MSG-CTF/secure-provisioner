package windowsruntime_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	win "github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

const targetID = "00000000-0000-4000-8000-000000000001"
const executionID = "00000000-0000-4000-8000-000000000002"

func validConnection() win.Connection {
	return win.Connection{TargetID: targetID, Name: "test-vm", Protocol: "rdp", Host: "203.0.113.10", Port: 3389, Username: "msgexec", RDPFile: "redirectclipboard:i:0\r\n"}
}

func TestBrokerConnectionUsesBearerAndValidatesResponse(t *testing.T) {
	connection := validConnection()
	connection.ExecutorCertificatePEM = "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/runtime/windows-vms/"+targetID+"/connection" || r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(connection)
	}))
	defer server.Close()
	broker, err := win.NewBroker(server.URL+"/api/", "secret-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := broker.Connection(context.Background(), targetID)
	if err != nil || got.Host != "203.0.113.10" || got.Username != "msgexec" || got.ExecutorCertificatePEM != connection.ExecutorCertificatePEM {
		t.Fatalf("connection = %#v, %v", got, err)
	}
}

func TestBrokerRejectsUntrustedConnectionFields(t *testing.T) {
	tests := map[string]func(*win.Connection){
		"target":         func(c *win.Connection) { c.TargetID = executionID },
		"protocol":       func(c *win.Connection) { c.Protocol = "ssh" },
		"hostname":       func(c *win.Connection) { c.Host = "rdp.example.test" },
		"host arguments": func(c *win.Connection) { c.Host = "203.0.113.10 /cert:ignore" },
		"zero port":      func(c *win.Connection) { c.Port = 0 },
		"large port":     func(c *win.Connection) { c.Port = 65536 },
		"empty user":     func(c *win.Connection) { c.Username = "" },
		"user arguments": func(c *win.Connection) { c.Username = "msgexec\r\n/password:secret" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			connection := validConnection()
			mutate(&connection)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(connection) }))
			defer server.Close()
			broker, err := win.NewBroker(server.URL, "secret-token", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := broker.Connection(context.Background(), targetID); err == nil {
				t.Fatal("accepted unsafe connection")
			}
		})
	}
}

func TestBrokerRequiresExactly200AndSanitizesErrors(t *testing.T) {
	for _, status := range []int{201, 202, 204, 401, 409, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"error":{"code":"WINDOWS_VM_NOT_READY","message":"secret-token password=hidden"}}`)
			}))
			defer server.Close()
			broker, err := win.NewBroker(server.URL, "secret-token", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = broker.Connection(context.Background(), targetID)
			var apiErr *win.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != status {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "password") {
				t.Fatalf("unsafe error = %v", err)
			}
		})
	}
}

func TestBrokerDoesNotFollowRedirectOrMutateCallerClient(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := server.Client()
	broker, err := win.NewBroker(server.URL, "secret-token", client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Connection(context.Background(), targetID); err == nil || redirected.Load() != 0 {
		t.Fatalf("redirect followed: count=%d err=%v", redirected.Load(), err)
	}
	if client.CheckRedirect != nil {
		t.Fatal("mutated caller client")
	}
}

func TestBrokerEventPreservesBodyAndMatchesAcknowledgement(t *testing.T) {
	for _, event := range []string{"started", "finished"} {
		t.Run(event, func(t *testing.T) {
			body := []byte(`{ "execution_id": "` + executionID + `", "event": "started" }`)
			state, vmState := "RUNNING", "RUNNING"
			if event == "finished" {
				body = []byte(`{"execution_id":"` + executionID + `","event":"finished","result":"succeeded","exit_code":0}`)
				state, vmState = "FINISHED", "RESET_REQUIRED"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, _ := io.ReadAll(r.Body)
				if string(got) != string(body) || r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || r.URL.Path != "/v1/runtime/windows-vms/"+targetID+"/execution-events" {
					t.Errorf("event changed: %q", got)
				}
				_, _ = fmt.Fprintf(w, `{"resource_target_id":%q,"execution_id":%q,"execution_state":%q,"vm_state":%q,"started_at":"2026-01-01T00:00:00Z","replayed":true}`, targetID, executionID, state, vmState)
			}))
			defer server.Close()
			broker, err := win.NewBroker(server.URL, "secret-token", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			ack, err := broker.Event(context.Background(), targetID, body)
			if err != nil || !ack.Replayed || ack.ExecutionState != state {
				t.Fatalf("ack = %#v, %v", ack, err)
			}
		})
	}
}

func TestBrokerFinishedReplayAcceptsCurrentReadyVM(t *testing.T) {
	body := []byte(`{"execution_id":"` + executionID + `","event":"finished","result":"succeeded","exit_code":0}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"resource_target_id":"`+targetID+`","execution_id":"`+executionID+`","execution_state":"FINISHED","vm_state":"READY","replayed":true}`)
	}))
	defer server.Close()
	broker, err := win.NewBroker(server.URL, "secret-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ack, err := broker.Event(context.Background(), targetID, body)
	if err != nil || !ack.Replayed || ack.ExecutionState != "FINISHED" || ack.VMState != "READY" {
		t.Fatalf("finished replay after VM reset: ack=%+v err=%v", ack, err)
	}
}

func TestBrokerRejectsMismatchedOrMalformedAcknowledgement(t *testing.T) {
	for name, response := range map[string]string{
		"wrong target":    `{"resource_target_id":"` + executionID + `","execution_id":"` + executionID + `","execution_state":"RUNNING","vm_state":"RUNNING"}`,
		"wrong execution": `{"resource_target_id":"` + targetID + `","execution_id":"` + targetID + `","execution_state":"RUNNING","vm_state":"RUNNING"}`,
		"wrong state":     `{"resource_target_id":"` + targetID + `","execution_id":"` + executionID + `","execution_state":"FINISHED","vm_state":"RESET_REQUIRED"}`,
		"wrong VM state":  `{"resource_target_id":"` + targetID + `","execution_id":"` + executionID + `","execution_state":"RUNNING","vm_state":"READY"}`,
		"null":            `null`, "trailing": `{}` + `{}`, "malformed": `{"resource_target_id":`,
		"oversize": strings.Repeat("x", 300*1024),
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, response) }))
			defer server.Close()
			broker, err := win.NewBroker(server.URL, "secret-token", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := broker.Event(context.Background(), targetID, []byte(`{"execution_id":"`+executionID+`","event":"started"}`)); err == nil {
				t.Fatal("accepted invalid ack")
			}
		})
	}
}

func TestBrokerRejectsInvalidConfigurationAndIDs(t *testing.T) {
	for _, url := range []string{"http://broker.example/api", "https://user:secret@broker.example/api", "https://broker.example/api?token=hidden", "https://broker.example/api?", "https://broker.example/api#fragment", "://bad"} {
		if _, err := win.NewBroker(url, "secret-token", nil); err == nil || strings.Contains(err.Error(), "hidden") {
			t.Fatalf("configuration %q error = %v", url, err)
		}
	}
	for _, id := range []string{"../connection", "00000000000040008000000000000001", "00000000-0000-4000-8000-00000000000A", "urn:uuid:" + targetID} {
		if win.ValidID(id) {
			t.Fatalf("accepted noncanonical UUID %q", id)
		}
	}
	if !win.ValidID(targetID) {
		t.Fatal("rejected canonical UUID")
	}
}

func TestBrokerRejectsEventOutputAndInvalidResultBeforeSending(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	broker, err := win.NewBroker(server.URL, "secret-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"execution_id":"` + executionID + `","event":"started","stdout":"secret"}`,
		`{"execution_id":"` + executionID + `","event":"finished","result":"succeeded","exit_code":7}`,
		`{"execution_id":"` + executionID + `","event":"finished","result":"unknown","exit_code":null}`,
		`{"execution_id":"` + executionID + `","event":"finished","result":"failed","exit_code":4294967296}`,
	} {
		if _, err := broker.Event(context.Background(), targetID, []byte(body)); err == nil {
			t.Fatalf("accepted invalid event %s", body)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("sent invalid events: %d", calls.Load())
	}
}
