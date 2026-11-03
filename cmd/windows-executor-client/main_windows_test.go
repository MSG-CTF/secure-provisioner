package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/testpki"
	"github.com/google/uuid"
)

// These tests run in the Windows job because the fixed port is privileged on
// Linux. The CLI requires the public VM address on port 443. All services in this
// harness bind loopback, use dummy credentials, and never execute the fixture.
func exerciseClient(t *testing.T, redirect, sharedCredential bool) (error, int32, []string) {
	return exerciseClientAuth(t, redirect, sharedCredential, false)
}

func exerciseClientAuth(t *testing.T, redirect, sharedCredential, useMTLS bool) (error, int32, []string) {
	t.Helper()
	const brokerToken = "local-test-broker-only-token-0123456789"
	const executorToken = "local-test-vm-only-executor-token-9876543210"
	var redirected atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		http.Error(w, "redirect must not be followed", http.StatusBadGateway)
	}))
	defer sink.Close()
	var mu sync.Mutex
	var events []string
	broker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+brokerToken {
			t.Error("Broker received a credential other than its own")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var event struct {
			ExecutionID string `json:"execution_id"`
			Event       string `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		events = append(events, event.Event)
		mu.Unlock()
		state := "RUNNING"
		if event.Event == "finished" {
			state = "RESET_REQUIRED"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"execution_id": event.ExecutionID, "vm_state": state})
	}))
	defer broker.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatalf("loopback port 443 is required for the CLI contract: %v", err)
	}
	vm := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if useMTLS && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Authorization") != "") {
			t.Error("VM mTLS was not isolated from bearer authentication")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !useMTLS && r.Header.Get("Authorization") != "Bearer "+executorToken {
			t.Error("VM received a credential other than its dedicated executor token")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusAccepted)
		case http.MethodGet:
			if redirect {
				http.Redirect(w, r, sink.URL+"/probe", http.StatusFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"execution_id": filepath.Base(r.URL.Path),
				"status": "succeeded", "exit_code": 0, "stdout_base64": "T0s=", "stderr_base64": "", "duration_ms": 1})
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))
	_ = vm.Listener.Close()
	vm.Listener = listener
	ca := testpki.NewClientCA(t)
	_, clientPEM, clientKeyPEM := ca.Client(t)
	if useMTLS {
		pool := x509.NewCertPool()
		pool.AddCert(ca.Certificate)
		vm.TLS = &tls.Config{ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	}
	vm.StartTLS()
	defer vm.Close()
	roots := x509.NewCertPool()
	roots.AddCert(broker.Certificate())
	originalTransport := http.DefaultTransport
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	http.DefaultTransport = transport
	defer func() {
		transport.CloseIdleConnections()
		http.DefaultTransport = originalTransport
	}()
	directory := t.TempDir()
	certificate := filepath.Join(directory, "vm.pem")
	brokerFile := filepath.Join(directory, "broker-token")
	executorFile := filepath.Join(directory, "executor-token")
	clientFile := filepath.Join(directory, "runtime-client.pem")
	clientKeyFile := filepath.Join(directory, "runtime-client-key.pem")
	binary := filepath.Join(directory, "fixture.exe")
	vmCredential := executorToken
	if sharedCredential {
		vmCredential = brokerToken
	}
	files := map[string][]byte{
		certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: vm.Certificate().Raw}),
		brokerFile:  []byte(brokerToken), executorFile: []byte(vmCredential), binary: []byte("MZ-local-harmless-fixture"),
		clientFile: clientPEM, clientKeyFile: clientKeyPEM,
	}
	for path, data := range files {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if useMTLS {
		err = runWithMTLS(vm.URL, broker.URL, uuid.NewString(), certificate, brokerFile, "", clientFile, clientKeyFile, binary, 2)
	} else {
		err = run(vm.URL, broker.URL, uuid.NewString(), certificate, brokerFile, executorFile, binary, 2)
	}
	mu.Lock()
	recorded := append([]string(nil), events...)
	mu.Unlock()
	return err, redirected.Load(), recorded
}

func TestClientMTLSDoesNotSendBrokerOrExecutorBearerToVM(t *testing.T) {
	err, redirected, events := exerciseClientAuth(t, false, false, true)
	if err != nil || redirected != 0 || strings.Join(events, ",") != "started,finished" {
		t.Fatalf("mTLS flow failed: err=%v redirected=%d events=%v", err, redirected, events)
	}
}

func TestClientRejectsMixedVMAuthenticationBeforeAnyBrokerEvent(t *testing.T) {
	err := runWithMTLS("https://127.0.0.1", "https://127.0.0.1", uuid.NewString(), "server.pem", "broker-token", "vm-token", "client.pem", "client-key.pem", "fixture.exe", 2)
	if err == nil || !strings.Contains(err.Error(), "exactly one complete VM authentication mode") {
		t.Fatalf("mixed mode accepted: %v", err)
	}
}

func TestClientUsesSeparateCredentialsAndCompletes(t *testing.T) {
	err, redirected, events := exerciseClient(t, false, false)
	if err != nil || redirected != 0 || strings.Join(events, ",") != "started,finished" {
		t.Fatalf("normal client flow failed: err=%v redirected=%d events=%v", err, redirected, events)
	}
}

func TestClientRejectsVMDowngradeRedirect(t *testing.T) {
	err, redirected, events := exerciseClient(t, true, false)
	if err == nil || redirected != 0 || strings.Join(events, ",") != "started,finished" {
		t.Fatalf("redirect was not safely rejected: err=%v redirected=%d events=%v", err, redirected, events)
	}
}

func TestClientRejectsSharedCredentialBeforeAnyBrokerEvent(t *testing.T) {
	err, redirected, events := exerciseClient(t, false, true)
	if err == nil || !strings.Contains(err.Error(), "different API tokens") || redirected != 0 || len(events) != 0 {
		t.Fatalf("shared credential reached a service: err=%v redirected=%d events=%v", err, redirected, events)
	}
}
