package windowsruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestHTTPSExecutorBrokerMTLSUsesPinnedCertificateWithoutBearer(t *testing.T) {
	id := "b51e0461-746e-424b-a8c0-fb307ed815b3"
	target := "e0e2843e-728e-47eb-a2ae-281b35cf6784"
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "runtime-client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "runtime-client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, &clientKey.PublicKey, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0640); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 || r.Header.Get("Authorization") != "" || r.URL.Path != "/v1/executions/"+id {
			t.Errorf("unexpected mTLS request: %s %s", r.Method, r.URL.Path)
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"execution_id": id, "status": "succeeded", "exit_code": 0, "stdout_base64": "b2sK", "stderr_base64": "", "output_truncated": false, "duration_ms": 1})
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	address, portString, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	clientPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{clientPair}}) // test-only: capture local TLS interceptor certificate
	if err != nil {
		t.Fatalf("mTLS fixture handshake: %v", err)
	}
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: probe.ConnectionState().PeerCertificates[0].Raw})
	probe.Close()
	transport, err := NewHTTPSExecutorTransport(HTTPSExecutorConfig{ClientCertificateFile: certPath, ClientKeyFile: keyPath, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	connection := Connection{TargetID: target, Host: address, Protocol: "rdp", Port: 3389, ExecutorCertificatePEM: string(serverPEM)}
	if err := transport.ValidateConnection(connection); err != nil {
		t.Fatal(err)
	}
	missingPin := connection
	missingPin.ExecutorCertificatePEM = ""
	if err := transport.ValidateConnection(missingPin); err == nil {
		t.Fatal("accepted connection without Broker server certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := transport.Execute(ctx, connection, Job{ID: id, Payload: []byte("MZtest"), Timeout: 30 * time.Second, ConnectTimeout: time.Second, OutputLimit: 65536})
	if out.Result != "succeeded" || out.ExitCode == nil || *out.ExitCode != 0 || out.Stdout != "ok\n" {
		t.Fatalf("mTLS outcome: %+v", out)
	}
}

func TestHTTPSExecutorTransportRunsAndCollectsResult(t *testing.T) {
	id := "b51e0461-746e-424b-a8c0-fb307ed815b3"
	target := "e0e2843e-728e-47eb-a2ae-281b35cf6784"
	payload := []byte("MZtest")
	digest := sha256.Sum256(payload)
	putCount := 0
	pollCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/executions/"+id || r.Header.Get("Authorization") != "Bearer executor-secret-token-1234567890" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPut:
			putCount++
			if r.Header.Get("X-Content-SHA256") != hex.EncodeToString(digest[:]) || r.Header.Get("X-Timeout-Seconds") != "30" {
				t.Error("missing execution headers")
			}
			w.WriteHeader(http.StatusAccepted)
		case http.MethodGet:
			pollCount++
			if pollCount == 1 {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"execution_id": id, "status": "succeeded", "exit_code": 0, "stdout_base64": "b2sK", "stderr_base64": "", "output_truncated": false, "duration_ms": 1})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	address, portString, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "executor.crt")
	tokenPath := filepath.Join(dir, "executor.token")
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) // test-only certificate capture
	if err != nil {
		t.Fatal(err)
	}
	actualCert := conn.ConnectionState().PeerCertificates[0].Raw
	conn.Close()
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: actualCert}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("executor-secret-token-1234567890"), 0600); err != nil {
		t.Fatal(err)
	}
	transport, err := NewHTTPSExecutorTransport(HTTPSExecutorConfig{Targets: map[string]ExecutorCredential{target: {TokenFile: tokenPath, CertificateFile: certPath, Port: port}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := transport.Execute(ctx, Connection{TargetID: target, Host: address, Protocol: "rdp", Port: 3389}, Job{ID: id, Payload: payload, Timeout: 30 * time.Second, ConnectTimeout: time.Second, OutputLimit: 65536})
	if out.Result != "succeeded" || out.ExitCode == nil || *out.ExitCode != 0 || out.Stdout != "ok\n" || out.StartedAt == nil || putCount != 1 || pollCount != 2 {
		t.Fatalf("unexpected outcome %#v, PUT %d, GET %d", out, putCount, pollCount)
	}
}

func TestHTTPSExecutorTransportReconcilesLostPutReply(t *testing.T) {
	id := "37bb814e-fcbb-4f03-84d8-bb066289b2ab"
	target := "561ea673-120a-46b7-910f-ab891a625121"
	puts, gets := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts++
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close() // VM accepted the request but the 202 response was lost.
			return
		}
		gets++
		_ = json.NewEncoder(w).Encode(map[string]any{"execution_id": id, "status": "succeeded", "exit_code": 0, "stdout_base64": "", "stderr_base64": "", "output_truncated": false, "duration_ms": 1})
	}))
	defer server.Close()
	address, portString, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	dir := t.TempDir()
	certPath, tokenPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "token")
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) // test-only certificate capture
	if err != nil {
		t.Fatal(err)
	}
	certificate := conn.ConnectionState().PeerCertificates[0].Raw
	conn.Close()
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("executor-secret-token-1234567890"), 0600); err != nil {
		t.Fatal(err)
	}
	transport, err := NewHTTPSExecutorTransport(HTTPSExecutorConfig{Targets: map[string]ExecutorCredential{target: {TokenFile: tokenPath, CertificateFile: certPath, Port: port}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out := transport.Execute(ctx, Connection{TargetID: target, Host: address, Protocol: "rdp", Port: 3389}, Job{ID: id, Payload: []byte("MZtest"), Timeout: 30 * time.Second, ConnectTimeout: time.Second, OutputLimit: 65536})
	if out.Result != "succeeded" || puts != 1 || gets == 0 {
		t.Fatalf("lost reply was not reconciled: %+v PUT=%d GET=%d", out, puts, gets)
	}
}
