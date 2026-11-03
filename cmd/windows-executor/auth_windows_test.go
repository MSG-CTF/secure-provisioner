package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/testpki"
)

func TestExecutorMTLSRejectsMissingAndForeignCertificates(t *testing.T) {
	ca := testpki.NewClientCA(t)
	caPath := filepath.Join(t.TempDir(), "client-ca.pem")
	if err := os.WriteFile(caPath, ca.PEM, 0600); err != nil {
		t.Fatal(err)
	}
	api, config, err := executorAuthentication("", caPath)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(api.authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("mTLS request carried a bearer credential")
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	root := x509.NewCertPool()
	root.AddCert(server.Certificate())
	valid, _, _ := ca.Client(t)
	foreign, _, _ := testpki.NewClientCA(t).Client(t)
	for _, tc := range []struct {
		name     string
		certs    []tls.Certificate
		accepted bool
	}{
		{"runtime", []tls.Certificate{valid}, true},
		{"no certificate", nil, false},
		{"foreign CA", []tls.Certificate{foreign}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: root, MinVersion: tls.VersionTLS12, Certificates: tc.certs}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			response, err := client.Get(server.URL + "/healthz")
			if tc.accepted {
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusNoContent {
					t.Fatalf("Runtime rejected: %d", response.StatusCode)
				}
			} else if err == nil {
				response.Body.Close()
				t.Fatal("untrusted client completed TLS handshake")
			}
		})
	}
	if requests.Load() != 1 {
		t.Fatalf("untrusted client reached handler: %d requests", requests.Load())
	}
}

func TestExecutorMTLSCannotFallBackToBearer(t *testing.T) {
	for _, paths := range [][2]string{{"", ""}, {"token", "client-ca"}} {
		if _, _, err := executorAuthentication(paths[0], paths[1]); err == nil {
			t.Fatal("ambiguous or missing authentication accepted")
		}
	}
	for _, contents := range [][]byte{nil, []byte("not a certificate")} {
		path := filepath.Join(t.TempDir(), "client-ca.pem")
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executorAuthentication("", path); err == nil {
			t.Fatal("invalid CA accepted")
		}
	}
	api := &executorAPI{requireMTLS: true}
	request := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/healthz", nil)
	request.Header.Set("Authorization", "Bearer dummy-broker-token-that-must-not-authorize")
	response := httptest.NewRecorder()
	api.authorize(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("bearer fallback reached handler") })).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing verified client chain accepted: %d", response.Code)
	}
}
