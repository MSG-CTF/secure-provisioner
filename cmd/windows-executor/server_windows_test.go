package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecutorAcceptsOnlyItsOwnCredential(t *testing.T) {
	const ownToken = "local-test-vm-a-executor-token-0123456789"
	api := &executorAPI{root: t.TempDir(), tokenHash: sha256.Sum256([]byte(ownToken))}
	handler := api.authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, headers := range [][]string{nil, {"Bearer wrong"},
		{"Bearer local-test-broker-only-token-0123456789"},
		{"Bearer local-test-vm-b-executor-token-9876543210"},
		{"Bearer " + ownToken, "Bearer " + ownToken}} {
		request := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/healthz", nil)
		for _, header := range headers {
			request.Header.Add("Authorization", header)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("untrusted credential accepted: HTTP %d", response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/healthz", nil)
	request.Header.Set("Authorization", "Bearer "+ownToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("own credential rejected: HTTP %d", response.Code)
	}
}

func TestExecutorRejectsTraversalAndNoncanonicalIDs(t *testing.T) {
	api := &executorAPI{root: t.TempDir()}
	for _, id := range []string{"../../outside", `C:\outside`, "00000000000000000000000000000000", "BAD"} {
		request := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/v1/executions/invalid", nil)
		request.SetPathValue("id", id)
		response := httptest.NewRecorder()
		if _, _, _, ok := api.paths(response, request); ok || response.Code != http.StatusBadRequest {
			t.Fatalf("invalid execution ID accepted: %q", id)
		}
	}
}
