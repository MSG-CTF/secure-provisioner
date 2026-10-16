package k3s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testBackendSecretRef = "152839e6-6c28-4ad7-b109-378df7d0092c"
const testBackendFlag = "CTF{local_fixture_only}"
const testBackendToken = "test-runtime-backend-secret-token-000000000"

type fixedTestSecretResolver struct {
	values map[string]string
	err    error
}

func (resolver fixedTestSecretResolver) Resolve(context.Context, string, string, string) (map[string]string, error) {
	return resolver.values, resolver.err
}

func TestBackendResolverSendsOnlyBoundReferenceAndReturnsValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/internal/v1/runtime-secrets/resolve" ||
			request.Header.Get("Authorization") != "Bearer "+testBackendToken {
			t.Error("unexpected resolver request")
		}
		var body map[string]string
		if json.NewDecoder(request.Body).Decode(&body) != nil || len(body) != 3 ||
			body["secret_ref"] != testBackendSecretRef || body["container"] != "challenge" || body["image"] != "pinned-image" {
			t.Error("reference binding was not sent")
		}
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write([]byte(`{"code":"SUCCESS","data":{"env":{"FLAG":"` + testBackendFlag + `"}}}`))
	}))
	defer server.Close()
	resolver, err := NewBackendSecretResolver(server.URL, testBackendToken)
	if err != nil {
		t.Fatal(err)
	}
	values, err := resolver.Resolve(context.Background(), testBackendSecretRef, "challenge", "pinned-image")
	if err != nil || values["FLAG"] != testBackendFlag {
		t.Fatalf("resolve failed: %v", err)
	}
}

func TestBackendResolverRejectsUnsafeConfigurationWithoutEcho(t *testing.T) {
	for _, origin := range []string{"http://backend.example.test", "https://user:password@backend.example.test", "https://backend.example.test/path", "https://backend.example.test?token=private", "https://backend.example.test#private"} {
		if _, err := NewBackendSecretResolver(origin, testBackendToken); err == nil ||
			strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "password") {
			t.Fatal("unsafe configuration accepted or echoed")
		}
	}
}

func TestBackendResolverDoesNotFollowRedirectsOrEchoFailureBody(t *testing.T) {
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer target.Close()
	for _, status := range []int{http.StatusFound, http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Location", target.URL)
			writer.WriteHeader(status)
			_, _ = writer.Write([]byte(testBackendFlag + testBackendToken))
		}))
		resolver, err := NewBackendSecretResolver(server.URL, testBackendToken)
		if err != nil {
			t.Fatal(err)
		}
		_, err = resolver.Resolve(context.Background(), testBackendSecretRef, "challenge", "pinned-image")
		server.Close()
		if err == nil || strings.Contains(err.Error(), testBackendFlag) || strings.Contains(err.Error(), testBackendToken) {
			t.Fatal("failure leaked a secret or returned success")
		}
	}
	if calls != 0 {
		t.Fatal("resolver forwarded credentials to a redirect target")
	}
}

func TestBackendResolverRejectsMalformedOversizedOrInvalidValues(t *testing.T) {
	for _, body := range []string{
		`{"code":"SUCCESS","data":{"env":{}}}`,
		`{"code":"SUCCESS","data":{"env":{"FLAG":1}}}`,
		`{"code":"SUCCESS","data":{"env":{"INTERNAL_TOKEN":null}}}`,
		`{"code":"SUCCESS","data":{"env":{"lower":"x"}}}`,
		`{"code":"SUCCESS","data":{"env":{"FLAG":"` + strings.Repeat("x", 4097) + `"}}}`,
		strings.Repeat("x", 128<<10+1),
	} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { _, _ = writer.Write([]byte(body)) }))
		resolver, _ := NewBackendSecretResolver(server.URL, testBackendToken)
		_, err := resolver.Resolve(context.Background(), testBackendSecretRef, "challenge", "pinned-image")
		server.Close()
		if err == nil {
			t.Fatal("invalid secret response accepted")
		}
	}
}
