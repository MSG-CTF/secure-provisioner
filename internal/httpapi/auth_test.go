package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testCurrentServiceToken  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testPreviousServiceToken = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	authenticationErrorBody  = "{\"error\":{\"code\":\"UNAUTHENTICATED\",\"message\":\"service authentication failed\"}}\n"
)

func TestServiceAuthenticationRejectsMissingMalformedAndInvalidCredentials(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []string
	}{
		{"missing", nil}, {"wrong scheme", []string{"Basic abc"}}, {"missing token", []string{"Bearer"}},
		{"extra field", []string{"Bearer wrong extra"}}, {"wrong token", []string{"Bearer CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}},
		{"multiple headers", []string{"Bearer " + testCurrentServiceToken, "Bearer " + testCurrentServiceToken}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewHandler(&recordingCreateUseCase{}, ServiceAuthConfig{CurrentToken: testCurrentServiceToken})
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", nil)
			request.Header["Authorization"] = tc.headers
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertAuthenticationFailure(t, response)
		})
	}
}

func TestServiceAuthenticationAcceptsCurrentAndPreviousTokens(t *testing.T) {
	handler := NewHandler(&recordingCreateUseCase{}, ServiceAuthConfig{CurrentToken: testCurrentServiceToken, PreviousToken: testPreviousServiceToken})
	for _, value := range []string{"Bearer " + testCurrentServiceToken, "bEaReR " + testPreviousServiceToken} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", nil)
		request.Header.Set("Authorization", value)
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusUnauthorized {
			t.Fatalf("Authorization %q rejected: %s", value, response.Body.String())
		}
	}
}

func TestServiceAuthenticationTreatsTokenAsCaseSensitive(t *testing.T) {
	handler := NewHandler(&recordingCreateUseCase{}, ServiceAuthConfig{CurrentToken: testCurrentServiceToken})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", nil)
	request.Header.Set("Authorization", "Bearer "+strings.ToLower(testCurrentServiceToken))
	handler.ServeHTTP(response, request)
	assertAuthenticationFailure(t, response)
}

func TestServiceAuthenticationRejectsAllCredentialsWithoutCurrentToken(t *testing.T) {
	handler := NewHandler(&recordingCreateUseCase{}, ServiceAuthConfig{PreviousToken: testPreviousServiceToken})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", nil)
	request.Header.Set("Authorization", "Bearer "+testPreviousServiceToken)
	handler.ServeHTTP(response, request)
	assertAuthenticationFailure(t, response)
}

func TestServiceAuthenticationRejectsBeforeReadingRequestBody(t *testing.T) {
	body := &countingReadCloser{Reader: strings.NewReader("not JSON")}
	handler := NewHandler(&recordingCreateUseCase{}, ServiceAuthConfig{CurrentToken: testCurrentServiceToken})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", nil)
	request.Body = body
	handler.ServeHTTP(response, request)
	assertAuthenticationFailure(t, response)
	if body.readCalls != 0 {
		t.Fatalf("request body Read calls = %d, want 0", body.readCalls)
	}
}

func TestAllInternalRoutesRequireServiceAuthentication(t *testing.T) {
	runtime := &recordingRuntimeUseCase{}
	handler := NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime, ServiceAuthConfig{CurrentToken: testCurrentServiceToken})
	for _, tc := range []struct{ method, path string }{{http.MethodPost, "/internal/v1/instances"}, {http.MethodGet, "/internal/v1/instances/i/runtime-status"}, {http.MethodDelete, "/internal/v1/instances/i"}, {http.MethodGet, "/internal/v1/operations/o"}} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(tc.method, tc.path, nil)
		handler.ServeHTTP(response, request)
		assertAuthenticationFailure(t, response)
	}
	if runtime.createCalls != 0 || runtime.statusCalls != 0 || runtime.deleteCalls != 0 || runtime.operationCalls != 0 {
		t.Fatal("runtime was called before authentication")
	}
}

func assertAuthenticationFailure(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("WWW-Authenticate") != `Bearer realm="secure-provisioner"` {
		t.Fatalf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
	}
	if response.Body.String() != authenticationErrorBody {
		t.Fatalf("body = %q", response.Body.String())
	}
}

type countingReadCloser struct {
	io.Reader
	readCalls int
}

func (reader *countingReadCloser) Read(p []byte) (int, error) {
	reader.readCalls++
	return reader.Reader.Read(p)
}
func (reader *countingReadCloser) Close() error { return nil }
