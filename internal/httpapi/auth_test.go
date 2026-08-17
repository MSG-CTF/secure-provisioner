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
	testCases := []struct {
		name    string
		headers []string
	}{
		{name: "missing"},
		{name: "wrong scheme", headers: []string{"Basic abc"}},
		{name: "missing token", headers: []string{"Bearer"}},
		{name: "extra field", headers: []string{"Bearer wrong extra"}},
		{name: "wrong token", headers: []string{"Bearer CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}},
		{name: "multiple headers", headers: []string{"Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := NewHandler(&recordingCreateUseCase{}, ServiceAuthConfig{CurrentToken: testCurrentServiceToken})
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", nil)
			request.Header["Authorization"] = testCase.headers
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			assertAuthenticationFailure(t, response)
		})
	}
}

func TestServiceAuthenticationAcceptsCurrentAndPreviousTokens(t *testing.T) {
	handler := NewHandler(&recordingCreateUseCase{}, ServiceAuthConfig{
		CurrentToken:  testCurrentServiceToken,
		PreviousToken: testPreviousServiceToken,
	})

	for _, authorization := range []string{
		"Bearer " + testCurrentServiceToken,
		"bEaReR " + testPreviousServiceToken,
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", nil)
		request.Header.Set("Authorization", authorization)

		handler.ServeHTTP(response, request)

		if response.Code == http.StatusUnauthorized {
			t.Fatalf("Authorization %q was rejected: %s", authorization, response.Body.String())
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
		t.Fatalf("request body Read() calls = %d, want 0", body.readCalls)
	}
}

func TestAllInternalRoutesRequireServiceAuthentication(t *testing.T) {
	runtime := &recordingRuntimeUseCase{}
	handler := NewHandlerWithRuntime(&recordingCreateUseCase{}, runtime, ServiceAuthConfig{CurrentToken: testCurrentServiceToken})

	for _, testCase := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "create", method: http.MethodPost, path: "/internal/v1/instances"},
		{name: "runtime status", method: http.MethodGet, path: "/internal/v1/instances/instance-01/runtime-status"},
		{name: "delete", method: http.MethodDelete, path: "/internal/v1/instances/instance-01"},
		{name: "operation", method: http.MethodGet, path: "/internal/v1/operations/operation-01"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(testCase.method, testCase.path, nil)

			handler.ServeHTTP(response, request)

			assertAuthenticationFailure(t, response)
		})
	}
	if runtime.createCalls != 0 || runtime.statusCalls != 0 || runtime.deleteCalls != 0 || runtime.operationCalls != 0 {
		t.Fatalf("runtime calls = create:%d status:%d delete:%d operation:%d, want all 0", runtime.createCalls, runtime.statusCalls, runtime.deleteCalls, runtime.operationCalls)
	}
}

func assertAuthenticationFailure(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
	}
	if got := response.Header().Get("WWW-Authenticate"); got != `Bearer realm="secure-provisioner"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	if got := response.Body.String(); got != authenticationErrorBody {
		t.Fatalf("body = %q, want %q", got, authenticationErrorBody)
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

func (reader *countingReadCloser) Close() error {
	return nil
}
