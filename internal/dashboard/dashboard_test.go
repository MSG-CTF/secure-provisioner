package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesRuntimeDashboard(t *testing.T) {
	handler := Handler(http.NotFoundHandler())
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q", contentType)
	}
	body := response.Body.String()
	for _, text := range []string{
		"Runtime Monitor",
		"컨테이너 런타임",
		"target_id",
		"CPU 사용량",
		"메모리 사용량",
		"인스턴스 삭제",
		"/internal/v1/instances/",
		"runtime-status",
	} {
		if !strings.Contains(body, text) {
			t.Fatalf("dashboard does not contain %q", text)
		}
	}
	for _, forbidden := range []string{"kubeconfig", "private_key", "api_server"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("dashboard contains forbidden cluster field %q", forbidden)
		}
	}
}

func TestHandlerDelegatesInternalAPI(t *testing.T) {
	api := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-API-Path", request.URL.Path)
		writer.WriteHeader(http.StatusTeapot)
	})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/internal/v1/instances/demo/runtime-status", nil)

	Handler(api).ServeHTTP(response, request)

	if response.Code != http.StatusTeapot || response.Header().Get("X-API-Path") != request.URL.Path {
		t.Fatalf("response = %#v", response.Result())
	}
}

func TestHandlerRejectsUnknownDashboardPath(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/unknown", nil)

	Handler(http.NotFoundHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d", response.Code)
	}
}
