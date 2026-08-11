package provisioner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardIsServedAtRoot(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	NewHandler(nil).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected dashboard status 200, got %d", response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "text/html; charset=utf-8" {
		t.Fatalf("expected HTML content type, got %q", contentType)
	}
	body := response.Body.String()
	for _, expected := range []string{"Secure Provisioner", "인스턴스 생성", "xss-101", "/internal/v1/instances"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected dashboard to contain %q", expected)
		}
	}
}
