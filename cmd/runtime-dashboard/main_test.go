package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/runtimeops"
)

func TestNewDemoHandlerServesDashboardAndRuntimeAPI(t *testing.T) {
	handler, _, err := newDemoHandler()
	if err != nil {
		t.Fatal(err)
	}

	root := httptest.NewRecorder()
	handler.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Code != http.StatusOK || !strings.Contains(root.Body.String(), "Runtime Monitor") {
		t.Fatalf("root response = %d %s", root.Code, root.Body.String())
	}

	status := httptest.NewRecorder()
	handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/internal/v1/instances/"+runtimeops.DemoInstanceID+"/runtime-status", nil))
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"target_id":"`+runtimeops.DemoTargetID+`"`) {
		t.Fatalf("status response = %d %s", status.Code, status.Body.String())
	}
}
