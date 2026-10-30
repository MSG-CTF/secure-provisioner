package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func TestCreateAcceptsSchedulerMultiportRequestsWithOptionalHealthcheck(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		for _, healthcheck := range []bool{false, true} {
			name := "expose"
			if explicit {
				name = "exposed_ports"
			}
			if healthcheck {
				name += "/http"
			} else {
				name += "/tcp"
			}
			t.Run(name, func(t *testing.T) {
				var body map[string]any
				if err := json.Unmarshal([]byte(validCreateRequestJSON()), &body); err != nil {
					t.Fatal(err)
				}
				workload := body["workload"].(map[string]any)
				web := workload["containers"].([]any)[0].(map[string]any)
				web["ports"] = []int{8080, 9090}
				if explicit {
					web["ports"] = []int{9000, 8080, 9090}
					delete(web, "expose")
					web["exposed_ports"] = []int{8080, 9090}
				}
				if healthcheck {
					workload["healthcheck"] = map[string]any{"container": "web", "port": 9090, "path": "/healthz"}
				}
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				runtime := &recordingRuntimeUseCase{
					operation: operations.Operation{ID: "op-multi", Type: operations.OperationTypeCreate, Status: operations.OperationStatusQueued},
					created:   true,
				}
				handler := newTestHandlerWithRuntime(&recordingCreateUseCase{}, runtime)
				request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(string(encoded)))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusAccepted || runtime.createCalls != 1 {
					t.Fatalf("Scheduler-compatible request rejected: %d %s", response.Code, response.Body.String())
				}
				container := runtime.createCommand.Containers[0]
				if !reflect.DeepEqual(container.PublicPorts(), []int{8080, 9090}) {
					t.Fatalf("public ports changed: %v", container.PublicPorts())
				}
				if healthcheck {
					if container.ReadinessHTTP == nil || container.ReadinessHTTP.Port != 9090 || container.ReadinessHTTP.Path != "/healthz" {
						t.Fatalf("HTTP healthcheck changed: %#v", container.ReadinessHTTP)
					}
				} else if container.ReadinessHTTP != nil {
					t.Fatal("request without healthcheck must use the TCP fallback")
				}
			})
		}
	}
}
