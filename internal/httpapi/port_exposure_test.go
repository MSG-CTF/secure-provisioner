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

func TestPortExposureAcceptsMixedPorts(t *testing.T) {
	body := strings.Replace(validCreateRequestJSON(), `"ports":[8080],"expose":true`, `"ports":[8080,8081],"exposed_ports":[8080]`, 1)
	if body == validCreateRequestJSON() {
		t.Fatal("fixture replacement did not match")
	}
	var request CreateWorkloadRequest
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip CreateWorkloadRequest
	if err := json.Unmarshal(wire, &roundTrip); err != nil {
		t.Fatalf("request round trip: %v", err)
	}
	encoded, err := json.Marshal(request.ToCommand().Containers[0])
	if err != nil {
		t.Fatal(err)
	}
	var container map[string]any
	if err := json.Unmarshal(encoded, &container); err != nil {
		t.Fatal(err)
	}
	ports, ok := container["ExposedPorts"].([]any)
	if !ok || len(ports) != 1 || ports[0] != float64(8080) {
		t.Fatalf("public ports were lost: %s", encoded)
	}
}

func TestPortExposureHTTPContract(t *testing.T) {
	for _, test := range []struct {
		name, field   string
		status, calls int
	}{
		{"mixed", `"exposed_ports":[8080]`, http.StatusAccepted, 1},
		{"both", `"expose":false,"exposed_ports":[8080]`, http.StatusBadRequest, 0},
		{"unknown port", `"exposed_ports":[1234]`, http.StatusBadRequest, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &recordingRuntimeUseCase{operation: operations.Operation{ID: "op-mixed", Type: operations.OperationTypeCreate, Status: operations.OperationStatusQueued}, created: true}
			body := strings.Replace(validCreateRequestJSON(), `"ports":[8080],"expose":true`, `"ports":[8080,9000],`+test.field, 1)
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			newTestHandlerWithRuntime(&recordingCreateUseCase{}, runtime).ServeHTTP(response, request)
			if response.Code != test.status || runtime.createCalls != test.calls {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, runtime.createCalls, response.Body)
			}
			if test.calls == 1 && !reflect.DeepEqual(runtime.createCommand.Containers[0].PublicPorts(), []int{8080}) {
				t.Fatal("queue received wrong public ports")
			}
			if test.calls == 0 {
				assertErrorCode(t, response, "INVALID_REQUEST")
			}
		})
	}
}

func TestPortExposureRejectsAmbiguousOrInvalidSelection(t *testing.T) {
	for _, field := range []string{
		`"expose":true,"exposed_ports":[8080]`,
		`"expose":false,"exposed_ports":[8080]`,
		`"expose":null,"exposed_ports":[8080]`,
		`"Expose":false,"exposed_ports":[8080]`,
		`"expose":false,"EXPOSED_PORTS":[8080]`,
		`"exposed_ports":null`, `"exposed_ports":[8080,8080]`,
		`"exposed_ports":[9000]`, `"exposed_ports":[0]`, `"exposed_ports":[65536]`,
		`"exposed_ports":[]`,
	} {
		t.Run(field, func(t *testing.T) {
			body := strings.Replace(validCreateRequestJSON(), `"expose":true`, field, 1)
			var request CreateWorkloadRequest
			if err := json.Unmarshal([]byte(body), &request); err == nil && request.Validate() == nil {
				t.Fatal("invalid public selection accepted")
			}
		})
	}
}

func TestPortExposureNormalizesLegacyAndFullSelectionIdentically(t *testing.T) {
	var legacy, selected CreateWorkloadRequest
	if err := json.Unmarshal([]byte(validCreateRequestJSON()), &legacy); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(validCreateRequestJSON(), `"expose":true`, `"exposed_ports":[8080]`, 1)
	body = strings.Replace(body, `"expose":false`, `"exposed_ports":[]`, 1)
	if err := json.Unmarshal([]byte(body), &selected); err != nil {
		t.Fatal(err)
	}
	if err := selected.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy.ToCommand(), selected.ToCommand()) {
		t.Fatal("new full/private selection changes legacy command")
	}
}

func TestPortExposurePreservesPwnRestriction(t *testing.T) {
	body := strings.Replace(validCreateRequestJSON(), `"ports":[8080],"expose":true`, `"ports":[8080,8081],"exposed_ports":[8080]`, 1)
	body = strings.Replace(body, `"WEB"`, `"PWN"`, 1)
	var request CreateWorkloadRequest
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatal(err)
	}
	if request.Validate() == nil {
		t.Fatal("PWN mixed port limitation was relaxed")
	}
}
