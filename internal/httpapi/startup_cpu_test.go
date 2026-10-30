package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestStartupCPURequiresExactReviewedPair(t *testing.T) {
	config := strings.Replace(testImagePolicies, `"status": "create_enabled",`,
		`"status": "create_enabled", "steady_cpu_millicores": 300, "startup_cpu_millicores": 1000,`, 1)
	catalog, err := ParseImagePolicies([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		steady, peak int
		approved     bool
	}{{300, 1000, true}, {250, 1000, false}, {300, 2000, false}, {0, 1000, true}} {
		request := validCreateWorkloadRequest()
		request.Workload.Containers = []RuntimeContainer{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true, RunAsUser: 10001}}
		request.Workload.SteadyCPUMillicores = tc.steady
		request.Workload.ResourceLimits.CPUMillicores = tc.peak
		err := catalog.Apply(&request)
		if (err == nil) != tc.approved {
			t.Fatalf("%+v: err=%v", tc, err)
		}
	}
	if len(catalog.StartupCPUProfiles()) != 1 {
		t.Fatal("missing replay policy")
	}
}

func TestStartupCPUConfirmationSurvivesAsyncOperationResponse(t *testing.T) {
	result := provisioner.CreateWorkloadResult{RuntimeWorkloadID: "workload", SteadyCPUMillicores: 300}
	op := operations.Operation{Type: operations.OperationTypeCreate, Status: operations.OperationStatusSucceeded,
		Result: operations.OperationResult{Create: &result}}
	response := newOperationResponse(op)
	if response.Result == nil || response.Result.SteadyCPUMillicores != 300 {
		t.Fatal("async result lost CPU confirmation")
	}
	encoded, _ := json.Marshal(response)
	if !strings.Contains(string(encoded), `"steady_cpu_millicores":300`) {
		t.Fatal("wire confirmation missing")
	}
	op.Status = operations.OperationStatusRunning
	if newOperationResponse(op).Result != nil {
		t.Fatal("published an unconfirmed result")
	}
}

func TestStartupCPUWireRejectsNullZeroAndUnknownCase(t *testing.T) {
	for _, field := range []string{`"steady_cpu_millicores":null`, `"steady_cpu_millicores":0`, `"steady_cpu_millicores":-1`, `"steady_cpu_millicores":"300"`, `"steady_cpu_millicores":true`, `"steadyCpuMillicores":300`} {
		var workload RuntimeWorkload
		if json.Unmarshal([]byte(`{`+field+`}`), &workload) == nil {
			t.Fatalf("accepted %s", field)
		}
	}
	var workload RuntimeWorkload
	if err := json.Unmarshal([]byte(`{"resource_limits":{"cpu_millicores":1000},"steady_cpu_millicores":300}`), &workload); err != nil || workload.SteadyCPUMillicores != 300 {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(RuntimeWorkload{})
	if strings.Contains(string(encoded), "steady_cpu_millicores") {
		t.Fatal("legacy fingerprint changed")
	}
}
