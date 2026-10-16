package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
)

const networkTestDBImage = "ghcr.io/msg-ctf/challenges/web-grade-tampering/db@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const testWorkloadNetworkPolicies = `{
  "schema_version": 2,
  "managed_repositories": ["ghcr.io/msg-ctf/challenges/web-grade-tampering/web", "ghcr.io/msg-ctf/challenges/web-grade-tampering/db"],
  "images": [
    {"image":"` + gradePolicyImage + `","container":"web","isolation_profile":"WEB","status":"create_enabled","run_as_user":10001,"ports":[8080],"exposed_ports":[8080],"writable_paths":[{"path":"/tmp","size_mib":32}]},
    {"image":"` + networkTestDBImage + `","container":"db","isolation_profile":"WEB","status":"create_enabled","run_as_user":10001,"ports":[5432],"exposed_ports":[],"writable_paths":[{"path":"/tmp","size_mib":32}]}
  ],
  "workload_networks": [{
    "id":"grade-db-v1", "mode":"EXPLICIT_TCP_V1", "isolation_profile":"WEB",
    "containers":[{"name":"web","image":"` + gradePolicyImage + `","ports":[8080]},{"name":"db","image":"` + networkTestDBImage + `","ports":[5432]}],
    "allow":[{"from":"web","to":"db","port":5432}]
  }]
}`

func networkTestRequest() CreateWorkloadRequest {
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{
		{Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true, RunAsUser: 10001},
		{Name: "db", Image: networkTestDBImage, Ports: []int{5432}, RunAsUser: 10001},
	}
	return request
}

func TestWorkloadNetworkPolicyRequiresExactImageSetAndSnapshotsGraph(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(testWorkloadNetworkPolicies))
	if err != nil {
		t.Fatal(err)
	}
	request := networkTestRequest()
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	graph := command.PolicyRequest.WorkloadNetwork
	if graph == nil || graph.ID != "grade-db-v1" || graph.Mode != isolation.NetworkModeExplicitTCPV1 || len(graph.Allow) != 1 || graph.Allow[0].Port != 5432 {
		t.Fatalf("trusted graph snapshot missing: %#v", graph)
	}
	request.Workload.Containers = request.Workload.Containers[:1]
	if err := catalog.Apply(&request); !errors.Is(err, ErrImagePolicyRejected) {
		t.Fatalf("partial graph image set accepted: %v", err)
	}
}

func TestWorkloadNetworkPolicyRejectsWrongDigestAndExtraCompanion(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(testWorkloadNetworkPolicies))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CreateWorkloadRequest){
		func(r *CreateWorkloadRequest) {
			r.Workload.Containers[1].Image = strings.Replace(networkTestDBImage, "bbbb", "aaaa", 1)
		},
		func(r *CreateWorkloadRequest) {
			r.Workload.Containers = append(r.Workload.Containers, RuntimeContainer{Name: "other", Image: gradePolicyImage, Ports: []int{8080}})
		},
	} {
		request := networkTestRequest()
		mutate(&request)
		if err := catalog.Apply(&request); !errors.Is(err, ErrImagePolicyRejected) {
			t.Fatalf("mismatched graph accepted: %v", err)
		}
	}
}

func TestGraphManagedRepositoriesDoNotFallBackToFullMeshOnDigestRotation(t *testing.T) {
	var config imagePolicyFile
	if err := json.Unmarshal([]byte(testWorkloadNetworkPolicies), &config); err != nil {
		t.Fatal(err)
	}
	replacements := []string{
		strings.Replace(gradePolicyImage, "9ffbf", "affbf", 1),
		strings.Replace(networkTestDBImage, "bbbb", "cccc", 1),
	}
	for index, replacement := range replacements {
		image := config.Images[index]
		image.Image = replacement
		config.Images = append(config.Images, image)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ParseImagePolicies(encoded)
	if err != nil {
		t.Fatal(err)
	}
	request := networkTestRequest()
	for index, replacement := range replacements {
		request.Workload.Containers[index].Image = replacement
	}
	if err := catalog.Apply(&request); !errors.Is(err, ErrImagePolicyRejected) {
		t.Fatalf("rotated digests fell back to full mesh: %v", err)
	}
	runtime := &recordingRuntimeUseCase{}
	handler := withTestServiceAuthentication(NewHandlerWithRuntimePolicies(&recordingCreateUseCase{}, runtime, ServiceAuthConfig{CurrentToken: testCurrentServiceToken}, catalog))
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(string(body)))
	httpRequest.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "IMAGE_POLICY_REJECTED") || runtime.createCalls != 0 {
		t.Fatalf("rotated digest response=%d body=%s queued=%d", response.Code, response.Body.String(), runtime.createCalls)
	}
}

func TestWorkloadNetworkPolicyRejectsInvalidConfig(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(testWorkloadNetworkPolicies, `"mode":"EXPLICIT_TCP_V1"`, `"mode":"FULL_MESH"`, 1),
		strings.Replace(testWorkloadNetworkPolicies, `"schema_version": 2`, `"schema_version": 1`, 1),
		strings.Replace(testWorkloadNetworkPolicies, `"id":"grade-db-v1"`, `"id":"grade-db-v1","unexpected":true`, 1),
		strings.Replace(testWorkloadNetworkPolicies, `"to":"db","port":5432`, `"to":"db","port":5433`, 1),
		strings.Replace(testWorkloadNetworkPolicies, `"from":"web","to":"db","port":5432`, `"from":"web","to":"web","port":8080`, 1),
		strings.Replace(testWorkloadNetworkPolicies, `"allow":[{"from":"web","to":"db","port":5432}]`, `"allow":[{"from":"web","to":"db","port":5432},{"from":"web","to":"db","port":5432}]`, 1),
	} {
		if _, err := ParseImagePolicies([]byte(raw)); err == nil {
			t.Fatalf("invalid graph accepted: %s", raw)
		}
	}
	var config imagePolicyFile
	if err := json.Unmarshal([]byte(testWorkloadNetworkPolicies), &config); err != nil {
		t.Fatal(err)
	}
	config.WorkloadNetworks = append(config.WorkloadNetworks, config.WorkloadNetworks[0])
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseImagePolicies(encoded); err == nil {
		t.Fatal("duplicate graph id accepted")
	}
	config.WorkloadNetworks[1].ID = "grade-db-v2"
	encoded, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseImagePolicies(encoded); err == nil {
		t.Fatal("digest shared by two graphs")
	}
}

func TestCreateJSONCannotSupplyWorkloadNetwork(t *testing.T) {
	request := networkTestRequest()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "workload_network") {
		t.Fatal("network appeared on the public wire")
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"workload_network":{"mode":"EXPLICIT_TCP_V1"}}`)...)
	var decoded CreateWorkloadRequest
	if err := json.Unmarshal(encoded, &decoded); err == nil {
		t.Fatal("caller network field accepted")
	}
}
