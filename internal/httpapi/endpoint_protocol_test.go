package httpapi

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func endpointCatalog(t *testing.T, entries []endpointProtocolPolicy) (*ImagePolicyCatalog, error) {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal([]byte(testImagePolicies), &config); err != nil {
		t.Fatal(err)
	}
	config["endpoint_protocols"] = entries
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return ParseImagePolicies(raw)
}

func TestOperatorEndpointHintIsDigestPinnedAndPreservesWebIsolation(t *testing.T) {
	hints := []provisioner.PortProtocol{{Port: 8080, Protocol: isolation.EndpointProtocolTCP}}
	catalog, err := endpointCatalog(t, []endpointProtocolPolicy{{Image: gradePolicyImage, Container: "web", Ports: hints}})
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true}}
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	if request.IsolationProfile != "WEB" || command.PolicyRequest.WorkloadProfile != isolation.WorkloadProfileWeb ||
		!reflect.DeepEqual(command.Containers[0].EndpointProtocols, hints) {
		t.Fatal("connection hint changed the isolation profile or was lost")
	}
	request.Workload.Containers[0].endpointProtocols[0].Protocol = isolation.EndpointProtocolHTTP
	if catalog.endpointProtocols[gradePolicyImage].Ports[0].Protocol != isolation.EndpointProtocolTCP || command.Containers[0].EndpointProtocols[0].Protocol != isolation.EndpointProtocolTCP {
		t.Fatal("request and catalog must not share mutable hint slices")
	}
	request.Workload.Containers[0].Name = "other"
	if err := catalog.Apply(&request); err == nil {
		t.Fatal("container mismatch accepted")
	}
	request.Workload.Containers[0].Name = "web"
	request.Workload.Containers[0].Ports = []int{9000}
	if err := catalog.Apply(&request); err == nil {
		t.Fatal("undeclared protocol port accepted")
	}
}

func TestInvalidOperatorEndpointHintsFailAtStartup(t *testing.T) {
	valid := endpointProtocolPolicy{Image: gradePolicyImage, Container: "web", Ports: []provisioner.PortProtocol{{Port: 8080, Protocol: isolation.EndpointProtocolTCP}}}
	for _, mutate := range []func(*endpointProtocolPolicy){
		func(p *endpointProtocolPolicy) { p.Image = "ghcr.io/example/app:latest" },
		func(p *endpointProtocolPolicy) { p.Container = "../web" },
		func(p *endpointProtocolPolicy) { p.Ports = nil },
		func(p *endpointProtocolPolicy) {
			p.Ports = []provisioner.PortProtocol{{Port: 0, Protocol: isolation.EndpointProtocolTCP}}
		},
		func(p *endpointProtocolPolicy) { p.Ports = []provisioner.PortProtocol{{Port: 8080, Protocol: "FILE"}} },
		func(p *endpointProtocolPolicy) { p.Ports = append(p.Ports, p.Ports[0]) },
	} {
		entry := valid
		entry.Ports = append([]provisioner.PortProtocol(nil), valid.Ports...)
		mutate(&entry)
		if _, err := endpointCatalog(t, []endpointProtocolPolicy{entry}); err == nil {
			t.Fatal("invalid endpoint policy accepted")
		}
	}
	if _, err := endpointCatalog(t, []endpointProtocolPolicy{valid, valid}); err == nil {
		t.Fatal("duplicate image accepted")
	}
}

func TestCallerCannotSupplyOperatorEndpointHints(t *testing.T) {
	for _, field := range []string{"endpoint_protocols", "EndpointProtocols", "endpointProtocols"} {
		var body map[string]any
		if err := json.Unmarshal([]byte(validCreateRequestJSON()), &body); err != nil {
			t.Fatal(err)
		}
		container := body["workload"].(map[string]any)["containers"].([]any)[0].(map[string]any)
		container[field] = []any{map[string]any{"port": 8080, "protocol": "TCP"}}
		raw, _ := json.Marshal(body)
		var request CreateWorkloadRequest
		if err := json.Unmarshal(raw, &request); err == nil {
			t.Fatal("caller supplied a server-owned hint")
		}
	}
}
