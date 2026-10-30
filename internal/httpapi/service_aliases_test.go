package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestServiceAliasesArePinnedByImagePolicyAndNotRequestJSON(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(strings.Replace(testImagePolicies, `"run_as_user": 10001,`, `"run_as_user": 10001, "service_aliases": ["web-compat"],`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true, RunAsUser: 10001}}
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	aliases := command.PolicyRequest.Containers[0].ServiceAliases
	if len(aliases) != 1 || aliases[0] != "web-compat" {
		t.Fatal("trusted alias missing from saved policy")
	}
	var container RuntimeContainer
	if err := json.Unmarshal([]byte(`{"name":"web","image":"x","ports":[8080],"service_aliases":["admin"]}`), &container); err == nil {
		t.Fatal("request JSON accepted an operator-only alias")
	}
}

func TestInvalidImagePolicyServiceAliasesAreRejected(t *testing.T) {
	for _, aliases := range []string{`["web"]`, `["bad.name"]`, `["one","two"]`, `[""]`} {
		raw := strings.Replace(testImagePolicies, `"run_as_user": 10001,`, `"run_as_user": 10001, "service_aliases": `+aliases+`,`, 1)
		if _, err := ParseImagePolicies([]byte(raw)); err == nil {
			t.Fatalf("invalid alias policy accepted: %s", aliases)
		}
	}
}
