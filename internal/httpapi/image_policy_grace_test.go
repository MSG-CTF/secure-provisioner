package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func gracePolicy(value string) string {
	return strings.Replace(testImagePolicies, "\"status\": \"create_enabled\",", "\"status\": \"create_enabled\", \"termination_grace_period_seconds\": "+value+",", 1)
}
func TestImagePolicyGraceReachesEveryDurableCopy(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(gracePolicy("5")))
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}}}
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	command.Policy, err = isolation.NewStaticResolver().Resolve(command.PolicyRequest)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var restored provisioner.CreateWorkloadCommand
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Containers[0].TerminationGracePeriodSeconds != 5 || restored.PolicyRequest.Containers[0].TerminationGracePeriodSeconds != 5 || restored.Policy.Containers[0].TerminationGracePeriodSeconds != 5 {
		t.Fatal("termination grace lost across a durable copy")
	}
	legacy := validCreateWorkloadRequest()
	data, err = json.Marshal(legacy.ToCommand())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "TerminationGracePeriodSeconds") {
		t.Fatal("legacy serialization gained a new default")
	}
}
func TestImagePolicyGraceRejectsUnsafeValuesAndCallerOverrides(t *testing.T) {
	for _, value := range []string{"0", "-1", "301", "1.5", "true", "[]", "\"5\""} {
		if _, err := ParseImagePolicies([]byte(gracePolicy(value))); err == nil {
			t.Fatalf("accepted invalid grace: %s", value)
		}
	}
	for _, field := range []string{"termination_grace_period_seconds", "TerminationGracePeriodSeconds"} {
		var container RuntimeContainer
		if err := json.Unmarshal([]byte("{\"name\":\"web\",\""+field+"\":5}"), &container); err == nil {
			t.Fatalf("caller changed operator grace: %s", field)
		}
	}
}
