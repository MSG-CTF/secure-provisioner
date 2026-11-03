package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func shutdownPolicy(strategy string) string {
	return strings.Replace(testImagePolicies, `"status": "create_enabled",`,
		`"status": "create_enabled", "shutdown_strategy": `+strategy+`,`, 1)
}

func TestImagePolicyShutdownReachesResolvedDurableCommand(t *testing.T) {
	for _, strategy := range []string{"python_sigint_pid1", "python_sigint_child"} {
		t.Run(strategy, func(t *testing.T) { assertShutdownDurableCommand(t, strategy) })
	}
}

func assertShutdownDurableCommand(t *testing.T, strategy string) {
	t.Helper()
	catalog, err := ParseImagePolicies([]byte(shutdownPolicy(`"` + strategy + `"`)))
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
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var restored provisioner.CreateWorkloadCommand
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(restored)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(encoded), `"ShutdownStrategy":"`+strategy+`"`) != 3 {
		t.Fatal("reviewed shutdown did not survive in container, policy request, and resolved policy")
	}
}

func TestImagePolicyShutdownRejectsUnsupportedStrategyOrProfile(t *testing.T) {
	for _, strategy := range []string{`"SIGINT"`, `"python_sigterm_pid1"`, `"python_sigint_pid1; id"`, `[]`, `true`} {
		t.Run(strategy, func(t *testing.T) {
			if _, err := ParseImagePolicies([]byte(shutdownPolicy(strategy))); err == nil {
				t.Fatal("unsupported shutdown strategy was accepted")
			}
		})
	}
	pwn := strings.Replace(shutdownPolicy(`"python_sigint_pid1"`), `"isolation_profile": "WEB"`, `"isolation_profile": "PWN"`, 1)
	pwn = strings.Replace(pwn, ",\n      {\"path\": \"/app/instance\", \"size_mib\": 32}", "", 1)
	// Establish that the profile fixture is otherwise valid before adding shutdown.
	withoutShutdown := strings.Replace(pwn, `"shutdown_strategy": "python_sigint_pid1",`, "", 1)
	if _, err := ParseImagePolicies([]byte(withoutShutdown)); err != nil {
		t.Fatalf("invalid PWN fixture: %v", err)
	}
	if _, err := ParseImagePolicies([]byte(pwn)); err == nil {
		t.Fatal("WEB-only shutdown strategy was accepted for PWN")
	}
}

func TestCallerCannotSelectShutdownStrategyOrLifecycle(t *testing.T) {
	for _, field := range []string{
		`"shutdown_strategy":"python_sigint_pid1"`, `"ShutdownStrategy":"python_sigint_pid1"`,
		`"shutdown_strategy":"python_sigint_child"`, `"ShutdownStrategy":"python_sigint_child"`,
		`"lifecycle":{"preStop":{"exec":{"command":["id"]}}}`, `"command":["id"]`, `"args":["id"]`,
	} {
		var container RuntimeContainer
		if err := json.Unmarshal([]byte(`{"name":"web",`+field+`}`), &container); err == nil {
			t.Fatalf("caller-selected execution field was accepted: %s", field)
		}
	}
}

func TestImagePolicyLegacyCommandOmitsShutdownStrategy(t *testing.T) {
	catalog, err := ParseImagePolicies([]byte(testImagePolicies))
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}}}
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(request.ToCommand())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "ShutdownStrategy") {
		t.Fatal("legacy command serialization gained a shutdown field")
	}
}
