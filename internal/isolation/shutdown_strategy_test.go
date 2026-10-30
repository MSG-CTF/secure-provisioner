package isolation_test

import (
	"encoding/json"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
)

func TestResolverRejectsUnsupportedShutdownStrategyOrProfile(t *testing.T) {
	for _, test := range []struct {
		profile  isolation.WorkloadProfile
		strategy string
	}{
		{isolation.WorkloadProfileWeb, "arbitrary_exec"},
		{isolation.WorkloadProfilePwn, "python_sigint_pid1"},
		{isolation.WorkloadProfilePwn, "python_sigint_child"},
	} {
		t.Run(string(test.profile)+"/"+test.strategy, func(t *testing.T) {
			request := validRequest()
			request.WorkloadProfile = test.profile
			request.Containers = request.Containers[:1]
			data, err := json.Marshal(map[string]string{"ShutdownStrategy": test.strategy})
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &request.Containers[0]); err != nil {
				t.Fatal(err)
			}
			if _, err := isolation.NewStaticResolver().Resolve(request); err == nil {
				t.Fatal("resolver accepted unsupported shutdown behavior")
			}
		})
	}
}
