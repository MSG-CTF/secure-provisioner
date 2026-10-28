package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
)

func TestPublicOriginIsAnOperatorOwnedImagePolicy(t *testing.T) {
	for _, name := range []string{"PUBLIC_ORIGIN", "FLAG", "LD_PRELOAD"} {
		raw := strings.Replace(testImagePolicies, `"status": "create_enabled",`, `"status": "create_enabled", "public_origin_env":"`+name+`",`, 1)
		_, err := ParseImagePolicies([]byte(raw))
		if (err == nil) != (name == "PUBLIC_ORIGIN") {
			t.Fatalf("field=%s err=%v", name, err)
		}
	}
}

func TestPublicOriginPolicyAllowsImagePreparation(t *testing.T) {
	raw := strings.Replace(testImagePolicies, `"status": "create_enabled",`, `"status": "create_enabled", "public_origin_env":"PUBLIC_ORIGIN",`, 1)
	catalog, err := ParseImagePolicies([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	request := imageprep.Request{IsolationProfile: "WEB", Containers: []imageprep.Container{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}}}}
	if err := catalog.Validate(request); err != nil {
		t.Fatalf("approved Gateway image cannot be prepared: %v", err)
	}
	request.Containers[0].Ports = []int{9090}
	if err := catalog.Validate(request); err == nil {
		t.Fatal("preparation bypassed approved ports")
	}
}

func TestPublicOriginCannotBeSuppliedByWorkloadCaller(t *testing.T) {
	raw := strings.Replace(testImagePolicies, `"status": "create_enabled",`, `"status": "create_enabled", "public_origin_env":"PUBLIC_ORIGIN",`, 1)
	catalog, err := ParseImagePolicies([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		runtime RuntimeType
		env     map[string]string
		allowed bool
	}{
		{"server_bound", RuntimeTypeKubernetes, map[string]string{"APP_ENV": "production"}, true},
		{"caller_origin", RuntimeTypeKubernetes, map[string]string{"PUBLIC_ORIGIN": "https://foreign.invalid"}, false},
		{"non_gateway_vm", RuntimeTypeVM, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := validCreateWorkloadRequest()
			request.Target.RuntimeType = tc.runtime
			request.Workload.Containers = []RuntimeContainer{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true, Env: tc.env}}
			err := catalog.Apply(&request)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v err=%v", tc.allowed, err)
			}
			if tc.allowed && request.Workload.Containers[0].publicOriginEnv != "PUBLIC_ORIGIN" {
				t.Fatal("trusted policy was lost")
			}
		})
	}
	var container RuntimeContainer
	if json.Unmarshal([]byte(`{"name":"web","public_origin_env":"PUBLIC_ORIGIN"}`), &container) == nil {
		t.Fatal("caller supplied the internal marker")
	}
}
