package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
	"github.com/MSG-CTF/secure-provisioner/internal/vm"
)

// Exercise production HTTP wiring: VM admission must still work when the same
// repositories are forbidden by the ordinary Kubernetes image catalog.
func TestApplicationBindsVMImagesWithoutKubernetesFallback(t *testing.T) {
	const repo = "ghcr.io/example/portal"
	const image = repo + "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	directory := t.TempDir()
	registryPath := filepath.Join(directory, "registry.json")
	if err := os.WriteFile(registryPath, []byte(`{"clusters":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(directory, "images.json")
	policy := `{"schema_version":1,"managed_repositories":["` + repo + `","ghcr.io/example/web"],"vm_required_repositories":["` + repo + `"],"images":[{"image":"ghcr.io/example/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","container":"web","isolation_profile":"WEB","status":"create_enabled","run_as_user":10001,"ports":[8080],"exposed_ports":[8080],"writable_paths":[{"path":"/tmp","size_mib":64}]}]}`
	if err := os.WriteFile(policyPath, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	target := vm.Target{ID: "exclusive-vm", Host: "192.0.2.10", Port: 22, User: "msgvm",
		Identity: filepath.Join(directory, "identity"), KnownHosts: filepath.Join(directory, "known_hosts"),
		Profile: strings.Repeat("a", 64), PublicURL: "http://192.0.2.10:18080",
		Limits:     httpapi.ResourceLimits{CPUMillicores: 2000, MemoryMiB: 4000, EphemeralStorageMiB: 2048},
		Containers: []vm.Container{{Name: "portal", Image: image, Ports: []int{8080}, PublicPorts: []int{8080}}},
	}
	encoded, err := json.Marshal(map[string]any{"schema_version": 1, "targets": []vm.Target{target}})
	if err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(directory, "vm-targets.json")
	if err := os.WriteFile(targetPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"image catalog only", "VM catalog only", "both"} {
		t.Run(source, func(t *testing.T) {
			config, err := loadConfig(environment(map[string]string{"PROVISIONER_CLUSTER_REGISTRY": registryPath, "PROVISIONER_SERVICE_TOKEN": validCurrentServiceToken}))
			if err != nil {
				t.Fatal(err)
			}
			if source != "VM catalog only" {
				config.ImagePoliciesPath = policyPath
			}
			if source != "image catalog only" {
				config.VMTargetsPath = targetPath
			}
			app, err := newApplication(config, fakeClientFactory{})
			if err != nil {
				t.Fatal(err)
			}
			req := httpapi.CreateWorkloadRequest{RequestID: "vm-admission-test", InstanceID: "00000000-0000-4000-8000-000000000001", TeamID: "00000000-0000-4000-8000-000000000002", IsolationProfile: "WEB",
				Target:   httpapi.RuntimeTarget{RuntimeType: httpapi.RuntimeTypeVM, TargetID: target.ID},
				Workload: httpapi.RuntimeWorkload{ResourceLimits: target.Limits, Containers: []httpapi.RuntimeContainer{{Name: "portal", Image: image, Ports: []int{8080}, Expose: true, RunAsUser: 10001}}},
			}
			post := func(req httpapi.CreateWorkloadRequest) *httptest.ResponseRecorder {
				t.Helper()
				raw, err := json.Marshal(req)
				if err != nil {
					t.Fatal(err)
				}
				httpReq := httptest.NewRequest(http.MethodPost, "/internal/v1/instances", strings.NewReader(string(raw)))
				httpReq.Header.Set("Authorization", "Bearer "+validCurrentServiceToken)
				httpReq.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				app.handler.ServeHTTP(response, httpReq)
				return response
			}
			// Block even a newly published digest, on a different K3s target.
			bad := req
			bad.Workload.Containers = append([]httpapi.RuntimeContainer(nil), req.Workload.Containers...)
			bad.Target = httpapi.RuntimeTarget{RuntimeType: httpapi.RuntimeTypeKubernetes, TargetID: "shared-k3s"}
			bad.Workload.Containers[0].Image = repo + "@sha256:" + strings.Repeat("b", 64)
			for _, alias := range []string{repo, strings.Replace(repo, "ghcr.io/", "ghcr.io:443/", 1), strings.Replace(repo, "ghcr.io/", "ghcr.io.:00443/", 1)} {
				bad.Workload.Containers[0].Image = alias + "@sha256:" + strings.Repeat("b", 64)
				if response := post(bad); response.Code != http.StatusUnprocessableEntity {
					t.Fatalf("K3s admission=%d alias=%s: %s", response.Code, alias, response.Body)
				}
			}
			if source != "image catalog only" {
				response := post(req)
				if response.Code != http.StatusAccepted {
					t.Fatalf("exact VM rejected=%d: %s", response.Code, response.Body)
				}
				// A changed digest is never auto-approved for the VM, either.
				req.RequestID = "changed-digest"
				req.InstanceID = "00000000-0000-4000-8000-000000000003"
				req.Workload.Containers[0].Image = repo + "@sha256:" + strings.Repeat("b", 64)
				if response = post(req); response.Code != http.StatusUnprocessableEntity {
					t.Fatalf("changed VM digest admitted=%d: %s", response.Code, response.Body)
				}
			}
		})
	}
}
