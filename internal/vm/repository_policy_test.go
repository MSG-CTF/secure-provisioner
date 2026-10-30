package vm

import (
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/httpapi"
)

func TestVMImagesCannotBeSubmittedToAnotherKubernetesTarget(t *testing.T) {
	cfg := target()
	r := &Router{targets: map[string]Target{cfg.ID: cfg}}
	const repo = "ghcr.io/example/portal"
	for _, image := range []string{cfg.Containers[0].Image, repo + "@sha256:" + strings.Repeat("b", 64), repo + ":latest",
		strings.Replace(cfg.Containers[0].Image, "ghcr.io/", "ghcr.io:443/", 1),
		strings.Replace(cfg.Containers[0].Image, "ghcr.io/", "ghcr.io.:00443/", 1),
	} {
		for _, legacy := range []bool{false, true} {
			req := request()
			req.Target = httpapi.RuntimeTarget{RuntimeType: httpapi.RuntimeTypeKubernetes, TargetID: "shared-k3s"}
			if legacy {
				req.Workload.Image, req.Workload.Containers = image, nil
			} else {
				req.Workload.Containers[0].Image = image
			}
			if err := r.Apply(&req); err == nil {
				t.Fatalf("VM image sent to K3s (legacy=%v): %s", legacy, image)
			}
		}
	}
	req := request()
	req.Target = httpapi.RuntimeTarget{RuntimeType: httpapi.RuntimeTypeKubernetes, TargetID: "shared-k3s"}
	req.Workload.Containers[0].Image = repo + "-other@sha256:" + strings.Repeat("a", 64)
	if err := r.Apply(&req); err != nil {
		t.Fatalf("unrelated K3s request rejected: %v", err)
	}
}
