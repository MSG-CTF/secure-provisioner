package httpapi

import (
	"errors"
	"strings"
	"testing"
)

func TestVMRequiredRepositoryBlocksKubernetesAcrossDigests(t *testing.T) {
	const repo = "ghcr.io/msg-ctf/challenges/web-afterimage/indexer"
	raw := strings.Replace(testImagePolicies, `"schema_version": 1,`, `"schema_version": 1, "vm_required_repositories": ["`+repo+`"],`, 1)
	raw = strings.Replace(raw, `"managed_repositories": [`, `"managed_repositories": ["`+repo+`",`, 1)
	catalog, err := ParseImagePolicies([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{repo + "@sha256:" + strings.Repeat("a", 64), repo + "@sha256:" + strings.Repeat("b", 64), repo + ":latest",
		strings.Replace(repo, "ghcr.io/", "ghcr.io:443/", 1) + "@sha256:" + strings.Repeat("a", 64),
		strings.Replace(repo, "ghcr.io/", "ghcr.io.:00443/", 1) + "@sha256:" + strings.Repeat("a", 64),
	} {
		for _, legacy := range []bool{false, true} {
			req := validCreateWorkloadRequest()
			if legacy {
				req.Workload.Image, req.Workload.Containers = image, nil
			} else {
				req.Workload.Containers[0].Image = image
			}
			if err := catalog.Apply(&req); !errors.Is(err, ErrImagePolicyRejected) || !strings.Contains(err.Error(), "dedicated VM") {
				t.Fatalf("VM repository admitted (legacy=%v image=%s): %v", legacy, image, err)
			}
		}
	}
	req := validCreateWorkloadRequest()
	if err := catalog.Apply(&req); err != nil {
		t.Fatalf("unrelated WEB rejected: %v", err)
	}
	if catalog.RequiresVMImage(repo + "-other@sha256:" + strings.Repeat("a", 64)) {
		t.Fatal("repository prefix matched unrelated image")
	}
}

func TestVMRequiredRepositoriesMustBeManagedAndUnique(t *testing.T) {
	for _, list := range []string{
		`["ghcr.io/unknown/image"]`,
		`["ghcr.io/msg-ctf/challenges/web-grade-tampering/web","ghcr.io/msg-ctf/challenges/web-grade-tampering/web"]`,
		`[""]`, `["GHCR.IO/IMAGE"]`,
	} {
		raw := strings.Replace(testImagePolicies, `"schema_version": 1,`, `"schema_version": 1, "vm_required_repositories": `+list+`,`, 1)
		if _, err := ParseImagePolicies([]byte(raw)); err == nil {
			t.Fatalf("invalid VM scope accepted: %s", list)
		}
	}
}

func TestManagedRepositoryKeysMustUseCanonicalRegistryHost(t *testing.T) {
	raw := strings.ReplaceAll(testImagePolicies, "ghcr.io/", "ghcr.io./")
	if _, err := ParseImagePolicies([]byte(raw)); err == nil {
		t.Fatal("noncanonical managed scope accepted")
	}
}
