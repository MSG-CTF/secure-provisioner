package provisioner

import "testing"

func TestRepositoryLookupPreservesRegistryPortAndExactPath(t *testing.T) {
	for image, want := range map[string]string{
		"registry.example:5000/group/image@sha256:abc": "registry.example:5000/group/image",
		"registry.example:5000/group/image:tag":        "registry.example:5000/group/image",
		"registry.example.:05000/group/image:tag":      "registry.example:5000/group/image",
		"ghcr.io/group/image-other@sha256:abc":         "ghcr.io/group/image-other",
		"ghcr.io/group/image":                          "ghcr.io/group/image",
		"GHCR.IO/group/image@sha256:abc":               "ghcr.io/group/image",
		"ghcr.io:443/group/image@sha256:abc":           "ghcr.io/group/image",
		"ghcr.io:00443/group/image:tag":                "ghcr.io/group/image",
		"ghcr.io./group/image@sha256:abc":              "ghcr.io/group/image",
		"ghcr.io.:443/group/image@sha256:abc":          "ghcr.io/group/image",
		"":                                             "",
	} {
		if got := ImageRepository(image); got != want {
			t.Fatalf("%q: got %q, want %q", image, got, want)
		}
	}
}
