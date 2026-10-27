package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFlagFilePathIsOperatorOwned(t *testing.T) {
	contents := strings.Replace(testImagePolicies, `"status": "create_enabled",`, `"status": "create_enabled", "requires_flag": true, "flag_file_path": "/flag",`, 1)
	catalog, err := ParseImagePolicies([]byte(contents))
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateWorkloadRequest()
	request.Workload.Containers = []RuntimeContainer{{Name: "web", Image: gradePolicyImage, Ports: []int{8080}, Expose: true}}
	if err := catalog.Apply(&request); err != nil {
		t.Fatal(err)
	}
	if request.Workload.Containers[0].flagFilePath != "/flag" || !request.Workload.Containers[0].requiresFlag {
		t.Fatal("operator FLAG file was not selected")
	}
	files := catalog.RequiredFlagFiles()
	files[gradePolicyImage] = "/changed"
	if catalog.RequiredFlagFiles()[gradePolicyImage] != "/flag" {
		t.Fatal("mutable policy escaped")
	}
	for _, key := range []string{"flag_file_path", "flagFilePath"} {
		var container RuntimeContainer
		if json.Unmarshal([]byte(`{"name":"web","`+key+`":"/flag"}`), &container) == nil {
			t.Fatal("caller chose a FLAG file")
		}
	}
	for _, filename := range []string{"/etc/passwd", "/sys/flag", "/home/ctf/../flag.txt", "flag.txt"} {
		if _, err := ParseImagePolicies([]byte(strings.Replace(contents, `"/flag"`, `"`+filename+`"`, 1))); err == nil {
			t.Fatal("unsafe operator path accepted")
		}
	}
	if _, err := ParseImagePolicies([]byte(strings.Replace(contents, `"requires_flag": true,`, "", 1))); err == nil {
		t.Fatal("file policy without required FLAG accepted")
	}
}

func TestPublishedPwnCatalogRequiresBackendFlags(t *testing.T) {
	catalog, err := LoadImagePolicies("../../config/pwn-image-policies.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.RequiredFlagImages()) != 10 || len(catalog.RequiredFlagFiles()) != 8 {
		t.Fatal("PWN FLAG policy is incomplete")
	}
	random6 := "ghcr.io/msg-ctf/challenges/pwn-random6/random6@sha256:8005b9a77163b476a4638d06905f8a18b5770311fa033e163fc706000d3b834a"
	policy, found := catalog.images[random6]
	if !found || policy.RunAsUser != 31337 || len(policy.Ports) != 1 || policy.Ports[0] != 6666 ||
		len(policy.ExposedPorts) != 1 || policy.ExposedPorts[0] != 6666 {
		t.Fatal("Random6 release policy does not match the author service")
	}
	for image, expectedPath := range map[string]string{
		"ghcr.io/msg-ctf/challenges/pwn-note/service@sha256:3c1dcb4478d82564ad298b1cddee770f5d786a6d1052b1f842a538f91439868e": "/home/ctf/flag.txt",
		"ghcr.io/msg-ctf/challenges/pwn-ghost-file/chall@sha256:59bdd9111ad77a9a682f0e862eade12193b62d9fd6fd77b9ee810cd7e06460bc": "/flag",
		"ghcr.io/msg-ctf/challenges/pwn-ghost-file/chall@sha256:d9d2a07ebfcea332f49b07273a8ac64a0665b49995c892a147c31d99e9c7eba8": "/flag",
		"ghcr.io/msg-ctf/challenges/pwn-price-tag/price-tag@sha256:fb15aab14664eafbcccfa94edec0597e81f6d78c575b8b562547bc8955dee751": "/home/player/flag.txt",
		"ghcr.io/msg-ctf/challenges/pwn-price-tag/price-tag@sha256:c92f888b7e01c931815409fb61e7224b5ab56d2603fc15edbc3568127aad7169": "/home/player/flag.txt",
	} {
		if catalog.RequiredFlagFiles()[image] != expectedPath {
			t.Fatalf("wrong FLAG mount for %s", image)
		}
	}
	for image, policy := range catalog.images {
		if policy.IsolationProfile != "PWN" || policy.CISmokeEnabled || !policy.RequiresFlag {
			t.Fatal("PWN isolation or FLAG requirement was weakened")
		}
		request := validCreateWorkloadRequest()
		request.IsolationProfile = "PWN"
		request.Workload.Containers = []RuntimeContainer{{Name: policy.Container, Image: image, Ports: policy.Ports, Expose: true}}
		if err := catalog.Apply(&request); err != nil {
			t.Fatal(err)
		}
		if err := request.Validate(); err == nil {
			t.Fatal("published image accepted without Backend secret_ref")
		}
		request.Workload.Containers[0].Image = strings.Split(image, "@")[0] + "@sha256:" + strings.Repeat("a", 64)
		if err := catalog.Apply(&request); err == nil {
			t.Fatal("unreviewed PWN digest was accepted")
		}
	}
}
