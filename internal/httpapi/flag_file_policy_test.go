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
