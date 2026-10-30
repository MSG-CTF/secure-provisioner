package httpapi

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestVMRequirementAndWorkloadNetworkAdmissionCoexist(t *testing.T) {
	var config imagePolicyFile
	if err := json.Unmarshal([]byte(testWorkloadNetworkPolicies), &config); err != nil {
		t.Fatal(err)
	}
	const vmRepository = "ghcr.io/msg-ctf/challenges/web-afterimage/portal"
	config.ManagedRepositories = append(config.ManagedRepositories, vmRepository)
	config.VMRequiredRepositories = []string{vmRepository}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ParseImagePolicies(encoded)
	if err != nil {
		t.Fatal(err)
	}
	request := networkTestRequest()
	if err := catalog.Apply(&request); err != nil || request.workloadNetwork == nil {
		t.Fatalf("approved network rejected after VM policy merge: %v", err)
	}
	request.Workload.Containers[0].Image = vmRepository + "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := catalog.Apply(&request); !errors.Is(err, ErrImagePolicyRejected) {
		t.Fatalf("VM-only image entered Kubernetes graph: %v", err)
	}
	config.VMRequiredRepositories = append(config.VMRequiredRepositories, config.ManagedRepositories[0])
	encoded, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseImagePolicies(encoded); err == nil {
		t.Fatal("VM-only repository accepted as a Kubernetes graph image")
	}
}
