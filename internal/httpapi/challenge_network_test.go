package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
)

func peerPolicyJSON() string {
	body := strings.Replace(testWorkloadNetworkPolicies, `"mode":"EXPLICIT_TCP_V1"`, `"mode":"PEER_GROUPS_V1"`, 1)
	return strings.Replace(body, `"allow":[{"from":"web","to":"db","port":5432}]`, `"peer_groups":[{"name":"appnet","members":["web","db"]}],"egress":[{"from":"web","cidr":"10.20.30.40/32","ports":[443]}]`, 1)
}

func TestNetworkRequiredRepositoriesRejectGraphRemovalAndDigestRotation(t *testing.T) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(testWorkloadNetworkPolicies), &raw); err != nil {
		t.Fatal(err)
	}
	raw["network_required_repositories"] = []string{"ghcr.io/msg-ctf/challenges/web-grade-tampering/web", "ghcr.io/msg-ctf/challenges/web-grade-tampering/db"}
	delete(raw, "workload_networks")
	encoded, _ := json.Marshal(raw)
	for _, rotate := range []bool{false, true} {
		body := string(encoded)
		request := networkTestRequest()
		if rotate {
			for index := range request.Workload.Containers {
				old := request.Workload.Containers[index].Image
				changed := strings.Replace(old, "@sha256:", "@sha256:c", 1)
				changed = changed[:len(changed)-1]
				body = strings.ReplaceAll(body, old, changed)
				request.Workload.Containers[index].Image = changed
			}
		}
		catalog, err := ParseImagePolicies([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if err := catalog.Apply(&request); !errors.Is(err, ErrImagePolicyRejected) {
			t.Fatalf("network-required images fell back to full mesh (rotation=%t): %v", rotate, err)
		}
	}
}

func TestPeerNetworkFingerprintReplayKeepsAcceptedSnapshotAfterPolicyChangeAndRemoval(t *testing.T) {
	store := operations.NewMemoryStore(func() (string, error) { return "peer-network-operation", nil })
	request := networkTestRequest()
	encoded, _ := json.Marshal(request)
	body := string(encoded)
	first := reviewPostBody(reviewPolicyHandler(t, store, peerPolicyJSON()), body)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first: %d %s", first.Code, first.Body.String())
	}
	accepted, err := store.GetByRequestID(request.RequestID)
	if err != nil || accepted.CreateCommand.Policy.WorkloadNetwork == nil || accepted.CreateCommand.RequestFingerprint == "" {
		t.Fatalf("missing accepted snapshot: %v", err)
	}
	var removed map[string]any
	if err := json.Unmarshal([]byte(peerPolicyJSON()), &removed); err != nil {
		t.Fatal(err)
	}
	delete(removed, "workload_networks")
	removed["network_required_repositories"] = []string{"ghcr.io/msg-ctf/challenges/web-grade-tampering/web"}
	removedJSON, _ := json.Marshal(removed)
	for _, policy := range []string{strings.Replace(peerPolicyJSON(), "10.20.30.40/32", "10.20.30.41/32", 1), string(removedJSON)} {
		handler := reviewPolicyHandler(t, store, policy)
		response := reviewPostBody(handler, body)
		if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"created":false`) {
			t.Fatalf("replay: %d %s", response.Code, response.Body.String())
		}
		saved, err := store.GetByRequestID(request.RequestID)
		if err != nil || !reflect.DeepEqual(accepted.CreateCommand.Policy.WorkloadNetwork, saved.CreateCommand.Policy.WorkloadNetwork) {
			t.Fatalf("accepted network changed: %v", err)
		}
		changed := request
		changed.Workload.ResourceLimits.MemoryMiB++
		changedJSON, _ := json.Marshal(changed)
		if response := reviewPostBody(handler, string(changedJSON)); response.Code != http.StatusConflict {
			t.Fatalf("changed caller input: %d %s", response.Code, response.Body.String())
		}
	}
}

func TestCallerCannotInjectPeerGroupsEgressOrRepositoryRequirements(t *testing.T) {
	for _, field := range []string{`"peer_groups":[]`, `"egress":[]`, `"network_required_repositories":[]`, `"workload_network":{"mode":"PEER_GROUPS_V1"}`} {
		body := strings.TrimSuffix(validCreateRequestJSON(), "}") + "," + field + "}"
		var request CreateWorkloadRequest
		if err := json.Unmarshal([]byte(body), &request); err == nil {
			t.Fatalf("caller field accepted: %s", field)
		}
	}
}

func TestNetworkCatalogRejectsUnknownOrDuplicateRequiredRepositories(t *testing.T) {
	for _, required := range []string{`["ghcr.io/unknown/service"]`, `["ghcr.io/msg-ctf/challenges/web-grade-tampering/web","ghcr.io/msg-ctf/challenges/web-grade-tampering/web"]`} {
		body := strings.Replace(testWorkloadNetworkPolicies, `"schema_version": 2,`, `"schema_version": 2,"network_required_repositories":`+required+`,`, 1)
		if _, err := ParseImagePolicies([]byte(body)); err == nil {
			t.Fatalf("invalid required repositories accepted: %s", required)
		}
	}
	body := strings.Replace(testImagePolicies, `"schema_version": 1,`, `"schema_version": 1,"network_required_repositories":[],`, 1)
	if body == testImagePolicies {
		t.Fatal("schema fixture was not changed")
	}
	if _, err := ParseImagePolicies([]byte(body)); err == nil {
		t.Fatal("schema 1 accepted network requirements")
	}
}

func TestNetworkCatalogRejectsUnknownNestedPeerAndEgressFields(t *testing.T) {
	for _, body := range []string{
		strings.Replace(peerPolicyJSON(), `"name":"appnet"`, `"name":"appnet","unexpected":true`, 1),
		strings.Replace(peerPolicyJSON(), `"cidr":"10.20.30.40/32"`, `"cidr":"10.20.30.40/32","protocol":"UDP"`, 1),
		strings.Replace(peerPolicyJSON(), `"ports":[443]`, `"ports":[443],"ports":[80]`, 1),
	} {
		if _, err := ParseImagePolicies([]byte(body)); err == nil {
			t.Fatal("unknown or duplicate nested network fields accepted")
		}
	}
}
