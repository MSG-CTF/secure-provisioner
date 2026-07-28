package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestDeleteWorkloadRequestDecodesAndConvertsSchedulerContract(t *testing.T) {
	body := `{"request_id":"req-delete-01","instance_id":"018f3f1e-21b8-7a91-a30b-63b3400fd001","team_id":1,"target":{"runtime_type":"KUBERNETES","target_id":"cluster-main"},"runtime_workload_id":"cluster-main/ns-team-1/workload-abc","delete_reason":"TTL_EXPIRED"}`
	var request DeleteWorkloadRequest
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	if command.RuntimeType != provisioner.RuntimeTypeKubernetes || command.Reason != provisioner.DeleteReasonTTLExpired {
		t.Fatalf("command = %#v", command)
	}
	if command.RuntimeWorkloadID != "cluster-main/ns-team-1/workload-abc" {
		t.Fatalf("runtime workload id = %q", command.RuntimeWorkloadID)
	}
}

func TestDeleteWorkloadRequestUsesDeleteReasonField(t *testing.T) {
	encoded, err := json.Marshal(validDeleteWorkloadRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"delete_reason":"USER_REQUESTED"`) || strings.Contains(string(encoded), `"reason"`) {
		t.Fatalf("json = %s", encoded)
	}
}

func TestDeleteWorkloadRequestAcceptsOnlyDocumentedReasons(t *testing.T) {
	reasons := []DeleteReason{
		DeleteReasonUserRequested,
		DeleteReasonTTLExpired,
		DeleteReasonIdleExpired,
		DeleteReasonHardTimeoutExpired,
		DeleteReasonCreateFailedCleanup,
		DeleteReasonAdminForced,
	}
	for _, reason := range reasons {
		request := validDeleteWorkloadRequest()
		request.Reason = reason
		if err := request.Validate(); err != nil {
			t.Fatalf("reason %q: %v", reason, err)
		}
	}
	request := validDeleteWorkloadRequest()
	request.Reason = "UNKNOWN"
	if err := request.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
}

func TestNewDeleteWorkloadResponseReturnsSuccess(t *testing.T) {
	response := NewDeleteWorkloadResponse("cluster-main/ns-team-1/workload-abc")
	if response.RuntimeWorkloadID != "cluster-main/ns-team-1/workload-abc" || response.Status != "SUCCESS" {
		t.Fatalf("response = %#v", response)
	}
}

func validDeleteWorkloadRequest() DeleteWorkloadRequest {
	return DeleteWorkloadRequest{
		RequestID:  "req-delete-01",
		InstanceID: "018f3f1e-21b8-7a91-a30b-63b3400fd001",
		TeamID:     1,
		Target: RuntimeTarget{
			RuntimeType: RuntimeTypeKubernetes,
			TargetID:    "cluster-main",
		},
		RuntimeWorkloadID: "cluster-main/ns-team-1/workload-abc",
		Reason:            DeleteReasonUserRequested,
	}
}
