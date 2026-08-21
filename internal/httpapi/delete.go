package httpapi

import (
	"fmt"
	"strings"

	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type DeleteReason string

const (
	DeleteReasonUserRequested       DeleteReason = "USER_REQUESTED"
	DeleteReasonTTLExpired          DeleteReason = "TTL_EXPIRED"
	DeleteReasonIdleExpired         DeleteReason = "IDLE_EXPIRED"
	DeleteReasonHardTimeoutExpired  DeleteReason = "HARD_TIMEOUT_EXPIRED"
	DeleteReasonCreateFailedCleanup DeleteReason = "CREATE_FAILED_CLEANUP"
	DeleteReasonAdminForced         DeleteReason = "ADMIN_FORCED"
)

type DeleteWorkloadRequest struct {
	RequestID         string             `json:"request_id"`
	InstanceID        string             `json:"instance_id"`
	TeamID            provisioner.TeamID `json:"team_id"`
	Target            RuntimeTarget      `json:"target"`
	RuntimeWorkloadID string             `json:"runtime_workload_id"`
	Reason            DeleteReason       `json:"delete_reason"`
}

type DeleteWorkloadResponse struct {
	RuntimeWorkloadID string `json:"runtime_workload_id"`
	Status            string `json:"status"`
}

func (request DeleteWorkloadRequest) Validate() error {
	if strings.TrimSpace(request.RequestID) == "" {
		return fmt.Errorf("request_id is required")
	}
	if !isUUID(request.InstanceID) {
		return fmt.Errorf("instance_id must be a UUID")
	}
	if !request.TeamID.Valid() {
		return fmt.Errorf("team_id must be a canonical UUID")
	}
	if request.Target.RuntimeType != RuntimeTypeKubernetes {
		return fmt.Errorf("runtime_type must be %s", RuntimeTypeKubernetes)
	}
	if strings.TrimSpace(request.Target.TargetID) == "" {
		return fmt.Errorf("target_id is required")
	}
	if strings.TrimSpace(request.RuntimeWorkloadID) == "" {
		return fmt.Errorf("runtime_workload_id is required")
	}
	if !request.Reason.isValid() {
		return fmt.Errorf("delete_reason is invalid")
	}
	return nil
}

func (request DeleteWorkloadRequest) ToCommand() provisioner.DeleteWorkloadCommand {
	return provisioner.DeleteWorkloadCommand{
		RequestID:         request.RequestID,
		InstanceID:        request.InstanceID,
		TeamID:            request.TeamID,
		RuntimeType:       provisioner.RuntimeType(request.Target.RuntimeType),
		TargetID:          request.Target.TargetID,
		RuntimeWorkloadID: request.RuntimeWorkloadID,
		Reason:            provisioner.DeleteReason(request.Reason),
	}
}

func NewDeleteWorkloadResponse(runtimeWorkloadID string) DeleteWorkloadResponse {
	return DeleteWorkloadResponse{
		RuntimeWorkloadID: runtimeWorkloadID,
		Status:            "SUCCESS",
	}
}

func (reason DeleteReason) isValid() bool {
	switch reason {
	case DeleteReasonUserRequested,
		DeleteReasonTTLExpired,
		DeleteReasonIdleExpired,
		DeleteReasonHardTimeoutExpired,
		DeleteReasonCreateFailedCleanup,
		DeleteReasonAdminForced:
		return true
	default:
		return false
	}
}
