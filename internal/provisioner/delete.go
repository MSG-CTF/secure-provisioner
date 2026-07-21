package provisioner

type DeleteReason string

const (
	DeleteReasonUserRequested       DeleteReason = "USER_REQUESTED"
	DeleteReasonTTLExpired          DeleteReason = "TTL_EXPIRED"
	DeleteReasonIdleExpired         DeleteReason = "IDLE_EXPIRED"
	DeleteReasonHardTimeoutExpired  DeleteReason = "HARD_TIMEOUT_EXPIRED"
	DeleteReasonCreateFailedCleanup DeleteReason = "CREATE_FAILED_CLEANUP"
	DeleteReasonAdminForced         DeleteReason = "ADMIN_FORCED"
)

type DeleteWorkloadCommand struct {
	RequestID         string
	InstanceID        string
	TeamID            int64
	RuntimeType       RuntimeType
	TargetID          string
	RuntimeWorkloadID string
	Reason            DeleteReason
}
