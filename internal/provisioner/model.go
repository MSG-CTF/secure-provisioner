package provisioner

import "time"

type Phase string

const (
	PhaseRequested    Phase = "REQUESTED"
	PhaseProvisioning Phase = "PROVISIONING"
	PhaseVerifying    Phase = "VERIFYING"
	PhaseReady        Phase = "READY"
	PhaseFailed       Phase = "FAILED"
	PhaseTerminating  Phase = "TERMINATING"
	PhaseTerminated   Phase = "TERMINATED"
	PhaseDeleteFailed Phase = "DELETE_FAILED"
)

type DesiredState string

const (
	DesiredRunning    DesiredState = "RUNNING"
	DesiredTerminated DesiredState = "TERMINATED"
)

type OperationType string

const (
	OperationCreate OperationType = "CREATE"
	OperationDelete OperationType = "DELETE"
)

type OperationStatus string

const (
	OperationPending   OperationStatus = "PENDING"
	OperationRunning   OperationStatus = "RUNNING"
	OperationRetryWait OperationStatus = "RETRY_WAIT"
	OperationSucceeded OperationStatus = "SUCCEEDED"
	OperationFailed    OperationStatus = "FAILED"
)

type CreateRequest struct {
	RequestID     string    `json:"request_id"`
	InstanceID    string    `json:"instance_id"`
	TeamID        int64     `json:"team_id"`
	ChallengeID   string    `json:"challenge_id"`
	ClusterID     string    `json:"cluster_id"`
	ReservationID string    `json:"reservation_id"`
	CreatedBy     string    `json:"created_by"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type DeleteRequest struct {
	RequestID string `json:"request_id"`
}

type Instance struct {
	InstanceID      string
	TeamID          int64
	ChallengeID     string
	ClusterID       string
	ReservationID   string
	Namespace       string
	SecurityProfile string
	ResourceProfile string
	NetworkProfile  string
	Endpoint        string
	Phase           Phase
	DesiredState    DesiredState
	Generation      int
	CreatedBy       string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	UpdatedAt       time.Time
	LastError       string
}

type Operation struct {
	OperationID   string          `json:"operation_id"`
	RequestID     string          `json:"request_id"`
	InstanceID    string          `json:"instance_id"`
	OperationType OperationType   `json:"operation_type"`
	Status        OperationStatus `json:"status"`
	Priority      int             `json:"priority"`
	AttemptCount  int             `json:"attempt_count"`
	MaxAttempts   int             `json:"max_attempts"`
	NextRetryAt   *time.Time      `json:"next_retry_at,omitempty"`
	LeaseOwner    string          `json:"lease_owner,omitempty"`
	LeaseUntil    *time.Time      `json:"lease_until,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

type InstanceView struct {
	InstanceID  string    `json:"instance_id"`
	TeamID      int64     `json:"team_id"`
	ChallengeID string    `json:"challenge_id"`
	Endpoint    string    `json:"endpoint,omitempty"`
	Phase       Phase     `json:"phase"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastError   string    `json:"last_error,omitempty"`
}

func newInstanceView(instance Instance) InstanceView {
	return InstanceView{
		InstanceID:  instance.InstanceID,
		TeamID:      instance.TeamID,
		ChallengeID: instance.ChallengeID,
		Endpoint:    instance.Endpoint,
		Phase:       instance.Phase,
		ExpiresAt:   instance.ExpiresAt,
		LastError:   instance.LastError,
	}
}

type AcceptedOperation struct {
	OperationID string `json:"operation_id"`
	InstanceID  string `json:"instance_id"`
	Phase       Phase  `json:"phase"`
	Duplicate   bool   `json:"duplicate"`
}

type Challenge struct {
	ChallengeID     string   `json:"challenge_id"`
	Image           string   `json:"image"`
	ContainerPort   int      `json:"container_port"`
	Command         []string `json:"command,omitempty"`
	SecurityProfile string   `json:"security_profile"`
	ResourceProfile string   `json:"resource_profile"`
	NetworkProfile  string   `json:"network_profile"`
	RuntimeClass    string   `json:"runtime_class"`
}

type Reservation struct {
	ReservationID       string `json:"reservation_id"`
	ClusterID           string `json:"cluster_id"`
	Valid               bool   `json:"valid"`
	CPUMillicores       int    `json:"cpu_millicores"`
	MemoryMiB           int    `json:"memory_mib"`
	EphemeralStorageMiB int    `json:"ephemeral_storage_mib"`
}

type RuntimeResources struct {
	InstanceID               string `json:"instance_id"`
	Namespace                string `json:"namespace"`
	Image                    string `json:"image"`
	ContainerPort            int    `json:"container_port"`
	RuntimeClass             string `json:"runtime_class"`
	ResourceQuotaApplied     bool   `json:"resource_quota_applied"`
	LimitRangeApplied        bool   `json:"limit_range_applied"`
	DefaultDenyNetworkPolicy bool   `json:"default_deny_network_policy"`
	DNSOnlyEgress            bool   `json:"dns_only_egress"`
	ServiceAccountAutomount  bool   `json:"service_account_automount"`
	AllowPrivilegeEscalation bool   `json:"allow_privilege_escalation"`
	Privileged               bool   `json:"privileged"`
	HostNetwork              bool   `json:"host_network"`
	HostPID                  bool   `json:"host_pid"`
	HostIPC                  bool   `json:"host_ipc"`
	HostPathAllowed          bool   `json:"host_path_allowed"`
	DropAllCapabilities      bool   `json:"drop_all_capabilities"`
	SeccompProfile           string `json:"seccomp_profile"`
	Endpoint                 string `json:"endpoint"`
	NodePort                 int32  `json:"node_port,omitempty"`
}
