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
	OperationSucceeded OperationStatus = "SUCCEEDED"
	OperationFailed    OperationStatus = "FAILED"
)

type CreateRequest struct {
	RequestID     string    `json:"requestId"`
	InstanceID    string    `json:"instanceId"`
	TeamID        string    `json:"teamId"`
	ChallengeID   string    `json:"challengeId"`
	ClusterID     string    `json:"clusterId"`
	ReservationID string    `json:"reservationId"`
	CreatedBy     string    `json:"createdBy"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

type DeleteRequest struct {
	RequestID string `json:"requestId"`
}

type Instance struct {
	InstanceID      string
	TeamID          string
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
	OperationID   string          `json:"operationId"`
	RequestID     string          `json:"requestId"`
	InstanceID    string          `json:"instanceId"`
	OperationType OperationType   `json:"operationType"`
	Status        OperationStatus `json:"status"`
	AttemptCount  int             `json:"attemptCount"`
	NextRetryAt   *time.Time      `json:"nextRetryAt,omitempty"`
	LastError     string          `json:"lastError,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
	UpdatedAt     time.Time       `json:"updatedAt"`
}

type InstanceView struct {
	InstanceID  string    `json:"instanceId"`
	TeamID      string    `json:"teamId"`
	ChallengeID string    `json:"challengeId"`
	Endpoint    string    `json:"endpoint,omitempty"`
	Phase       Phase     `json:"phase"`
	ExpiresAt   time.Time `json:"expiresAt"`
	LastError   string    `json:"lastError,omitempty"`
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
	OperationID string `json:"operationId"`
	InstanceID  string `json:"instanceId"`
	Phase       Phase  `json:"phase"`
	Duplicate   bool   `json:"duplicate"`
}

type Challenge struct {
	ChallengeID     string `json:"challengeId"`
	Image           string `json:"image"`
	ContainerPort   int    `json:"containerPort"`
	SecurityProfile string `json:"securityProfile"`
	ResourceProfile string `json:"resourceProfile"`
	NetworkProfile  string `json:"networkProfile"`
	RuntimeClass    string `json:"runtimeClass"`
}

type Reservation struct {
	ReservationID       string `json:"reservationId"`
	ClusterID           string `json:"clusterId"`
	Valid               bool   `json:"valid"`
	CPUMillicores       int    `json:"cpuMillicores"`
	MemoryMiB           int    `json:"memoryMiB"`
	EphemeralStorageMiB int    `json:"ephemeralStorageMiB"`
}

type RuntimeResources struct {
	InstanceID               string `json:"instanceId"`
	Namespace                string `json:"namespace"`
	Image                    string `json:"image"`
	ContainerPort            int    `json:"containerPort"`
	RuntimeClass             string `json:"runtimeClass"`
	ResourceQuotaApplied     bool   `json:"resourceQuotaApplied"`
	LimitRangeApplied        bool   `json:"limitRangeApplied"`
	DefaultDenyNetworkPolicy bool   `json:"defaultDenyNetworkPolicy"`
	DNSOnlyEgress            bool   `json:"dnsOnlyEgress"`
	ServiceAccountAutomount  bool   `json:"serviceAccountAutomount"`
	AllowPrivilegeEscalation bool   `json:"allowPrivilegeEscalation"`
	Privileged               bool   `json:"privileged"`
	HostNetwork              bool   `json:"hostNetwork"`
	HostPID                  bool   `json:"hostPID"`
	HostIPC                  bool   `json:"hostIPC"`
	HostPathAllowed          bool   `json:"hostPathAllowed"`
	DropAllCapabilities      bool   `json:"dropAllCapabilities"`
	SeccompProfile           string `json:"seccompProfile"`
	Endpoint                 string `json:"endpoint"`
}
