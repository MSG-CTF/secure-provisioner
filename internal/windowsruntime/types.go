// Package windowsruntime runs one submitted executable in a broker-approved RDP session.
package windowsruntime

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound  = errors.New("windows execution not found")
	ErrConflict  = errors.New("windows request conflicts with an existing execution")
	ErrLeaseLost = errors.New("windows execution lease lost")
)

// UnboundTargetID is stored only for direct checker jobs awaiting a Broker VM.
const UnboundTargetID = "00000000-0000-0000-0000-000000000000"

type Connection struct {
	TargetID               string `json:"resource_target_id"`
	Name                   string `json:"name"`
	Protocol               string `json:"protocol"`
	Host                   string `json:"host"`
	Port                   int    `json:"port"`
	Username               string `json:"username"`
	RDPFile                string `json:"rdp_file"`
	ExecutorCertificatePEM string `json:"executor_certificate_pem,omitempty"`
}

// VMPage is a broker snapshot, not an execution reservation.
type VMPage struct {
	Items      []Connection `json:"items"`
	NextCursor *string      `json:"next_cursor"`
}

type EventAck struct {
	TargetID       string `json:"resource_target_id"`
	ExecutionID    string `json:"execution_id"`
	ExecutionState string `json:"execution_state"`
	VMState        string `json:"vm_state"`
	Replayed       bool   `json:"replayed"`
}

type Outcome struct {
	Result          string     `json:"result"`
	ExitCode        *int64     `json:"exit_code"`
	Started         *bool      `json:"started,omitempty"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	Stdout          string     `json:"stdout"`
	Stderr          string     `json:"stderr"`
	StdoutTruncated bool       `json:"stdout_truncated"`
	StderrTruncated bool       `json:"stderr_truncated"`
	ErrorCode       string     `json:"error_code,omitempty"`
}

// CheckerJob is operator-side data. It is persisted with the execution but
// never serialized in a public Runtime response or sent to the Windows guest.
type CheckerJob struct {
	BackendID     string          `json:"backend_id,omitempty"`
	AssignmentID  string          `json:"assignment_id"`
	PayloadSHA256 string          `json:"payload_sha256"`
	BackendURL    string          `json:"backend_url"`
	JobToken      string          `json:"job_token"`
	Request       *CheckerRequest `json:"request,omitempty"`
	ResultEventID string          `json:"result_event_id,omitempty"`
	ResultBody    []byte          `json:"result_body,omitempty"`
	ResultPending bool            `json:"result_pending,omitempty"`
}

type Record struct {
	QueueState       string        `json:"-"`
	QueuePosition    *int          `json:"-"`
	ID               string        `json:"execution_id"`
	RequestID        string        `json:"request_id"`
	TargetID         string        `json:"resource_target_id"`
	Fingerprint      string        `json:"fingerprint"`
	Phase            string        `json:"phase"`
	Outcome          *Outcome      `json:"outcome,omitempty"`
	ErrorCode        string        `json:"error_code,omitempty"`
	BrokerPending    bool          `json:"broker_pending"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
	Payload          []byte        `json:"-"`
	Checker          *CheckerJob   `json:"-"`
	StartedBody      []byte        `json:"-"`
	FinishedBody     []byte        `json:"-"`
	Connection       *Connection   `json:"-"`
	StartUncertain   bool          `json:"-"`
	Owner            string        `json:"-"`
	LeaseUntil       time.Time     `json:"-"`
	NextAttempt      time.Time     `json:"-"`
	Attempt          int           `json:"-"`
	ExecutionTimeout time.Duration `json:"execution_timeout_ns"`
	ConnectTimeout   time.Duration `json:"connect_timeout_ns"`
	OutputLimit      int           `json:"output_limit_bytes"`
}

// Save must atomically persist the record and both event bodies, provided the
// expected owner still holds an unexpired lease. Clearing Owner releases it.
type Store interface {
	Submit(context.Context, Record) (Record, bool, error)
	Get(context.Context, string) (Record, error)
	GetByRequest(context.Context, string) (Record, error)
	Claim(context.Context, string, time.Duration) (*Record, error)
	BindTarget(context.Context, string, string, string) (bool, error)
	Save(context.Context, Record, string) error
	Renew(context.Context, string, string, time.Duration) error
}

type Broker interface {
	Connection(context.Context, string) (Connection, error)
	Event(context.Context, string, []byte) (EventAck, error)
}

type Job struct {
	ID             string
	Payload        []byte
	Timeout        time.Duration
	ConnectTimeout time.Duration
	OutputLimit    int
}

type Transport interface {
	Execute(context.Context, Connection, Job) Outcome
}
