// Package imageprep owns advisory cache observations and durable preparation history.
// Neither is an authorization to create a workload.
package imageprep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/validation"
)

var (
	ErrInvalid    = errors.New("invalid image preparation request")
	ErrConflict   = errors.New("image preparation request conflict")
	ErrPolicy     = errors.New("image preparation policy rejected")
	ErrNotFound   = errors.New("image preparation not found")
	ErrLeaseLost  = errors.New("image preparation lease lost")
	imagePattern  = regexp.MustCompile(`^ghcr[.]io/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$`)
	DigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type Container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Ports []int  `json:"ports"`
}
type Request struct {
	RequestID        string      `json:"request_id"`
	ReleaseID        string      `json:"release_id,omitempty"`
	Architecture     string      `json:"architecture"`
	IsolationProfile string      `json:"isolation_profile"`
	Containers       []Container `json:"containers"`
	TargetIDs        []string    `json:"target_ids"`
}
type Retry struct {
	RequestID string   `json:"request_id"`
	NodeUIDs  []string `json:"node_uids,omitempty"`
}
type Query struct {
	Architecture string   `json:"architecture"`
	Images       []string `json:"images"`
	TargetIDs    []string `json:"target_ids"`
}
type Image struct {
	Image          string     `json:"image"`
	ResolvedDigest string     `json:"resolved_manifest_digest,omitempty"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	ObservedAt     *time.Time `json:"observed_at"`
	ErrorCode      string     `json:"error_code,omitempty"`
}
type NodeResult struct {
	TargetID     string     `json:"target_id"`
	UID          string     `json:"node_uid"`
	Name         string     `json:"node_name"`
	Architecture string     `json:"architecture"`
	Status       string     `json:"status"`
	ObservedAt   *time.Time `json:"observed_at"`
	Images       []Image    `json:"images"`
}
type Operation struct {
	ID           string       `json:"operation_id"`
	ParentID     string       `json:"parent_operation_id,omitempty"`
	RequestID    string       `json:"request_id"`
	ReleaseID    string       `json:"release_id,omitempty"`
	ImageSetID   string       `json:"image_set_id"`
	Architecture string       `json:"architecture"`
	Status       string       `json:"status"`
	ErrorCode    string       `json:"error_code,omitempty"`
	Nodes        []NodeResult `json:"nodes"`
}

// Record is persisted privately; only Operation is exposed to callers.
type Record struct {
	Operation   Operation
	Request     Request
	Scope       string
	Endpoint    string
	Fingerprint string
	Frozen      []Node
	Next        time.Time
	Lease       string
	LeaseUntil  time.Time
}
type Node struct {
	TargetID     string
	UID          string
	Name         string
	BootID       string
	Architecture string
	MachineID    string
}
type Evidence struct {
	MachineID      string `json:"machine_id"`
	NodeUID        string `json:"node_uid"`
	BootID         string `json:"boot_id"`
	OS             string `json:"os"`
	Architecture   string `json:"architecture"`
	Image          string `json:"image"`
	ResolvedDigest string `json:"resolved_manifest_digest"`
	Complete       bool   `json:"complete"`
}
type NodeObservation struct {
	Node   Node
	Images map[string]Evidence
}
type Observation struct {
	PolicyRevision string
	TargetID       string
	ImageSetID     string
	Architecture   string
	Images         []string
	ObservedAt     time.Time
	ValidUntil     time.Time
	Nodes          []NodeObservation
	Complete       bool
}
type TargetReadiness struct {
	TargetID          string     `json:"target_id"`
	Ready             bool       `json:"ready"`
	ReadyNodeCount    int        `json:"ready_node_count"`
	EligibleNodeCount int        `json:"eligible_node_count"`
	ObservedAt        *time.Time `json:"observed_at"`
	ValidUntil        *time.Time `json:"valid_until"`
}
type Readiness struct {
	ImageSetID   string            `json:"image_set_id"`
	Architecture string            `json:"architecture"`
	Targets      []TargetReadiness `json:"targets"`
}
type Failure struct{ Code string }

func (f Failure) Error() string { return f.Code }
func ErrorCode(err error) string {
	var f Failure
	if errors.As(err, &f) && slices.Contains([]string{"NETWORK_TIMEOUT", "REGISTRY_UNAVAILABLE", "RATE_LIMITED", "REGISTRY_UNAUTHORIZED", "MANIFEST_NOT_FOUND", "PLATFORM_MISMATCH", "RESOURCE_EXHAUSTED", "NODE_IDENTITY_MISMATCH", "AGENT_UNAVAILABLE", "CONTENT_INCOMPLETE", "POLICY_REJECTED"}, f.Code) {
		return f.Code
	}
	return "AGENT_UNAVAILABLE"
}
func transient(code string) bool {
	return code == "NETWORK_TIMEOUT" || code == "REGISTRY_UNAVAILABLE" || code == "RATE_LIMITED"
}

type Store interface {
	Find(context.Context, string, string, string) (Record, bool, error)
	Insert(context.Context, Record) (Record, error)
	Get(context.Context, string) (Record, error)
	Claim(context.Context, time.Time, time.Duration) (Record, bool, error)
	Save(context.Context, Record, bool) error
	Watch(context.Context) ([]Query, error)
	PutObservation(context.Context, Observation) error
	Observation(context.Context, string, string) (Observation, bool, error)
	LockNode(context.Context, string, string, time.Time, time.Duration) (bool, error)
	UnlockNode(context.Context, string, string) error
}
type Inventory interface {
	Known(string) bool
	Enabled(string, string) bool
	Nodes(context.Context, string, string) ([]Node, error)
}
type Policy interface {
	Revision() string
	Validate(Request) error
	Approved(string) bool
}
type Runner interface {
	Run(context.Context, Node, string, bool) (Evidence, error)
}
type Config struct {
	TTL             time.Duration
	ObserveInterval time.Duration
	MaxAttempts     int
	Concurrency     int
}

func validArchitecture(a string) bool { return a == "AMD64" || a == "ARM64" }
func validID(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\r\n\x00")
}
func ValidImage(s string) bool {
	if len(s) > 512 || !imagePattern.MatchString(s) {
		return false
	}
	repo, _, _ := strings.Cut(s, "@")
	for _, part := range strings.Split(strings.TrimPrefix(repo, "ghcr.io/"), "/") {
		if part == "" || part == "." || part == ".." || strings.Contains(part, ":") {
			return false
		}
	}
	return true
}
func uniqueStrings(s []string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	seen := map[string]bool{}
	for _, v := range s {
		if !validID(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func (r *Request) Normalize() error {
	if !validID(r.RequestID) || !validArchitecture(r.Architecture) || (r.IsolationProfile != "WEB" && r.IsolationProfile != "PWN") || !uniqueStrings(r.TargetIDs, 1, 50) || len(r.Containers) < 1 || len(r.Containers) > 32 {
		return ErrInvalid
	}
	if r.ReleaseID != "" {
		u, e := uuid.Parse(r.ReleaseID)
		if e != nil || u.String() != r.ReleaseID || u == uuid.Nil {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for i := range r.Containers {
		c := &r.Containers[i]
		if len(validation.IsDNS1123Label(c.Name)) != 0 || seen[c.Name] || !ValidImage(c.Image) || len(c.Ports) < 1 || len(c.Ports) > 32 {
			return ErrInvalid
		}
		seen[c.Name] = true
		slices.Sort(c.Ports)
		for n, p := range c.Ports {
			if p < 1 || p > 65535 || (n > 0 && c.Ports[n-1] == p) {
				return ErrInvalid
			}
		}
	}
	slices.SortFunc(r.Containers, func(a, b Container) int { return strings.Compare(a.Name, b.Name) })
	slices.Sort(r.TargetIDs)
	return nil
}
func (r Request) Images() []string {
	images := []string{}
	for _, c := range r.Containers {
		if !slices.Contains(images, c.Image) {
			images = append(images, c.Image)
		}
	}
	slices.Sort(images)
	return images
}
func (q Query) Validate() error {
	if !validArchitecture(q.Architecture) || !uniqueStrings(q.TargetIDs, 1, 50) || len(q.Images) < 1 || len(q.Images) > 32 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, ref := range q.Images {
		if !ValidImage(ref) || seen[ref] {
			return ErrInvalid
		}
		seen[ref] = true
	}
	return nil
}
func ImageSetID(arch string, images []string) string {
	images = slices.Clone(images)
	slices.Sort(images)
	images = slices.Compact(images)
	b, _ := json.Marshal(struct {
		Version      int      `json:"schema_version"`
		Architecture string   `json:"architecture"`
		Images       []string `json:"images"`
	}{1, arch, images})
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func fingerprint(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
