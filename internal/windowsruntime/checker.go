package windowsruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrCheckerUnavailable = errors.New("Windows checker backend unavailable")
var ErrCheckerPayloadDenied = errors.New("Windows checker payload denied")

var checkerSHA40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var checkerSHA64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CheckerRequest is the metadata-only Backend v1 checker submission.
type CheckerRequest struct {
	RequestVersion   int    `json:"request_version"`
	SubmissionID     string `json:"submission_id"`
	AssignmentID     string `json:"assignment_id"`
	TeamID           string `json:"team_id"`
	ChallengeID      string `json:"challenge_id"`
	ReleaseID        string `json:"release_id"`
	SelectionMode    string `json:"selection_mode,omitempty"`
	VMID             string `json:"vm_id"`
	ReadinessCheckID string `json:"readiness_check_id"`
	PayloadSHA256    string `json:"payload_sha256"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	MaxOutputBytes   int    `json:"max_output_bytes"`
	CheckerCommitSHA string `json:"checker_commit_sha"`
	VMTemplateSHA256 string `json:"vm_template_sha256"`
	DriverSHA256     string `json:"driver_sha256"`
	ConfigVersion    string `json:"config_version"`
}

type CheckerConfig struct {
	BackendURL       string
	Backends         map[string]string
	Targets          map[string]bool
	CheckerCommitSHA string
	VMTemplateSHA256 string
	DriverSHA256     string
	ConfigVersion    string
}

type Checker struct {
	service *Service
	cfg     CheckerConfig
}

func NewChecker(service *Service, cfg CheckerConfig, client *http.Client) (*Checker, error) {
	if service == nil || client == nil || (cfg.BackendURL == "") == (len(cfg.Backends) == 0) || len(cfg.Targets) == 0 && !service.poolAnyTargets || !checkerSHA40.MatchString(cfg.CheckerCommitSHA) || !checkerSHA64.MatchString(cfg.VMTemplateSHA256) || !checkerSHA64.MatchString(cfg.DriverSHA256) || cfg.ConfigVersion == "" || len(cfg.ConfigVersion) > 200 {
		return nil, errors.New("invalid Windows checker configuration")
	}
	if cfg.BackendURL != "" {
		cfg.Backends = map[string]string{"default": cfg.BackendURL}
	}
	for id, origin := range cfg.Backends {
		if id != "default" && id != "internal" && id != "external" || !validCheckerOrigin(origin) {
			return nil, errors.New("invalid Windows checker backend")
		}
	}
	for target, allowed := range cfg.Targets {
		if !ValidID(target) || !allowed {
			return nil, errors.New("invalid Windows checker target")
		}
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if clone.Timeout == 0 || clone.Timeout > 10*time.Second {
		clone.Timeout = 10 * time.Second
	}
	service.checkerHTTPClient = &clone
	return &Checker{service: service, cfg: cfg}, nil
}

func validCheckerOrigin(origin string) bool {
	u, err := url.Parse(origin)
	return err == nil && !strings.ContainsAny(origin, "?#") && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.Opaque == ""
}

func checkerRequestID(backendID, submissionID string) string {
	if backendID == "" || backendID == "default" {
		return submissionID
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("windows-checker:"+backendID+":"+submissionID)).String()
}

func sameCheckerBackend(a, b string) bool {
	if a == "" {
		a = "default"
	}
	if b == "" {
		b = "default"
	}
	return a == b
}

func (c *Checker) Submit(ctx context.Context, request CheckerRequest, token string) (Record, bool, error) {
	return c.SubmitForBackend(ctx, "default", request, token)
}

func (c *Checker) SubmitForBackend(ctx context.Context, backendID string, request CheckerRequest, token string) (Record, bool, error) {
	backendURL, ok := c.cfg.Backends[backendID]
	if !ok {
		return Record{}, false, ErrInvalidSubmission
	}
	if request.RequestVersion != 1 || !ValidID(request.SubmissionID) || !ValidID(request.AssignmentID) || !ValidID(request.TeamID) || !ValidID(request.ChallengeID) || !ValidID(request.ReleaseID) || request.TimeoutSeconds < 10 || request.TimeoutSeconds > 180 || request.MaxOutputBytes != c.service.cfg.OutputLimit || len(request.PayloadSHA256) != 64 || len(token) < 20 || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n\x00") || request.CheckerCommitSHA != c.cfg.CheckerCommitSHA || request.VMTemplateSHA256 != c.cfg.VMTemplateSHA256 || request.DriverSHA256 != c.cfg.DriverSHA256 || request.ConfigVersion != c.cfg.ConfigVersion {
		return Record{}, false, ErrInvalidSubmission
	}
	targetID := request.VMID
	switch request.SelectionMode {
	case "":
		if !ValidID(targetID) || !c.cfg.Targets[targetID] || request.ReadinessCheckID == "" || len(request.ReadinessCheckID) > 200 || strings.ContainsAny(request.ReadinessCheckID, "\r\n\x00") {
			return Record{}, false, ErrInvalidSubmission
		}
	case "broker_pool":
		if targetID != "" || request.ReadinessCheckID != "" || !c.service.poolAnyTargets && len(c.service.poolTargets) == 0 {
			return Record{}, false, ErrInvalidSubmission
		}
		targetID = UnboundTargetID
	default:
		return Record{}, false, ErrInvalidSubmission
	}
	if _, err := hex.DecodeString(request.PayloadSHA256); err != nil || strings.ToLower(request.PayloadSHA256) != request.PayloadSHA256 {
		return Record{}, false, ErrInvalidSubmission
	}
	return c.service.QueueChecker(ctx, checkerRequestID(backendID, request.SubmissionID), targetID, CheckerJob{BackendID: backendID, AssignmentID: request.AssignmentID, PayloadSHA256: request.PayloadSHA256, BackendURL: backendURL, JobToken: token, Request: &request}, time.Duration(request.TimeoutSeconds)*time.Second)
}

func (s *Service) fetchCheckerPayload(ctx context.Context, record Record) ([]byte, error) {
	if record.Checker == nil || s.checkerHTTPClient == nil {
		return nil, ErrCheckerUnavailable
	}
	if record.Checker.Request == nil {
		return nil, ErrCheckerUnavailable
	}
	path := record.Checker.BackendURL + "/internal/v1/checker-submissions/" + record.Checker.Request.SubmissionID + "/payload"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, ErrCheckerUnavailable
	}
	httpRequest.Header.Set("Authorization", "Bearer "+record.Checker.JobToken)
	response, err := s.checkerHTTPClient.Do(httpRequest)
	if err != nil {
		return nil, ErrCheckerUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, ErrCheckerAuthRejected
	}
	if response.StatusCode == http.StatusNotFound {
		return nil, ErrCheckerPayloadDenied
	}
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || media != "application/octet-stream" {
		return nil, ErrCheckerUnavailable
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, int64(s.MaxPayload())+1))
	if err != nil || len(payload) > s.MaxPayload() {
		return nil, ErrCheckerUnavailable
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != record.Fingerprint || len(payload) < 2 || payload[0] != 'M' || payload[1] != 'Z' {
		return nil, ErrInvalidSubmission
	}
	return payload, nil
}

func (c *Checker) Get(ctx context.Context, submissionID string) (Record, error) {
	return c.GetForBackend(ctx, "default", submissionID)
}

func (c *Checker) GetForBackend(ctx context.Context, backendID, submissionID string) (Record, error) {
	if _, ok := c.cfg.Backends[backendID]; !ok {
		return Record{}, ErrNotFound
	}
	record, err := c.service.GetByRequest(ctx, checkerRequestID(backendID, submissionID))
	if err != nil {
		return Record{}, err
	}
	if record.Checker == nil || !sameCheckerBackend(record.Checker.BackendID, backendID) || record.Checker.Request == nil || record.Checker.Request.SubmissionID != submissionID {
		return Record{}, ErrNotFound
	}
	return record, nil
}
