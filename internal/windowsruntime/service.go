package windowsruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrInvalidSubmission = errors.New("invalid Windows executable submission")

type ServiceConfig struct {
	MaxPayload       int
	OutputLimit      int
	ExecutionTimeout time.Duration
	ConnectTimeout   time.Duration
	LeaseDuration    time.Duration
	RetryInterval    time.Duration
	PollInterval     time.Duration
	Concurrency      int
}

func DefaultServiceConfig() ServiceConfig {
	return ServiceConfig{MaxPayload: 10 << 20, OutputLimit: 64 << 10, ExecutionTimeout: 180 * time.Second, ConnectTimeout: 60 * time.Second, LeaseDuration: 45 * time.Second, RetryInterval: 5 * time.Second, PollInterval: 200 * time.Millisecond, Concurrency: 2}
}

type Service struct {
	cfg                  ServiceConfig
	store                Store
	broker               Broker
	transport            Transport
	checkerHTTPClient    *http.Client
	checkerServiceTokens map[string]string
	poolTargets          map[string]bool
	poolAnyTargets       bool
}

func NewService(cfg ServiceConfig, store Store, broker Broker, transport Transport) (*Service, error) {
	if store == nil || broker == nil || transport == nil || cfg.MaxPayload < 2 || cfg.MaxPayload > 10<<20 || cfg.OutputLimit < 1 || cfg.OutputLimit > 1<<20 || cfg.ExecutionTimeout < time.Second || cfg.ExecutionTimeout > time.Hour || cfg.ConnectTimeout < time.Second || cfg.ConnectTimeout > 5*time.Minute || cfg.LeaseDuration < time.Second || cfg.PollInterval <= 0 || cfg.RetryInterval <= 0 || cfg.Concurrency < 1 || cfg.Concurrency > 16 {
		return nil, errors.New("invalid Windows runtime configuration")
	}
	return &Service{cfg: cfg, store: store, broker: broker, transport: transport}, nil
}
func (s *Service) MaxPayload() int { return s.cfg.MaxPayload }
func (s *Service) SetPoolTargets(targets map[string]ExecutorCredential) {
	s.poolAnyTargets = false
	s.poolTargets = make(map[string]bool, len(targets))
	for id := range targets {
		s.poolTargets[id] = true
	}
}
func (s *Service) SetPoolAnyTargets() {
	s.poolTargets = nil
	s.poolAnyTargets = true
}
func (s *Service) SetCheckerServiceTokens(tokens map[string]string) {
	s.checkerServiceTokens = make(map[string]string, len(tokens))
	for id, token := range tokens {
		s.checkerServiceTokens[id] = token
	}
}
func (s *Service) Submit(ctx context.Context, requestID, targetID string, payload []byte) (Record, bool, error) {
	return s.submit(ctx, requestID, targetID, payload, nil, s.cfg.ExecutionTimeout)
}

func (s *Service) validCheckerMetadata(requestID, targetID string, checker CheckerJob, timeout time.Duration) bool {
	request := checker.Request
	return validCheckerOrigin(checker.BackendURL) && ValidID(requestID) && ValidID(targetID) && ValidID(checker.AssignmentID) && checkerSHA64.MatchString(checker.PayloadSHA256) && len(checker.JobToken) >= 20 && len(checker.JobToken) <= 4096 && !strings.ContainsAny(checker.JobToken, " \t\r\n\x00") && timeout >= 10*time.Second && timeout <= s.cfg.ExecutionTimeout && request != nil && ValidID(request.SubmissionID) && checkerRequestID(checker.BackendID, request.SubmissionID) == requestID && request.AssignmentID == checker.AssignmentID && (request.SelectionMode == "broker_pool" && targetID == UnboundTargetID && request.VMID == "" || request.SelectionMode == "" && request.VMID == targetID) && request.PayloadSHA256 == checker.PayloadSHA256 && time.Duration(request.TimeoutSeconds)*time.Second == timeout && request.MaxOutputBytes == s.cfg.OutputLimit
}

func checkerReplayMatches(record Record, checker *CheckerJob, timeout time.Duration) bool {
	return (record.Checker == nil) == (checker == nil) && (checker == nil || sameCheckerBackend(record.Checker.BackendID, checker.BackendID) && record.Checker.AssignmentID == checker.AssignmentID && record.Checker.PayloadSHA256 == checker.PayloadSHA256 && record.Checker.BackendURL == checker.BackendURL && record.Checker.Request != nil && *record.Checker.Request == *checker.Request && record.ExecutionTimeout == timeout)
}

// QueueChecker acknowledges a Backend job before any network fetch. A lost
// submission response can therefore always be reconciled by GET.
func (s *Service) QueueChecker(ctx context.Context, requestID, targetID string, checker CheckerJob, timeout time.Duration) (Record, bool, error) {
	if !s.validCheckerMetadata(requestID, targetID, checker, timeout) {
		return Record{}, false, ErrInvalidSubmission
	}
	now := time.Now().UTC()
	record, created, err := s.store.Submit(ctx, Record{ID: uuid.NewString(), RequestID: requestID, TargetID: targetID, Fingerprint: checker.PayloadSHA256, Checker: &checker, Phase: "FETCH_PENDING", CreatedAt: now, UpdatedAt: now, ExecutionTimeout: timeout, ConnectTimeout: s.cfg.ConnectTimeout, OutputLimit: s.cfg.OutputLimit})
	if err != nil {
		return Record{}, false, err
	}
	if !checkerReplayMatches(record, &checker, timeout) {
		return Record{}, false, ErrConflict
	}
	return record, created, nil
}

func (s *Service) submit(ctx context.Context, requestID, targetID string, payload []byte, checker *CheckerJob, timeout time.Duration) (Record, bool, error) {
	if !ValidID(requestID) || !ValidID(targetID) || len(payload) < 2 || len(payload) > s.cfg.MaxPayload || payload[0] != 'M' || payload[1] != 'Z' {
		return Record{}, false, ErrInvalidSubmission
	}
	digest := sha256.Sum256(payload)
	fingerprint := hex.EncodeToString(digest[:])
	now := time.Now().UTC()
	record, created, err := s.store.Submit(ctx, Record{ID: uuid.NewString(), RequestID: requestID, TargetID: targetID, Fingerprint: fingerprint, Payload: payload, Checker: checker, Phase: "QUEUED", CreatedAt: now, UpdatedAt: now, ExecutionTimeout: timeout, ConnectTimeout: s.cfg.ConnectTimeout, OutputLimit: s.cfg.OutputLimit})
	if err != nil {
		return Record{}, false, err
	}
	if !checkerReplayMatches(record, checker, timeout) {
		return Record{}, false, ErrConflict
	}
	return record, created, nil
}
func (s *Service) Get(ctx context.Context, id string) (Record, error) {
	if !ValidID(id) {
		return Record{}, ErrNotFound
	}
	return s.store.Get(ctx, id)
}

func (s *Service) GetByRequest(ctx context.Context, requestID string) (Record, error) {
	if !ValidID(requestID) {
		return Record{}, ErrNotFound
	}
	return s.store.GetByRequest(ctx, requestID)
}

// Run never assigns a second execution ID after an ambiguous start. HTTPS
// recovery replays only the executor's idempotent PUT for the same ID.
func (s *Service) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	if _, ok := s.store.(recoveryDeliveryStore); ok && s.checkerHTTPClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				_ = s.ProcessRecoveryOne(ctx)
				timer := time.NewTimer(s.cfg.PollInterval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	}
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				_ = s.ProcessOne(ctx)
				timer := time.NewTimer(s.cfg.PollInterval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	}
	<-ctx.Done()
	wg.Wait()
	return nil
}

func (s *Service) ProcessOne(ctx context.Context) error {
	owner := uuid.NewString()
	claimStarted := time.Now()
	r, err := s.store.Claim(ctx, owner, s.cfg.LeaseDuration)
	if err != nil || r == nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	renewCtx, stopRenew := context.WithCancel(context.WithoutCancel(ctx))
	defer stopRenew()
	renewed := make(chan struct{})
	guarded := make(chan struct{})
	leaseUpdates := make(chan time.Time, 1)
	// Start from request time rather than response receipt: a delayed DB reply
	// must not extend local ownership past the server's lease. The margin also
	// leaves time to stop RDP and checkpoint while the last lease is still valid.
	leaseDeadline := claimStarted.Add(s.cfg.LeaseDuration * 9 / 10)
	defer func() { stopRenew(); <-renewed; <-guarded }()
	go func(initialDeadline time.Time) {
		defer close(guarded)
		timer := time.NewTimer(time.Until(initialDeadline))
		defer timer.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-timer.C:
				cancel()
				stopRenew()
				return
			case deadline := <-leaseUpdates:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(time.Until(deadline))
			}
		}
	}(leaseDeadline)
	go func(id string) {
		defer close(renewed)
		ticker := time.NewTicker(s.cfg.LeaseDuration / 3)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-ticker.C:
				renewStarted := time.Now()
				bound := renewStarted.Add(s.cfg.LeaseDuration / 3)
				if leaseDeadline.Before(bound) {
					bound = leaseDeadline
				}
				callCtx, stopCall := context.WithDeadline(renewCtx, bound)
				err := s.store.Renew(callCtx, id, owner, s.cfg.LeaseDuration)
				stopCall()
				if err != nil || time.Now().After(leaseDeadline) {
					cancel()
					return
				}
				leaseDeadline = renewStarted.Add(s.cfg.LeaseDuration * 9 / 10)
				select {
				case leaseUpdates <- leaseDeadline:
				case <-renewCtx.Done():
					return
				}
			}
		}
	}(r.ID)
	// Shutdown cancels the transport but must still checkpoint a result and outbox while the
	// lease is alive. Bounded database/network calls cannot hold shutdown forever.
	saveCtx, stopSave := context.WithCancel(context.WithoutCancel(ctx))
	defer stopSave()
	save := func() error {
		r.UpdatedAt = time.Now().UTC()
		c, cancelSave := context.WithTimeout(saveCtx, 10*time.Second)
		defer cancelSave()
		return s.store.Save(c, *r, owner)
	}
	release := func(code string) error {
		r.ErrorCode = code
		r.Owner = ""
		r.NextAttempt = time.Now().Add(s.cfg.RetryInterval)
		return save()
	}
	deliverChecker := func() error {
		if r.Checker == nil || !r.Checker.ResultPending {
			return nil
		}
		post := func() error {
			c, done := context.WithTimeout(saveCtx, 10*time.Second)
			defer done()
			return s.postCheckerResult(c, *r)
		}
		err := post()
		if errors.Is(err, ErrCheckerAuthRejected) && r.Checker.Request != nil && r.Checker.Request.SelectionMode == "broker_pool" {
			c, done := context.WithTimeout(saveCtx, 10*time.Second)
			fresh, refreshErr := s.refreshCheckerToken(c, *r)
			done()
			if refreshErr != nil {
				if errors.Is(refreshErr, ErrCheckerAuthRejected) {
					r.Phase = "BLOCKED"
					r.ErrorCode = "CHECKER_SERVICE_AUTH_REJECTED"
					r.Owner = ""
					return save()
				}
				return release("CHECKER_TOKEN_REFRESH_PENDING")
			}
			r.Checker.JobToken = fresh
			if err := save(); err != nil {
				return err
			}
			err = post()
		}
		if errors.Is(err, ErrCheckerAuthRejected) {
			r.Phase = "BLOCKED"
			r.ErrorCode = "CHECKER_AUTH_REJECTED"
			r.Owner = ""
			return save()
		} else if err != nil {
			return release("CHECKER_RESULT_PENDING")
		}
		r.Checker.ResultPending = false
		r.Checker.JobToken = ""
		r.Checker.ResultBody = nil
		if r.Phase != "REJECTED" {
			r.ErrorCode = ""
		}
		r.Owner = ""
		return save()
	}
	deliver := func() error {
		c, done := context.WithTimeout(saveCtx, 15*time.Second)
		defer done()
		ack, eventErr := s.broker.Event(c, r.TargetID, r.FinishedBody)
		if eventErr != nil {
			var api *APIError
			if errors.As(eventErr, &api) && api.Status == 409 {
				r.Phase = "BLOCKED"
				r.ErrorCode = "BROKER_FINISH_CONFLICT"
				r.Owner = ""
				return save()
			}
			return release("BROKER_FINISH_PENDING")
		}
		if ack.TargetID != r.TargetID || ack.ExecutionID != r.ID || ack.ExecutionState != "FINISHED" || ack.VMState == "" {
			return release("BROKER_FINISH_RESPONSE_INVALID")
		}
		r.BrokerPending = false
		r.ErrorCode = ""
		r.Payload = nil
		if r.Checker == nil || !r.Checker.ResultPending {
			r.Owner = ""
		}
		if cleanup, ok := s.transport.(interface {
			Cleanup(context.Context, Connection, string) error
		}); ok && r.Connection != nil {
			cleanupCtx, stopCleanup := context.WithTimeout(saveCtx, 5*time.Second)
			_ = cleanup.Cleanup(cleanupCtx, *r.Connection, r.ID)
			stopCleanup()
		}
		r.Connection = nil
		if err := save(); err != nil {
			return err
		}
		return deliverChecker()
	}
	reject := func(code string) error {
		r.Phase = "REJECTED"
		r.ErrorCode = code
		if r.Checker != nil {
			started := false
			r.Outcome = &Outcome{Result: "unreachable", ErrorCode: code, Started: &started}
			if err := prepareCheckerResult(r, time.Now().UTC()); err != nil {
				return err
			}
		}
		if r.Checker == nil || !r.Checker.ResultPending {
			r.Owner = ""
		}
		if err := save(); err != nil {
			return err
		}
		return deliverChecker()
	}
	finish := func(out Outcome) error {
		limit := r.OutputLimit
		if limit < 1 || limit > 1<<20 {
			limit = s.cfg.OutputLimit
		}
		out = normalizeOutcome(out, limit)
		r.Outcome = &out
		r.Phase = "FINISHED"
		r.BrokerPending = true
		if err := prepareCheckerResult(r, time.Now().UTC()); err != nil {
			return err
		}
		r.FinishedBody, _ = json.Marshal(struct {
			ID       string `json:"execution_id"`
			Event    string `json:"event"`
			Result   string `json:"result"`
			ExitCode *int64 `json:"exit_code,omitempty"`
		}{r.ID, "finished", out.Result, out.ExitCode})
		if err := save(); err != nil {
			return err
		}
		return deliver()
	}
	if r.Phase == "FINISHED" && r.BrokerPending {
		return deliver()
	}
	if r.Phase == "FINISHED" && r.Checker != nil && r.Checker.ResultPending {
		return deliverChecker()
	}
	if r.Phase == "REJECTED" && r.Checker != nil && r.Checker.ResultPending {
		return deliverChecker()
	}
	if r.Phase == "FETCH_PENDING" {
		if r.Checker == nil {
			r.Phase = "BLOCKED"
			r.ErrorCode = "CHECKER_METADATA_MISSING"
			r.Owner = ""
			return save()
		}
		payload, fetchErr := s.fetchCheckerPayload(runCtx, *r)
		if errors.Is(fetchErr, ErrCheckerAuthRejected) && r.Checker.Request != nil && r.Checker.Request.SelectionMode == "broker_pool" {
			fresh, refreshErr := s.refreshCheckerToken(runCtx, *r)
			if refreshErr == nil {
				r.Checker.JobToken = fresh
				if err := save(); err != nil {
					return err
				}
				payload, fetchErr = s.fetchCheckerPayload(runCtx, *r)
			} else if !errors.Is(refreshErr, ErrCheckerAuthRejected) {
				return release("CHECKER_TOKEN_REFRESH_PENDING")
			}
		}
		if errors.Is(fetchErr, ErrCheckerAuthRejected) {
			r.Phase = "BLOCKED"
			r.ErrorCode = "CHECKER_PAYLOAD_AUTH_REJECTED"
			r.Owner = ""
			return save()
		}
		if errors.Is(fetchErr, ErrInvalidSubmission) {
			return reject("CHECKER_PAYLOAD_INVALID")
		}
		if errors.Is(fetchErr, ErrCheckerPayloadDenied) {
			return reject("CHECKER_PAYLOAD_DENIED")
		}
		if fetchErr != nil {
			return release("CHECKER_PAYLOAD_PENDING")
		}
		r.Payload = payload
		r.Phase = "QUEUED"
		r.Owner = ""
		r.NextAttempt = time.Time{}
		return save()
	}
	if r.Phase == "APPROVED" || r.Phase == "CONNECTING" || r.Phase == "RUNNING" {
		if resumable, ok := s.transport.(interface {
			Resume(context.Context, Connection, Job) Outcome
		}); ok {
			if r.Connection == nil || len(r.Payload) == 0 {
				return finish(Outcome{Result: "unreachable", ErrorCode: "EXECUTOR_RECOVERY_MISSING"})
			}
			execCtx, stopExec := context.WithTimeout(runCtx, r.ConnectTimeout+r.ExecutionTimeout+20*time.Second)
			defer stopExec()
			return finish(s.resume(execCtx, resumable, *r.Connection, Job{ID: r.ID, Payload: r.Payload, Timeout: r.ExecutionTimeout, ConnectTimeout: r.ConnectTimeout, OutputLimit: r.OutputLimit}))
		}
		if recoverer, ok := s.transport.(interface {
			Recover(context.Context, string) error
		}); ok {
			if err := recoverer.Recover(runCtx, r.ID); err != nil {
				r.Phase = "BLOCKED"
				r.ErrorCode = "TRANSPORT_RECOVERY_FAILED"
				r.Owner = ""
				return save()
			}
		}
		return finish(Outcome{Result: "unreachable", ErrorCode: "RUNTIME_INTERRUPTED"})
	}
	recoveringStart := r.Phase == "START_PENDING"
	if r.Phase == "QUEUED" {
		if r.TargetID == UnboundTargetID {
			targetID, selectionErr := s.selectPoolTarget(runCtx, r.ID, owner)
			if selectionErr != nil || targetID == "" {
				return release("BROKER_VM_PENDING")
			}
			r.TargetID = targetID
		}
		conn, connErr := s.broker.Connection(runCtx, r.TargetID)
		if connErr != nil {
			var api *APIError
			if errors.As(connErr, &api) && api.Status >= 400 && api.Status < 500 && api.Status != 429 {
				return reject("BROKER_CONNECTION_REJECTED")
			}
			return release("BROKER_CONNECTION_PENDING")
		}
		if validator, ok := s.transport.(interface{ ValidateConnection(Connection) error }); ok {
			if validator.ValidateConnection(conn) != nil {
				return reject("EXECUTOR_CONNECTION_INVALID")
			}
		}
		r.Connection = &conn
		r.Phase = "START_PENDING"
		r.StartedBody, _ = json.Marshal(struct {
			ID    string `json:"execution_id"`
			Event string `json:"event"`
		}{r.ID, "started"})
		r.StartUncertain = true
		if err := save(); err != nil {
			return err
		}
	}
	if r.Phase != "START_PENDING" || len(r.StartedBody) == 0 {
		return release("INVALID_EXECUTION_STATE")
	}
	ack, startErr := s.broker.Event(runCtx, r.TargetID, r.StartedBody)
	if startErr != nil {
		var api *APIError
		if errors.As(startErr, &api) && api.Status >= 400 && api.Status < 500 && api.Status != 429 {
			if recoveringStart && r.StartUncertain {
				r.Owner = ""
				r.Phase = "BLOCKED"
				r.ErrorCode = "BROKER_START_RECONCILIATION_REQUIRED"
				return save()
			}
			return reject("BROKER_START_REJECTED")
		}
		return release("BROKER_START_PENDING")
	}
	if ack.TargetID != r.TargetID || ack.ExecutionID != r.ID || ack.ExecutionState != "RUNNING" || ack.VMState != "RUNNING" {
		return release("BROKER_START_RESPONSE_INVALID")
	}
	r.Phase = "APPROVED"
	r.StartUncertain = false
	if err := save(); err != nil {
		return err
	}
	if r.Connection == nil {
		return finish(Outcome{Result: "failed", ErrorCode: "CONNECTION_MISSING"})
	}
	if runCtx.Err() != nil {
		return finish(Outcome{Result: "unreachable", ErrorCode: "RUNTIME_STOPPED"})
	}
	r.Phase = "CONNECTING"
	if err := save(); err != nil {
		return err
	}
	if r.ExecutionTimeout < time.Second || r.ExecutionTimeout > time.Hour || r.ConnectTimeout < time.Second || r.ConnectTimeout > 5*time.Minute || r.OutputLimit < 1 || r.OutputLimit > 1<<20 {
		return finish(Outcome{Result: "failed", ErrorCode: "STORED_LIMITS_INVALID"})
	}
	execCtx, stopExec := context.WithTimeout(runCtx, r.ConnectTimeout+r.ExecutionTimeout+20*time.Second)
	defer stopExec()
	return finish(s.execute(execCtx, *r.Connection, Job{ID: r.ID, Payload: r.Payload, Timeout: r.ExecutionTimeout, ConnectTimeout: r.ConnectTimeout, OutputLimit: r.OutputLimit}))
}

// selectPoolTarget reserves one READY Broker VM in the durable store before
// the started event. A list response alone never grants permission to upload.
func (s *Service) selectPoolTarget(ctx context.Context, executionID, owner string) (string, error) {
	source, ok := s.broker.(interface {
		List(context.Context, int, string) (VMPage, error)
	})
	if !ok || !s.poolAnyTargets && len(s.poolTargets) == 0 {
		return "", ErrTargetDiscoveryUnavailable
	}
	cursor := ""
	for pageNumber := 0; pageNumber < 20; pageNumber++ {
		page, err := source.List(ctx, 200, cursor)
		if err != nil {
			return "", err
		}
		for _, item := range page.Items {
			if !s.poolAnyTargets && !s.poolTargets[item.TargetID] {
				continue
			}
			bound, bindErr := s.store.BindTarget(ctx, executionID, owner, item.TargetID)
			if bindErr != nil {
				return "", bindErr
			}
			if bound {
				return item.TargetID, nil
			}
		}
		if page.NextCursor == nil {
			return "", nil
		}
		cursor = *page.NextCursor
	}
	return "", errors.New("Windows target list exceeds page limit")
}

func (s *Service) execute(ctx context.Context, c Connection, j Job) (out Outcome) {
	defer func() {
		if recover() != nil {
			out = Outcome{Result: "failed", ErrorCode: "TRANSPORT_RUNTIME_FAILED"}
		}
	}()
	return s.transport.Execute(ctx, c, j)
}

func (s *Service) resume(ctx context.Context, transport interface {
	Resume(context.Context, Connection, Job) Outcome
}, c Connection, j Job) (out Outcome) {
	defer func() {
		if recover() != nil {
			out = Outcome{Result: "failed", ErrorCode: "TRANSPORT_RUNTIME_FAILED"}
		}
	}()
	return transport.Resume(ctx, c, j)
}
func normalizeOutcome(out Outcome, limit int) Outcome {
	validCode := out.ExitCode == nil || *out.ExitCode >= -2147483648 && *out.ExitCode <= 4294967295
	validResult := out.Result == "succeeded" || out.Result == "failed" || out.Result == "timeout" || out.Result == "unreachable"
	if !validCode || !validResult || out.Result == "succeeded" && (out.ExitCode == nil || *out.ExitCode != 0) {
		out.Result = "failed"
		out.ErrorCode = "INVALID_EXECUTION_RESULT"
		if !validCode {
			out.ExitCode = nil
		}
	}
	bound := func(value string, truncated bool) (string, bool) {
		value = strings.ToValidUTF8(value, "�")
		if len(value) > limit {
			value = value[:limit]
			for !utf8.ValidString(value) {
				value = value[:len(value)-1]
			}
			truncated = true
		}
		return value, truncated
	}
	out.Stdout, out.StdoutTruncated = bound(out.Stdout, out.StdoutTruncated)
	out.Stderr, out.StderrTruncated = bound(out.Stderr, out.StderrTruncated)
	// Guest-provided diagnostics are codes, never exception text or filenames.
	if len(out.ErrorCode) > 80 || strings.IndexFunc(out.ErrorCode, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
	}) >= 0 {
		out.ErrorCode = "GUEST_EXECUTION_FAILED"
	}
	return out
}
