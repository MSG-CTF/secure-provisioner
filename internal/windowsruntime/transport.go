package windowsruntime

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Credential is selected only by the broker's VM UUID. Secret files must be
// private regular files outside WorkRoot. A blank pin uses normal PKI validation.
type Credential struct {
	PasswordFile      string `json:"password_file"`
	ResultKeyFile     string `json:"result_key_file"`
	CertificateSHA256 string `json:"certificate_sha256"`
	AccountSID        string `json:"account_sid"`
}

type FreeRDPConfig struct {
	ClientPath  string                `json:"client_path"`
	XvfbPath    string                `json:"xvfb_path"`
	WorkRoot    string                `json:"work_root"`
	Credentials map[string]Credential `json:"credentials"`
}

type FreeRDPTransport struct {
	cfg        FreeRDPConfig
	validation sync.Mutex
	validated  bool
}

var transportSID = regexp.MustCompile(`^S-1-(?:[0-9]+-){1,14}[0-9]+$`)
var transportErrorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var transportVersion3 = regexp.MustCompile(`(?mi)\bFreeRDP version 3\.[0-9]+\.[0-9]+\b`)

func transportValidID(id string) bool { v, e := uuid.Parse(id); return e == nil && v.String() == id }

func NewFreeRDPTransport(cfg FreeRDPConfig) (*FreeRDPTransport, error) {
	for _, p := range []string{cfg.ClientPath, cfg.XvfbPath, cfg.WorkRoot} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n,") {
			return nil, errors.New("Windows RDP paths must be clean absolute paths without delimiters")
		}
	}
	if len(cfg.Credentials) == 0 {
		return nil, errors.New("Windows RDP credentials are required")
	}
	credentials := make(map[string]Credential, len(cfg.Credentials))
	for id, c := range cfg.Credentials {
		if !transportValidID(id) || !transportSID.MatchString(c.AccountSID) {
			return nil, errors.New("invalid Windows RDP credential mapping")
		}
		for _, secretPath := range []string{c.PasswordFile, c.ResultKeyFile} {
			if !filepath.IsAbs(secretPath) || filepath.Clean(secretPath) != secretPath || strings.ContainsAny(secretPath, "\x00\r\n") {
				return nil, errors.New("invalid Windows RDP secret path")
			}
			rel, err := filepath.Rel(cfg.WorkRoot, secretPath)
			if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return nil, errors.New("Windows RDP secrets must be outside the work root")
			}
		}
		if c.CertificateSHA256 != "" {
			raw, err := hex.DecodeString(c.CertificateSHA256)
			if err != nil || len(raw) != sha256.Size {
				return nil, errors.New("Windows certificate pin must contain 64 SHA256 hex digits")
			}
			c.CertificateSHA256 = strings.ToLower(c.CertificateSHA256)
		}
		credentials[id] = c
	}
	cfg.Credentials = credentials
	return &FreeRDPTransport{cfg: cfg}, nil
}

// Validate is safe to call at startup. It checks the installed major version
// without connecting to a server and never returns raw client diagnostics.
func (t *FreeRDPTransport) Validate(ctx context.Context) error {
	t.validation.Lock()
	defer t.validation.Unlock()
	if t.validated {
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("Windows RDP transport requires a Linux host")
	}
	for _, p := range []string{t.cfg.ClientPath, t.cfg.XvfbPath} {
		s, e := os.Stat(p)
		if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0111 == 0 {
			return errors.New("Windows RDP client and Xvfb runner must be executable files")
		}
	}
	if err := transportMkdirAll(t.cfg.WorkRoot); err != nil {
		return errors.New("Windows RDP work root is not a private directory")
	}
	for _, c := range t.cfg.Credentials {
		password, err := transportReadFile(c.PasswordFile, 511, true)
		if err != nil || !transportValidPassword(password) {
			return errors.New("invalid Windows RDP password file")
		}
		clear(password)
		key, err := transportReadFile(c.ResultKeyFile, sha256.Size, true)
		if err != nil || len(key) != sha256.Size {
			clear(key)
			return errors.New("invalid Windows RDP result key file")
		}
		clear(key)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := transportProbeVersion(probeCtx, t.cfg.ClientPath, transportEnvironment(t.cfg.WorkRoot))
	if err != nil || !transportVersion3.Match(output) {
		return errors.New("Windows RDP client must report FreeRDP version 3")
	}
	t.validated = true
	return nil
}

func transportEnvironment(home string) []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "TMPDIR=" + home, "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "USER=runtime", "LOGNAME=runtime"}
}
func transportValidPassword(b []byte) bool {
	return len(b) > 0 && len(b) <= 511 && !bytes.ContainsAny(b, "\x00\r\n") && utf8.Valid(b)
}
func transportFailure(result, code string) Outcome { return Outcome{Result: result, ErrorCode: code} }

func (t *FreeRDPTransport) Execute(ctx context.Context, c Connection, j Job) Outcome {
	if err := ctx.Err(); err != nil {
		return transportFailure("unreachable", "execution_cancelled")
	}
	if !transportValidID(j.ID) || !transportValidID(c.TargetID) || c.Protocol != "rdp" || c.Port < 1 || c.Port > 65535 || !transportHost(c.Host) || len(c.Username) == 0 || len(c.Username) > 256 || strings.IndexFunc(c.Username, unicode.IsControl) >= 0 || j.Timeout <= 0 || j.ConnectTimeout <= 0 || j.Timeout > 24*time.Hour || j.ConnectTimeout > time.Hour || j.OutputLimit < 1 || j.OutputLimit > 16<<20 || len(j.Payload) == 0 || len(j.Payload) > 64<<20 {
		return transportFailure("failed", "invalid_execution")
	}
	profile, err := BuildRDPProfile(c, false)
	if err != nil {
		return transportFailure("failed", "rdp_profile_invalid")
	}
	cred, ok := t.cfg.Credentials[c.TargetID]
	if !ok {
		return transportFailure("failed", "credentials_missing")
	}
	if err := t.Validate(ctx); err != nil {
		return transportFailure("failed", "transport_unavailable")
	}
	password, err := transportReadFile(cred.PasswordFile, 511, true)
	if err != nil || !transportValidPassword(password) {
		clear(password)
		return transportFailure("failed", "credentials_invalid")
	}
	defer clear(password)
	resultKey, err := transportReadFile(cred.ResultKeyFile, sha256.Size, true)
	if err != nil || len(resultKey) != sha256.Size {
		clear(resultKey)
		return transportFailure("failed", "result_key_invalid")
	}
	defer clear(resultKey)
	base := filepath.Join(t.cfg.WorkRoot, j.ID)
	if err := transportMkdirExclusive(base); err != nil {
		return transportFailure("failed", "execution_directory_exists")
	}
	control, share := filepath.Join(base, "control"), filepath.Join(base, "share")
	if transportMkdirExclusive(control) != nil || transportMkdirExclusive(share) != nil {
		return transportFailure("failed", "workspace_invalid")
	}
	profilePath := filepath.Join(control, "connection.rdp")
	if transportWriteFile(profilePath, profile) != nil {
		return transportFailure("failed", "workspace_write_failed")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return transportFailure("failed", "nonce_unavailable")
	}
	digest := sha256.Sum256(j.Payload)
	request := transportRequest{SchemaVersion: 1, ExecutionID: j.ID, Nonce: hex.EncodeToString(nonce[:]), PayloadSHA256: hex.EncodeToString(digest[:]), TimeoutSeconds: int64((j.Timeout + time.Second - 1) / time.Second), OutputLimitBytes: j.OutputLimit}
	manifest, err := json.Marshal(request)
	if err != nil {
		return transportFailure("failed", "manifest_invalid")
	}
	if transportWriteFile(filepath.Join(share, "payload.exe"), j.Payload) != nil || transportWriteFile(filepath.Join(share, "request.json"), manifest) != nil {
		return transportFailure("failed", "workspace_write_failed")
	}
	cert := "/cert:deny"
	if cred.CertificateSHA256 != "" {
		cert = "/cert:deny,fingerprint:sha256:" + cred.CertificateSHA256
	}
	args := []string{"-a", "--server-args=-screen 0 800x600x24 -nolisten tcp", t.cfg.ClientPath, profilePath, "/from-stdin:force", cert, "/sec:nla", "-drives", "-home-drive", "-clipboard", "-auto-reconnect", "-multitouch", "-gestures", "/audio-mode:2", "/log-level:OFF", "/size:800x600", "/gdi:sw", "/drive:runtimejob," + share}
	input := append(append([]byte(nil), password...), '\n')
	defer clear(input)
	proc, err := transportStartProcess(control, j.ID, t.cfg.XvfbPath, args, transportEnvironment(control), input)
	if err != nil {
		return transportFailure("unreachable", "rdp_start_failed")
	}
	defer func() { _ = proc.stop(); proc.wait() }()
	connectDeadline := time.NewTimer(j.ConnectTimeout)
	defer connectDeadline.Stop()
	var runDeadline <-chan time.Time
	var runTimer *time.Timer
	defer func() {
		if runTimer != nil {
			runTimer.Stop()
		}
	}()
	state := transportGuestState{request: request, accountSID: cred.AccountSID, limit: j.OutputLimit, key: resultKey}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if outcome, done, err := state.poll(share); err != nil {
			return transportFailure("failed", "guest_response_invalid")
		} else if done {
			return outcome
		}
		if state.started && runDeadline == nil {
			runTimer = time.NewTimer(j.Timeout + 2*time.Second)
			runDeadline = runTimer.C
			connectDeadline.Stop()
		}
		select {
		case <-ctx.Done():
			return transportFailure("unreachable", "execution_cancelled")
		case <-proc.done:
			// A final atomically published result may precede client exit. A client
			// exit code by itself says nothing about the payload's exit code.
			if outcome, done, err := state.poll(share); err != nil {
				return transportFailure("failed", "guest_response_invalid")
			} else if done {
				return outcome
			}
			return transportFailure("unreachable", "rdp_disconnected")
		case <-connectDeadline.C:
			return transportFailure("unreachable", "runner_unavailable")
		case <-runDeadline:
			return Outcome{Result: "timeout", StartedAt: state.startedAt, ErrorCode: "execution_deadline"}
		case <-tick.C:
		}
	}
}

func transportHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n,/%[] \\@") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Recover stops only an invocation whose private ownership record still matches
// the kernel's PID, boot identity, owner, start time and process group.
func (t *FreeRDPTransport) Recover(ctx context.Context, id string) error {
	if !transportValidID(id) {
		return errors.New("invalid Windows execution ID")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return transportRecoverProcess(ctx, filepath.Join(t.cfg.WorkRoot, id, "control"), id)
}

type transportRequest struct {
	SchemaVersion    int    `json:"schema_version"`
	ExecutionID      string `json:"execution_id"`
	Nonce            string `json:"nonce"`
	PayloadSHA256    string `json:"payload_sha256"`
	TimeoutSeconds   int64  `json:"timeout_seconds"`
	OutputLimitBytes int    `json:"output_limit_bytes"`
}

type transportCorrelation struct {
	SchemaVersion int    `json:"schema_version"`
	ExecutionID   string `json:"execution_id"`
	Nonce         string `json:"nonce"`
	PayloadSHA256 string `json:"payload_sha256"`
}
type transportReady struct {
	transportCorrelation
	AccountSID string `json:"account_sid"`
	IsAdmin    *bool  `json:"is_admin"`
	Integrity  string `json:"integrity"`
	SessionID  int64  `json:"session_id"`
	Protocol   string `json:"protocol"`
}
type transportStarted struct {
	transportCorrelation
	PID int64 `json:"pid"`
}
type transportResult struct {
	transportCorrelation
	Result          string          `json:"result"`
	ExitCode        json.RawMessage `json:"exit_code"`
	Stdout          *string         `json:"stdout"`
	Stderr          *string         `json:"stderr"`
	StdoutTruncated *bool           `json:"stdout_truncated"`
	StderrTruncated *bool           `json:"stderr_truncated"`
	ErrorCode       string          `json:"error_code,omitempty"`
}
type transportGuestState struct {
	request        transportRequest
	accountSID     string
	limit          int
	key            []byte
	ready, started bool
	startedAt      *time.Time
}

type transportSignedFrame struct{ Payload, Signature string }

func (f *transportSignedFrame) UnmarshalJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid guest envelope")
	}
	seen := make(map[string]bool, 2)
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok || seen[name] || (name != "payload" && name != "signature") {
			return errors.New("invalid guest envelope field")
		}
		seen[name] = true
		var value string
		if err = d.Decode(&value); err != nil {
			return err
		}
		if name == "payload" {
			f.Payload = value
		} else {
			f.Signature = value
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	if len(seen) != 2 {
		return errors.New("missing guest envelope field")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing guest envelope JSON")
	}
	return nil
}

// Guest frames are authenticated by the privileged supervisor. Correlation alone
// is insufficient: the submitted user process can read its redirected manifest.
func transportDecodeGuest(path string, max int, key []byte, v any) (bool, error) {
	if len(key) != sha256.Size {
		return false, errors.New("guest authentication key invalid")
	}
	var frame transportSignedFrame
	present, err := transportDecode(path, base64.StdEncoding.EncodedLen(max)+256, &frame)
	if err != nil || !present {
		return present, err
	}
	if len(frame.Signature) != 64 || strings.ToLower(frame.Signature) != frame.Signature || len(frame.Payload) > base64.StdEncoding.EncodedLen(max) || strings.ContainsAny(frame.Payload, "\r\n") {
		return false, errors.New("guest authentication frame invalid")
	}
	signature, err := hex.DecodeString(frame.Signature)
	if err != nil {
		return false, errors.New("guest authentication signature invalid")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(frame.Payload)
	if err != nil || len(payload) > max || !utf8.Valid(payload) {
		return false, errors.New("guest authentication payload invalid")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), signature) {
		return false, errors.New("guest authentication failed")
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if err = d.Decode(v); err != nil {
		return false, err
	}
	if d.Decode(new(any)) != io.EOF {
		return false, errors.New("trailing guest JSON")
	}
	return true, nil
}

func (s *transportGuestState) correlated(c transportCorrelation) bool {
	return c.SchemaVersion == 1 && c.ExecutionID == s.request.ExecutionID && c.Nonce == s.request.Nonce && c.PayloadSHA256 == s.request.PayloadSHA256
}

func transportDecode(path string, max int, v any) (bool, error) {
	b, err := transportReadFile(path, max, false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !utf8.Valid(b) {
		return false, errors.New("invalid UTF8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(v); err != nil {
		return false, err
	}
	if d.Decode(new(any)) != io.EOF {
		return false, errors.New("trailing JSON")
	}
	return true, nil
}

func (s *transportGuestState) poll(share string) (Outcome, bool, error) {
	invalid := func() (Outcome, bool, error) { return Outcome{}, false, errors.New("invalid guest evidence") }
	if !s.ready {
		var r transportReady
		if present, e := transportDecodeGuest(filepath.Join(share, "ready.json"), 4096, s.key, &r); e != nil {
			return Outcome{}, false, e
		} else if present {
			if !s.correlated(r.transportCorrelation) || r.AccountSID != s.accountSID || r.IsAdmin == nil || *r.IsAdmin || r.Integrity != "medium" || r.SessionID <= 0 || r.Protocol != "rdp" {
				return invalid()
			}
			s.ready = true
		}
	}
	if !s.started {
		var r transportStarted
		if present, e := transportDecodeGuest(filepath.Join(share, "started.json"), 4096, s.key, &r); e != nil {
			return Outcome{}, false, e
		} else if present {
			if !s.ready || !s.correlated(r.transportCorrelation) || r.PID <= 0 {
				return invalid()
			}
			s.started = true
			now := time.Now().UTC()
			s.startedAt = &now
		}
	}
	var r transportResult
	present, e := transportDecodeGuest(filepath.Join(share, "result.json"), 4096+12*s.limit, s.key, &r)
	if e != nil {
		return Outcome{}, false, e
	}
	if !present {
		return Outcome{}, false, nil
	}
	if !s.correlated(r.transportCorrelation) || r.Stdout == nil || r.Stderr == nil || r.StdoutTruncated == nil || r.StderrTruncated == nil || len(*r.Stdout) > s.limit || len(*r.Stderr) > s.limit || len(r.ExitCode) == 0 || (r.ErrorCode != "" && !transportErrorCode.MatchString(r.ErrorCode)) {
		return invalid()
	}
	var exit *int64
	if string(r.ExitCode) != "null" {
		var n int64
		if json.Unmarshal(r.ExitCode, &n) != nil || n < -2147483648 || n > 4294967295 {
			return invalid()
		}
		exit = &n
	}
	switch r.Result {
	case "succeeded":
		if !s.ready || !s.started || exit == nil || *exit != 0 || r.ErrorCode != "" {
			return invalid()
		}
	case "timeout":
		if !s.ready || !s.started {
			return invalid()
		}
	case "failed":
	default:
		return invalid()
	}
	return Outcome{Result: r.Result, ExitCode: exit, StartedAt: s.startedAt, Stdout: *r.Stdout, Stderr: *r.Stderr, StdoutTruncated: *r.StdoutTruncated, StderrTruncated: *r.StderrTruncated, ErrorCode: r.ErrorCode}, true, nil
}
