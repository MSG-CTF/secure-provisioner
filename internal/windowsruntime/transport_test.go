package windowsruntime

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

const transportTestID = "f53f83ae-1ef8-43ad-acd2-dfc5d8cf923a"
const transportTestTarget = "67a54d68-9ac3-4a57-a2e9-75e37fd2cb28"
const transportTestSID = "S-1-5-21-123-456-789-1001"
const transportTestResultKey = "0123456789abcdef0123456789abcdef"

// The test executable is a benign stand-in at the operating-system process
// boundary. It never executes payload.exe or makes a network connection.
func init() {
	if len(os.Args) < 2 {
		return
	}
	if os.Args[1] == "/version" {
		if strings.Contains(filepath.Base(os.Args[0]), "version2") {
			fmt.Println("This is FreeRDP version 2.11.7 (test helper)")
			os.Exit(0)
		}
		fmt.Println("This is FreeRDP version 3.10.3 (test helper)")
		os.Exit(0)
	}
	if os.Args[1] == "--transport-child" {
		_ = os.WriteFile(os.Args[2], []byte(fmt.Sprint(os.Getpid())), 0600)
		for {
			time.Sleep(time.Second)
		}
	}
	if os.Args[1] != "-a" {
		return
	}
	var share string
	for _, a := range os.Args[2:] {
		if strings.HasPrefix(a, "/drive:runtimejob,") {
			share = strings.TrimPrefix(a, "/drive:runtimejob,")
		}
	}
	if share == "" {
		os.Exit(4)
	}
	if len(os.Args) < 5 || os.Args[4] != filepath.Join(filepath.Dir(share), "control", "connection.rdp") {
		os.Exit(6)
	}
	profileBytes, err := os.ReadFile(os.Args[4])
	if err != nil || len(profileBytes) < 2 || len(profileBytes)%2 != 0 || profileBytes[0] != 0xff || profileBytes[1] != 0xfe {
		os.Exit(7)
	}
	units := make([]uint16, (len(profileBytes)-2)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(profileBytes[2+2*i:])
	}
	profile := string(utf16.Decode(units))
	if !strings.Contains(profile, "full address:s:192.0.2.10:3389\r\n") || !strings.Contains(profile, "username:s:runner\r\n") {
		os.Exit(8)
	}
	input, _ := io.ReadAll(os.Stdin)
	observed, _ := json.Marshal(map[string]any{"args": os.Args[1:], "env": os.Environ(), "stdin": string(input), "profile": profile})
	_ = os.WriteFile(filepath.Join(filepath.Dir(share), "control", "observed.json"), observed, 0600)
	data, _ := os.ReadFile(filepath.Join(share, "request.json"))
	var req map[string]any
	if json.Unmarshal(data, &req) != nil {
		os.Exit(5)
	}
	payload, _ := os.ReadFile(filepath.Join(share, "payload.exe"))
	mode := string(payload)
	if mode == "disconnect" {
		os.Exit(0)
	}
	if mode == "missing_runner" {
		for {
			time.Sleep(time.Second)
		}
	}
	base := map[string]any{"schema_version": req["schema_version"], "execution_id": req["execution_id"], "nonce": req["nonce"], "payload_sha256": req["payload_sha256"]}
	write := func(name string, extra map[string]any) {
		v := map[string]any{}
		for k, x := range base {
			v[k] = x
		}
		for k, x := range extra {
			v[k] = x
		}
		b, _ := json.Marshal(v)
		if mode != "unsigned_"+strings.TrimSuffix(name, ".json") {
			key := []byte(transportTestResultKey)
			if mode == "wrong_key" {
				key = []byte(strings.Repeat("z", 32))
			}
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write(b)
			frame := map[string]any{"payload": base64.StdEncoding.EncodeToString(b), "signature": hex.EncodeToString(mac.Sum(nil))}
			if mode == "tampered_payload" && name == "result.json" {
				v["stdout"] = "forged"
				altered, _ := json.Marshal(v)
				frame["payload"] = base64.StdEncoding.EncodeToString(altered)
			}
			b, _ = json.Marshal(frame)
		}
		_ = os.WriteFile(filepath.Join(share, name+".tmp"), b, 0600)
		_ = os.Rename(filepath.Join(share, name+".tmp"), filepath.Join(share, name))
	}
	if mode != "missing_ready" && mode != "prestart_failed" {
		ready := map[string]any{"account_sid": transportTestSID, "is_admin": false, "integrity": "medium", "session_id": 3, "protocol": "rdp"}
		if mode == "wrong_sid" {
			ready["account_sid"] = "S-1-5-21-1-2-3-500"
		}
		if mode == "admin" {
			ready["is_admin"] = true
		}
		write("ready.json", ready)
	}
	if mode != "missing_started" && mode != "prestart_failed" {
		write("started.json", map[string]any{"pid": 1234})
	}
	if mode == "hang" || mode == "orphan" {
		child := exec.Command(os.Args[0], "--transport-child", filepath.Join(filepath.Dir(share), "control", "child.pid"))
		_ = child.Start()
		if mode == "orphan" {
			for i := 0; i < 100; i++ {
				if _, e := os.Stat(filepath.Join(filepath.Dir(share), "control", "child.pid")); e == nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			os.Exit(0)
		}
		for {
			time.Sleep(time.Second)
		}
	}
	result := map[string]any{"result": "succeeded", "exit_code": 0, "stdout": "hello", "stderr": "", "stdout_truncated": false, "stderr_truncated": false}
	switch mode {
	case "nonce":
		result["nonce"] = strings.Repeat("0", 64)
	case "signed_old_nonce":
		result["nonce"] = strings.Repeat("0", 64)
	case "digest":
		result["payload_sha256"] = strings.Repeat("0", 64)
	case "oversize":
		result["stdout"] = strings.Repeat("x", 65)
	case "oversize_file":
		_ = os.WriteFile(filepath.Join(share, "result.json"), []byte(strings.Repeat(" ", 10000)), 0600)
		for {
			time.Sleep(time.Second)
		}
	case "malformed":
		_ = os.WriteFile(filepath.Join(share, "result.json"), []byte(`{"result":`), 0600)
		for {
			time.Sleep(time.Second)
		}
	case "schema":
		result["schema_version"] = 2
	case "missing_output_flag":
		delete(result, "stdout_truncated")
	case "nonzero_success":
		result["exit_code"] = 7
	case "null_success":
		result["exit_code"] = nil
	case "large_exit":
		result["result"] = "failed"
		result["exit_code"] = uint64(3221225477)
	case "prestart_failed":
		result["result"] = "failed"
		result["exit_code"] = nil
		result["error_code"] = "runner_rejected"
	case "timeout":
		result["result"] = "timeout"
		result["exit_code"] = nil
	case "symlink":
		b, _ := json.Marshal(result)
		outside := filepath.Join(filepath.Dir(share), "control", "outside-result")
		_ = os.WriteFile(outside, b, 0600)
		_ = os.Symlink(outside, filepath.Join(share, "result.json"))
		for {
			time.Sleep(time.Second)
		}
	}
	write("result.json", result)
	for {
		time.Sleep(time.Second)
	}
}

func transportFixture(t *testing.T) (*FreeRDPTransport, Connection, Job) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("production transport requires Linux process groups")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "password")
	if err := os.WriteFile(secret, []byte("transport-test-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "result-key")
	if err := os.WriteFile(keyFile, []byte(transportTestResultKey), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewFreeRDPTransport(FreeRDPConfig{ClientPath: exe, XvfbPath: exe, WorkRoot: filepath.Join(dir, "jobs"), Credentials: map[string]Credential{transportTestTarget: {PasswordFile: secret, ResultKeyFile: keyFile, AccountSID: transportTestSID}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BROKER_TOKEN", "must-never-reach-client")
	return tr, Connection{TargetID: transportTestTarget, Protocol: "rdp", Host: "192.0.2.10", Port: 3389, Username: "runner", RDPFile: "full address:s:192.0.2.10:3389\r\nusername:s:runner\r\nprompt for credentials:i:1\r\nenablecredsspsupport:i:1\r\nredirectclipboard:i:0\r\nredirectprinters:i:0\r\ndrivestoredirect:s:\r\n"}, Job{ID: transportTestID, Payload: []byte("success"), Timeout: time.Second, ConnectTimeout: time.Second, OutputLimit: 64}
}

func TestTransportConsumesPrivateBrokerRDPProfile(t *testing.T) {
	tr, c, j := transportFixture(t)
	if got := tr.Execute(context.Background(), c, j); got.Result != "succeeded" {
		t.Fatalf("profile connection failed: %+v", got)
	}
	b, e := os.ReadFile(filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "observed.json"))
	if e != nil {
		t.Fatal(e)
	}
	var observed struct {
		Args    []string `json:"args"`
		Profile string   `json:"profile"`
	}
	if e = json.Unmarshal(b, &observed); e != nil {
		t.Fatal(e)
	}
	profile := filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "connection.rdp")
	if len(observed.Args) < 4 || observed.Args[3] != profile {
		t.Fatal("FreeRDP did not receive the broker profile as its first argument")
	}
	for _, arg := range observed.Args {
		if strings.HasPrefix(arg, "/v:") || strings.HasPrefix(arg, "/u:") {
			t.Fatal("target was supplied through CLI rather than the broker profile")
		}
	}
	if !strings.Contains(observed.Profile, "full address:s:192.0.2.10:3389\r\n") || !strings.Contains(observed.Profile, "username:s:runner\r\n") {
		t.Fatal("client helper did not consume target/account from profile")
	}
	info, e := os.Lstat(profile)
	if e != nil {
		t.Fatal(e)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("connection profile is not a private regular file")
	}
	data, e := os.ReadFile(profile)
	if e != nil {
		t.Fatal(e)
	}
	text := decodeProfileForTest(t, data)
	if strings.Contains(text, "transport-test-secret") || strings.Contains(text, transportTestResultKey) || strings.Contains(text, "password") {
		t.Fatal("secret was included in the connection profile")
	}
	if _, e = os.Stat(filepath.Join(tr.cfg.WorkRoot, j.ID, "share", "connection.rdp")); !os.IsNotExist(e) {
		t.Fatal("connection profile exposed to guest")
	}
}

func TestTransportRejectsMissingOrUnsafeBrokerRDPProfile(t *testing.T) {
	for _, mode := range []string{"empty", "unsafe", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			tr, c, j := transportFixture(t)
			switch mode {
			case "empty":
				c.RDPFile = ""
			case "unsafe":
				c.RDPFile += "password 51:b:danger\r\n"
			case "mismatch":
				c.RDPFile = strings.Replace(c.RDPFile, "192.0.2.10:3389", "192.0.2.11:3389", 1)
			}
			got := tr.Execute(context.Background(), c, j)
			if got.Result != "failed" || got.ErrorCode != "rdp_profile_invalid" {
				t.Fatalf("invalid broker profile was ignored: %+v", got)
			}
			if _, e := os.Stat(filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "process.json")); !os.IsNotExist(e) {
				t.Fatal("RDP started despite an invalid broker profile")
			}
		})
	}
}

func TestTransportSuccessRequiresGuestResultAndRestrictsClient(t *testing.T) {
	tr, c, j := transportFixture(t)
	before := time.Now().UTC()
	got := tr.Execute(context.Background(), c, j)
	if got.Result != "succeeded" || got.ExitCode == nil || *got.ExitCode != 0 || got.Stdout != "hello" {
		t.Fatalf("unexpected outcome: %+v", got)
	}
	if got.StartedAt == nil || got.StartedAt.Before(before) || got.StartedAt.After(time.Now().UTC()) {
		t.Fatalf("verified guest start time missing or invalid: %+v", got.StartedAt)
	}
	b, err := os.ReadFile(filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "observed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var obs struct {
		Args  []string `json:"args"`
		Env   []string `json:"env"`
		Stdin string   `json:"stdin"`
	}
	if err := json.Unmarshal(b, &obs); err != nil {
		t.Fatal(err)
	}
	if obs.Stdin != "transport-test-secret\n" {
		t.Fatal("password was not supplied through stdin")
	}
	joined := strings.Join(obs.Args, " ") + strings.Join(obs.Env, " ")
	for _, bad := range []string{"transport-test-secret", transportTestResultKey, tr.cfg.Credentials[c.TargetID].ResultKeyFile, "must-never-reach-client", "drivestoredirect", "/cert:ignore", "/cert:tofu", "+drives", "+home-drive", "+clipboard", "/printer:", "/smartcard:", "+auto-reconnect"} {
		if strings.Contains(joined, bad) {
			t.Errorf("unsafe client launch contains %q", bad)
		}
	}
	for _, needed := range []string{"/cert:deny", "/from-stdin:force", "-drives", "-home-drive", "-clipboard", "-auto-reconnect"} {
		if !strings.Contains(joined, needed) {
			t.Errorf("missing client restriction %q", needed)
		}
	}
	var drives []string
	for _, a := range obs.Args {
		if strings.HasPrefix(a, "/drive:") {
			drives = append(drives, a)
		}
	}
	if len(drives) != 1 || drives[0] != "/drive:runtimejob,"+filepath.Join(tr.cfg.WorkRoot, j.ID, "share") {
		t.Fatalf("unexpected shares: %v", drives)
	}
	if _, err := os.Stat(filepath.Join(tr.cfg.WorkRoot, j.ID, "share", "process.json")); !os.IsNotExist(err) {
		t.Fatal("process identity exposed to guest")
	}
	if _, err := os.Stat(filepath.Join(tr.cfg.WorkRoot, j.ID, "share", "password")); !os.IsNotExist(err) {
		t.Fatal("password exposed to guest")
	}
	files, err := os.ReadDir(filepath.Join(tr.cfg.WorkRoot, j.ID, "share"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, e := os.ReadFile(filepath.Join(tr.cfg.WorkRoot, j.ID, "share", file.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(data), transportTestResultKey) {
			t.Fatalf("result signing key exposed in %s", file.Name())
		}
	}
}

func TestTransportRejectsUnauthenticatedGuestFrames(t *testing.T) {
	for _, mode := range []string{"unsigned_ready", "unsigned_started", "unsigned_result", "tampered_payload", "wrong_key", "signed_old_nonce"} {
		t.Run(mode, func(t *testing.T) {
			tr, c, j := transportFixture(t)
			j.Payload = []byte(mode)
			got := tr.Execute(context.Background(), c, j)
			if got.Result != "failed" || got.ErrorCode != "guest_response_invalid" || got.ExitCode != nil {
				t.Fatalf("forged guest evidence accepted: %+v", got)
			}
		})
	}
}

func TestTransportGuestDecoderRejectsAmbiguousEnvelopes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("host file safety is Linux-only")
	}
	inner := []byte(`{"schema_version":1}`)
	mac := hmac.New(sha256.New, []byte(transportTestResultKey))
	_, _ = mac.Write(inner)
	payload, signature := base64.StdEncoding.EncodeToString(inner), hex.EncodeToString(mac.Sum(nil))
	for _, frame := range []string{
		fmt.Sprintf(`{"payload":%q,"payload":%q,"signature":%q}`, payload, payload, signature),
		fmt.Sprintf(`{"payload":%q,"signature":%q,"signature":%q}`, payload, signature, signature),
		fmt.Sprintf(`{"Payload":%q,"signature":%q}`, payload, signature),
	} {
		path := filepath.Join(t.TempDir(), "ready.json")
		if e := os.WriteFile(path, []byte(frame), 0600); e != nil {
			t.Fatal(e)
		}
		var decoded map[string]any
		if _, e := transportDecodeGuest(path, 4096, []byte(transportTestResultKey), &decoded); e == nil {
			t.Fatal("ambiguous authentication envelope accepted")
		}
	}
}

func TestTransportRejectsInvalidGuestEvidence(t *testing.T) {
	for _, mode := range []string{"nonce", "digest", "oversize", "oversize_file", "malformed", "schema", "missing_output_flag", "nonzero_success", "null_success", "missing_ready", "missing_started", "wrong_sid", "admin", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			tr, c, j := transportFixture(t)
			j.Payload = []byte(mode)
			got := tr.Execute(context.Background(), c, j)
			if got.Result != "failed" || got.ExitCode != nil {
				t.Fatalf("unsafe guest result accepted: %+v", got)
			}
		})
	}
}

func TestTransportPreservesLargeWindowsExitCode(t *testing.T) {
	tr, c, j := transportFixture(t)
	j.Payload = []byte("large_exit")
	got := tr.Execute(context.Background(), c, j)
	if got.Result != "failed" || got.ExitCode == nil || *got.ExitCode != 3221225477 {
		t.Fatalf("Windows exit code lost: %+v", got)
	}
}

func TestTransportPreservesCorrelatedGuestTimeout(t *testing.T) {
	tr, c, j := transportFixture(t)
	j.Payload = []byte("timeout")
	got := tr.Execute(context.Background(), c, j)
	if got.Result != "timeout" || got.ExitCode != nil {
		t.Fatalf("guest timeout lost: %+v", got)
	}
}

func TestTransportRejectsSecretSymlinkAndWorkspaceSymlink(t *testing.T) {
	tr, c, j := transportFixture(t)
	secret := tr.cfg.Credentials[c.TargetID].PasswordFile
	if e := os.Rename(secret, secret+".real"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(secret+".real", secret); e != nil {
		t.Fatal(e)
	}
	if got := tr.Execute(context.Background(), c, j); got.Result != "failed" {
		t.Fatalf("secret symlink accepted: %+v", got)
	}
	if e := os.Remove(secret); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(secret+".real", secret); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(tr.cfg.WorkRoot, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(t.TempDir(), filepath.Join(tr.cfg.WorkRoot, j.ID)); e != nil {
		t.Fatal(e)
	}
	if got := tr.Execute(context.Background(), c, j); got.Result != "failed" {
		t.Fatalf("workspace symlink accepted: %+v", got)
	}
}

func TestTransportAllowsCorrelatedPrestartFailure(t *testing.T) {
	tr, c, j := transportFixture(t)
	j.Payload = []byte("prestart_failed")
	got := tr.Execute(context.Background(), c, j)
	if got.Result != "failed" || got.ErrorCode != "runner_rejected" {
		t.Fatalf("prestart failure lost: %+v", got)
	}
}

func TestTransportDisconnectIsNeverSuccess(t *testing.T) {
	tr, c, j := transportFixture(t)
	j.Payload = []byte("disconnect")
	got := tr.Execute(context.Background(), c, j)
	if got.Result != "unreachable" || got.ExitCode != nil {
		t.Fatalf("client exit treated as payload completion: %+v", got)
	}
}

func TestTransportExecutionCannotBeReused(t *testing.T) {
	tr, c, j := transportFixture(t)
	if got := tr.Execute(context.Background(), c, j); got.Result != "succeeded" {
		t.Fatal(got)
	}
	if got := tr.Execute(context.Background(), c, j); got.Result != "failed" {
		t.Fatalf("execution was reused: %+v", got)
	}
}

func TestTransportRejectsPasswordOutsideSecretBoundary(t *testing.T) {
	tr, c, j := transportFixture(t)
	for _, password := range []string{"bad\npassword", "bad\x00password", strings.Repeat("x", 4097)} {
		if err := os.WriteFile(tr.cfg.Credentials[c.TargetID].PasswordFile, []byte(password), 0600); err != nil {
			t.Fatal(err)
		}
		if got := tr.Execute(context.Background(), c, j); got.Result != "failed" {
			t.Fatalf("invalid password accepted: %+v", got)
		}
	}
}

func TestTransportResultKeyRequiresPrivateExact32Bytes(t *testing.T) {
	for _, mode := range []string{"short", "long", "public", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			tr, c, _ := transportFixture(t)
			keyPath := tr.cfg.Credentials[c.TargetID].ResultKeyFile
			switch mode {
			case "short":
				if e := os.WriteFile(keyPath, []byte(strings.Repeat("k", 31)), 0600); e != nil {
					t.Fatal(e)
				}
			case "long":
				if e := os.WriteFile(keyPath, []byte(strings.Repeat("k", 33)), 0600); e != nil {
					t.Fatal(e)
				}
			case "public":
				if e := os.Chmod(keyPath, 0644); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(keyPath, keyPath+".real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(keyPath+".real", keyPath); e != nil {
					t.Fatal(e)
				}
			}
			if e := tr.Validate(context.Background()); e == nil {
				t.Fatal("invalid result key file accepted")
			}
		})
	}
}

func TestTransportRereadsResultKeyForEachExecution(t *testing.T) {
	tr, c, j := transportFixture(t)
	if e := tr.Validate(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(tr.cfg.Credentials[c.TargetID].ResultKeyFile, []byte("short"), 0600); e != nil {
		t.Fatal(e)
	}
	got := tr.Execute(context.Background(), c, j)
	if got.Result != "failed" || got.ErrorCode != "result_key_invalid" {
		t.Fatalf("changed result key was not revalidated: %+v", got)
	}
	cred := tr.cfg.Credentials[c.TargetID]
	cred.ResultKeyFile = filepath.Join(tr.cfg.WorkRoot, "signing-key")
	bad := tr.cfg
	bad.Credentials = map[string]Credential{c.TargetID: cred}
	if _, e := NewFreeRDPTransport(bad); e == nil {
		t.Fatal("result signing key under work root accepted")
	}
}

func TestTransportSHA256PinAndStrictPathValidation(t *testing.T) {
	tr, c, j := transportFixture(t)
	cred := tr.cfg.Credentials[c.TargetID]
	cred.CertificateSHA256 = strings.Repeat("ab", 32)
	tr.cfg.Credentials[c.TargetID] = cred
	if got := tr.Execute(context.Background(), c, j); got.Result != "succeeded" {
		t.Fatal(got)
	}
	b, err := os.ReadFile(filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "observed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "/cert:deny,fingerprint:sha256:"+strings.Repeat("ab", 32)) {
		t.Fatal("preconfigured SHA256 pin was not supplied")
	}
	bad := tr.cfg
	bad.Credentials = map[string]Credential{c.TargetID: {PasswordFile: filepath.Join(tr.cfg.WorkRoot, "secret"), AccountSID: transportTestSID}}
	if _, err := NewFreeRDPTransport(bad); err == nil {
		t.Fatal("secret under work root accepted")
	}
	bad = tr.cfg
	bad.WorkRoot = "relative"
	if _, err := NewFreeRDPTransport(bad); err == nil {
		t.Fatal("relative work root accepted")
	}
}

func transportWaitFile(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, e := os.ReadFile(path); e == nil && len(b) > 0 {
			return b
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("helper did not publish %s", filepath.Base(path))
	return nil
}

func transportProcessLive(pid int) bool {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return false
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return true
	}
	return !strings.HasPrefix(strings.TrimSpace(string(b)[end+1:]), "Z ")
}

func transportAssertStopped(t *testing.T, pid int) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		if !transportProcessLive(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("owned descendant %d survived termination", pid)
}

func TestTransportTimeoutKillsOwnedProcessGroup(t *testing.T) {
	tr, c, j := transportFixture(t)
	j.Payload = []byte("hang")
	j.Timeout = 20 * time.Millisecond
	got := tr.Execute(context.Background(), c, j)
	if got.Result != "timeout" || got.ExitCode != nil || got.StartedAt == nil {
		t.Fatalf("wrong execution deadline outcome: %+v", got)
	}
	pidBytes := transportWaitFile(t, filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "child.pid"))
	pid, e := strconv.Atoi(string(pidBytes))
	if e != nil {
		t.Fatal(e)
	}
	transportAssertStopped(t, pid)
}

func TestTransportMissingRunnerHasConnectDeadline(t *testing.T) {
	tr, c, j := transportFixture(t)
	j.Payload = []byte("missing_runner")
	j.ConnectTimeout = 75 * time.Millisecond
	got := tr.Execute(context.Background(), c, j)
	if got.Result != "unreachable" || got.ErrorCode != "runner_unavailable" {
		t.Fatalf("missing runner misclassified: %+v", got)
	}
}

func TestTransportDisconnectKillsClientOrphans(t *testing.T) {
	tr, c, j := transportFixture(t)
	j.Payload = []byte("orphan")
	got := tr.Execute(context.Background(), c, j)
	if got.Result != "unreachable" {
		t.Fatalf("disconnected client outcome: %+v", got)
	}
	pidBytes := transportWaitFile(t, filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "child.pid"))
	pid, e := strconv.Atoi(string(pidBytes))
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if p, e := os.FindProcess(pid); e == nil {
			_ = p.Kill()
		}
	}()
	transportAssertStopped(t, pid)
}

func TestTransportRecoveryStopsMatchingOwnedProcessGroup(t *testing.T) {
	tr, c, j := transportFixture(t)
	j.Payload = []byte("hang")
	j.Timeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan Outcome, 1)
	go func() { result <- tr.Execute(ctx, c, j) }()
	pidBytes := transportWaitFile(t, filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "child.pid"))
	pid, e := strconv.Atoi(string(pidBytes))
	if e != nil {
		t.Fatal(e)
	}
	if e := tr.Recover(context.Background(), j.ID); e != nil {
		t.Fatal(e)
	}
	select {
	case got := <-result:
		if got.Result != "unreachable" {
			t.Fatalf("recovered session outcome: %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("recovered client remained running")
	}
	transportAssertStopped(t, pid)
}

func TestTransportRecoveryRefusesChangedPIDIdentity(t *testing.T) {
	tr, c, j := transportFixture(t)
	j.Payload = []byte("hang")
	j.Timeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan Outcome, 1)
	go func() { result <- tr.Execute(ctx, c, j) }()
	_ = transportWaitFile(t, filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "child.pid"))
	path := filepath.Join(tr.cfg.WorkRoot, j.ID, "control", "process.json")
	b := transportWaitFile(t, path)
	var identity map[string]any
	if e := json.Unmarshal(b, &identity); e != nil {
		t.Fatal(e)
	}
	pid := int(identity["pid"].(float64))
	identity["start_time"] = "0"
	changed, _ := json.Marshal(identity)
	if e := os.WriteFile(path, changed, 0600); e != nil {
		t.Fatal(e)
	}
	if e := tr.Recover(context.Background(), j.ID); e == nil {
		t.Fatal("changed process identity accepted")
	}
	if !transportProcessLive(pid) {
		t.Fatal("recovery killed a process with mismatched identity")
	}
	cancel()
	select {
	case <-result:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled client remained running")
	}
}

func TestTransportValidateRejectsFreeRDP2(t *testing.T) {
	tr, _, _ := transportFixture(t)
	exe, e := os.ReadFile(tr.cfg.ClientPath)
	if e != nil {
		t.Fatal(e)
	}
	client := filepath.Join(t.TempDir(), "freerdp-version2")
	if e := os.WriteFile(client, exe, 0700); e != nil {
		t.Fatal(e)
	}
	tr.cfg.ClientPath = client
	if e := tr.Validate(context.Background()); e == nil {
		t.Fatal("FreeRDP 2 accepted")
	}
}
