//go:build linux

package windowsruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Every path component is opened without following links. In particular, guest
// files never resolve symlinks out of their one redirected share.
func transportParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, "", errors.New("unclean path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, "", e
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

func transportReadFile(path string, max int, private bool) ([]byte, error) {
	fd, name, err := transportParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	n, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(n), name)
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(n, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 0 || st.Size > int64(max) || private && (st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("file boundary rejected")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(b) > max {
		return nil, errors.New("file size rejected")
	}
	return b, nil
}

func transportWriteFile(path string, data []byte) error {
	fd, name, err := transportParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	n, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(n), name)
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func transportMkdirExclusive(path string) error {
	fd, name, err := transportParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.Mkdirat(fd, name, 0700); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func transportMkdirAll(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("invalid root")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if err = unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			unix.Close(fd)
			return err
		}
		n, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return e
		}
		fd = n
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
		return errors.New("work root must be owned and private")
	}
	return nil
}

type transportLimitedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *transportLimitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 4096 - b.Len()
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
func transportProbeVersion(ctx context.Context, path string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, "/version")
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	var output transportLimitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if output.overflow {
		return nil, errors.New("version output too large")
	}
	return output.Bytes(), nil
}

type transportProcessIdentity struct {
	SchemaVersion int    `json:"schema_version"`
	ExecutionID   string `json:"execution_id"`
	PID           int    `json:"pid"`
	PGID          int    `json:"pgid"`
	StartTime     string `json:"start_time"`
	BootID        string `json:"boot_id"`
	UID           uint32 `json:"uid"`
}
type transportOwnedProcess struct {
	cmd      *exec.Cmd
	identity transportProcessIdentity
	done     chan struct{}
}

func transportProcIdentity(pid int) (transportProcessIdentity, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return transportProcessIdentity{}, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return transportProcessIdentity{}, errors.New("invalid proc stat")
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) < 20 {
		return transportProcessIdentity{}, errors.New("invalid proc stat")
	}
	pgid, err := strconv.Atoi(fields[2])
	if err != nil {
		return transportProcessIdentity{}, err
	}
	var st unix.Stat_t
	if err = unix.Stat(fmt.Sprintf("/proc/%d", pid), &st); err != nil {
		return transportProcessIdentity{}, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return transportProcessIdentity{}, err
	}
	return transportProcessIdentity{SchemaVersion: 1, PID: pid, PGID: pgid, StartTime: fields[19], BootID: strings.TrimSpace(string(boot)), UID: st.Uid}, nil
}

func transportStartProcess(control, id, path string, args, env []string, input []byte) (*transportOwnedProcess, error) {
	// The gate cannot start RDP until its identity has reached durable private
	// storage. If the service dies first, EOF on stdin makes the gate exit.
	// Keep the verified group leader alive while the client runs. On client
	// exit the leader kills its own group, so an orphaned Xvfb/client descendant
	// cannot outlive the identity required by restart recovery.
	gate := `IFS= read -r runtime_gate; [ "$runtime_gate" = go ] || exit 126; trap 'kill -KILL -$$' EXIT HUP INT TERM; exec 3<&0; "$@" <&3 3<&- & runtime_child=$!; exec 3<&-; wait "$runtime_child"`
	argv := append([]string{"-c", gate, "runtime-rdp", path}, args...)
	cmd := exec.Command("/bin/sh", argv...)
	cmd.Dir = control
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdin = r
	if err = cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return nil, err
	}
	r.Close()
	proc := &transportOwnedProcess{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(proc.done) }()
	identity, err := transportProcIdentity(cmd.Process.Pid)
	if err == nil {
		identity.ExecutionID = id
		proc.identity = identity
		var b []byte
		b, err = json.Marshal(identity)
		if err == nil {
			err = transportWriteFile(filepath.Join(control, "process.json"), b)
		}
	}
	if err != nil {
		w.Close()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		proc.wait()
		return nil, err
	}
	gateInput := append([]byte("go\n"), input...)
	_, err = w.Write(gateInput)
	clear(gateInput)
	w.Close()
	if err != nil {
		_ = proc.stop()
		proc.wait()
		return nil, err
	}
	return proc, nil
}

func transportStopIdentity(expected transportProcessIdentity) error {
	if expected.SchemaVersion != 1 || expected.PID <= 1 || expected.PGID != expected.PID || expected.StartTime == "" || expected.BootID == "" || expected.UID != uint32(os.Geteuid()) {
		return errors.New("invalid RDP process owner")
	}
	actual, err := transportProcIdentity(expected.PID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return err
	}
	if actual.PGID != expected.PGID || actual.StartTime != expected.StartTime || actual.BootID != expected.BootID || actual.UID != expected.UID {
		return errors.New("RDP process identity changed")
	}
	if err = syscall.Kill(-expected.PGID, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
func (p *transportOwnedProcess) stop() error { return transportStopIdentity(p.identity) }
func (p *transportOwnedProcess) wait() {
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
	}
}
func transportRecoverProcess(ctx context.Context, control, id string) error {
	var identity transportProcessIdentity
	present, err := transportDecode(filepath.Join(control, "process.json"), 4096, &identity)
	if err != nil {
		return errors.New("RDP process ownership file invalid")
	}
	if !present {
		return nil
	}
	if identity.ExecutionID != id {
		return errors.New("RDP process execution ID mismatch")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return transportStopIdentity(identity)
}
