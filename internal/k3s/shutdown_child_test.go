package k3s

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestReviewedPythonChildHookPreservesExecutionAndIsolation(t *testing.T) {
	baseline, err := BuildResourceSet(validCluster("aws-dev"), shutdownCommand(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	approved, err := BuildResourceSet(validCluster("aws-dev"), shutdownCommand(t, "python_sigint_child"))
	if err != nil {
		t.Fatal(err)
	}
	pod := approved.Deployment.Spec.Template.Spec.DeepCopy()
	hook := pod.Containers[0].Lifecycle.PreStop.Exec.Command
	want := []string{"/usr/local/bin/python3", "-I", "-B", "-c", pythonChildShutdownProgram}
	if !reflect.DeepEqual(hook, want) {
		t.Fatal("child shutdown did not render its fixed operator-approved program")
	}
	pod.Containers[0].Lifecycle = nil
	if !reflect.DeepEqual(*pod, baseline.Deployment.Spec.Template.Spec) {
		t.Fatal("child shutdown changed the image, command, environment, resources, or isolation")
	}
	if approved.ExpectedSpecHash == baseline.ExpectedSpecHash {
		t.Fatal("shutdown choice was not retained in the resource identity")
	}
}

// Execute the actual fixed program against a private proc fixture. pidfd and signal
// calls are captured, so this test never inspects or signals host processes.
const childShutdownDriver = `import json, os, signal, sys, tempfile
from pathlib import Path
from unittest.mock import patch

data = json.load(sys.stdin)
scope = {"__name__": "shutdown_test"}
exec(data["program"], scope)
out = {"signalled": False, "opened": [], "closed": [], "signals": []}
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    processes = {
        1: (0, "/bin/sh"),
        10: (1, "/usr/local/bin/python3.12"),
        11: (10, "/usr/local/bin/python3.12"),
        99: (1, "/usr/local/bin/python3.12"),
    }
    case = data["case"]
    if case == "ambiguous":
        processes[20] = (1, "/usr/bin/python3")
    if case == "python_init":
        processes[1] = (0, "/usr/local/bin/python3.12")
    if case == "non_python":
        processes[10] = (1, "/usr/local/bin/node")
        processes.pop(11)
    if case == "cycle":
        processes[10] = (10, "/usr/local/bin/python3.12")
    def write_stat(pid, parent, start="12345"):
        fields = ["S", str(parent)] + ["0"] * 17 + [start]
        (root / str(pid) / "stat").write_text(str(pid) + " (worker (test)) " + " ".join(fields))
    for pid, (parent, executable) in processes.items():
        path = root / str(pid)
        path.mkdir()
        write_stat(pid, parent)
        (path / "exe").symlink_to(executable)
    real_info = scope["process_info"]
    def info(path):
        value = real_info(path)
        if case == "foreign_uid" and path.name == "10":
            value["uid"] += 1
        return value
    scope["process_info"] = info
    def open_pidfd(pid, flags):
        out["opened"].append(pid)
        if case == "exited":
            raise ProcessLookupError()
        if case == "reused_pid":
            write_stat(pid, processes[pid][0], "99999")
        if case == "exec_changed":
            (root / str(pid) / "exe").unlink()
            (root / str(pid) / "exe").symlink_to("/bin/sh")
        return 321
    def send(descriptor, signum, info, flags):
        out["signals"].append([descriptor, signum, flags])
    with patch.object(os, "getpid", return_value=99), patch.object(os, "pidfd_open", side_effect=open_pidfd), patch.object(os, "close", side_effect=out["closed"].append), patch.object(signal, "pidfd_send_signal", side_effect=send):
        try:
            out["signalled"] = scope["interrupt_child"](root)
        except (OSError, ValueError, IndexError):
            pass
print(json.dumps(out))
`

func TestPythonChildSignalGuardsAndPIDGeneration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("proc and pidfd contract is exercised on Linux")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python 3 is needed to execute the reviewed lifecycle program")
	}
	for _, test := range []struct {
		name      string
		opened    []int
		closed    []int
		signalled bool
	}{
		{"main_with_nested_worker", []int{10}, []int{321}, true},
		{"ambiguous", []int{}, []int{}, false},
		{"python_init", []int{}, []int{}, false},
		{"non_python", []int{}, []int{}, false},
		{"foreign_uid", []int{}, []int{}, false},
		{"cycle", []int{}, []int{}, false},
		{"reused_pid", []int{10}, []int{321}, false},
		{"exec_changed", []int{10}, []int{321}, false},
		{"exited", []int{10}, []int{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, err := json.Marshal(map[string]string{"program": pythonChildShutdownProgram, "case": test.name})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, python, "-I", "-B", "-c", childShutdownDriver)
			command.Stdin = bytes.NewReader(input)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("reviewed program fixture: %v: %s", err, output)
			}
			var result struct {
				Signalled bool    `json:"signalled"`
				Opened    []int   `json:"opened"`
				Closed    []int   `json:"closed"`
				Signals   [][]int `json:"signals"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("invalid fixture result: %v: %s", err, output)
			}
			if result.Signalled != test.signalled || !reflect.DeepEqual(result.Opened, test.opened) || !reflect.DeepEqual(result.Closed, test.closed) {
				t.Fatalf("unsafe or missing signal: %+v", result)
			}
			if test.signalled {
				if !reflect.DeepEqual(result.Signals, [][]int{{321, 2, 0}}) {
					t.Fatalf("expected one SIGINT through the pinned pidfd, got %+v", result.Signals)
				}
			} else if len(result.Signals) != 0 {
				t.Fatal("unsafe process received a signal")
			}
		})
	}
}
