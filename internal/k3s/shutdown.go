package k3s

import "github.com/MSG-CTF/secure-provisioner/internal/isolation"

func reviewedShutdownCommand(strategy isolation.ShutdownStrategy) []string {
	var program string
	switch strategy {
	case isolation.ShutdownStrategyPythonSIGINTPID1:
		// Keep the existing hook byte-for-byte compatible with live workloads.
		program = "import os, signal; os.kill(1, signal.SIGINT)"
	case isolation.ShutdownStrategyPythonSIGINTChild:
		program = pythonChildShutdownProgram
	default:
		return nil
	}
	return []string{"/usr/local/bin/python3", "-I", "-B", "-c", program}
}

// Only an operator-approved WEB image can opt into this fixed program.
// Ambiguous processes, unsupported pidfds, and exit races leave normal grace handling intact.
const pythonChildShutdownProgram = `import os
import re
import signal
from pathlib import Path


def process_info(path):
    fields = (path / "stat").read_text().rpartition(") ")[2].split()
    executable = Path(os.readlink(path / "exe")).name
    return {
        "parent": int(fields[1]),
        "start": fields[19],
        "python": re.fullmatch(r"python(?:[0-9]+(?:\.[0-9]+)*)?", executable) is not None,
        "uid": path.stat().st_uid,
    }


def interrupt_child(proc):
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return False
    me = os.getpid()
    processes = {}
    for path in proc.iterdir():
        if not path.name.isdigit():
            continue
        try:
            processes[int(path.name)] = process_info(path)
        except (OSError, ValueError, IndexError):
            continue

    roots = []
    for pid, info in processes.items():
        if pid in (1, me) or not info["python"] or info["uid"] != os.geteuid():
            continue
        parent = info["parent"]
        visited = {pid}
        python_parent = False
        while parent and parent not in visited and parent in processes:
            visited.add(parent)
            if parent == 1:
                if not python_parent and not processes[parent]["python"]:
                    roots.append(pid)
                break
            python_parent |= processes[parent]["python"]
            parent = processes[parent]["parent"]
    if len(roots) != 1:
        return False

    pid = roots[0]
    descriptor = os.pidfd_open(pid, 0)
    try:
        current = process_info(proc / str(pid))
        if (current["start"] != processes[pid]["start"]
                or current["uid"] != os.geteuid() or not current["python"]):
            return False
        signal.pidfd_send_signal(descriptor, signal.SIGINT, None, 0)
        return True
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        interrupt_child(Path("/proc"))
    except (OSError, ValueError, IndexError):
        pass
`
