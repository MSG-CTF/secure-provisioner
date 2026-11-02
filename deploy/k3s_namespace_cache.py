"""Opt-in watch-cache profile for the reviewed SQLite K3s execution nodes."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

DROPIN_NAME = "zz-msgctf-namespace-cache.yaml"
DROPIN = b"# Managed by MSG CTF k3s_namespace_cache.py\nkube-apiserver-arg+:\n  - watch-cache=false\n"
BASE = {"watch_cache": True}
TUNED = {"watch_cache": False}
REVIEWED_VERSION = "v1.36.4+k3s1"



class Refused(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def cache_profile(log):
    if "Running kube-apiserver" not in log:
        raise Refused("cannot verify the running apiserver flags")
    flags = re.findall(r"--watch-cache=([a-z]+)", log)
    if len(flags) > 1 or (flags and flags[0] not in ["true", "false"]):
        raise Refused("ambiguous apiserver cache flags")
    return {"watch_cache": flags != ["false"]}


def validate_node(nodes, namespaces, expected):
    if len(nodes) != 1 or nodes[0]["metadata"]["uid"] != expected:
        raise Refused("expected a single node with the reviewed Node UID")
    if not any(c["type"] == "Ready" and c["status"] == "True" for c in nodes[0]["status"]["conditions"]):
        raise Refused("node is not Ready")
    if any(n["metadata"]["name"].startswith("ctf-") for n in namespaces):
        raise Refused("challenge namespace still exists; drain and finish cleanup first")


class System:
    def run(self, args, timeout=12):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise Refused("node command failed: " + args[0])
        return result.stdout

    def snapshot(self, expected):
        base = ["k3s", "kubectl", "--request-timeout=8s"]
        nodes = json.loads(self.run(base + ["get", "nodes", "-o", "json"]))["items"]
        namespaces = json.loads(self.run(base + ["get", "namespaces", "-o", "json"]))["items"]
        validate_node(nodes, namespaces, expected)
        if nodes[0]["status"]["nodeInfo"]["kubeletVersion"] != REVIEWED_VERSION:
            raise Refused("only the reviewed K3s version is supported")
        log = self.run(["journalctl", "-u", "k3s", "--no-pager", "-g", "Running kube-apiserver", "-n", "1", "-o", "cat"])
        return cache_profile(log)

    def check_config_source(self):
        pid = self.run(["systemctl", "show", "k3s", "--property=MainPID", "--value"]).strip()
        arguments = Path("/proc", pid, "cmdline").read_bytes().split(b"\0")
        environment = dict(p.split(b"=", 1) for p in Path("/proc", pid, "environ").read_bytes().split(b"\0") if b"=" in p)
        keys = [b"K3S_CONFIG_FILE", b"K3S_KUBE_APISERVER_ARG", b"K3S_DATASTORE_ENDPOINT", b"K3S_CLUSTER_INIT"]
        if any(environment.get(key) for key in keys):
            raise Refused("custom API, datastore or config environment requires review")
        flags = [b"--config", b"--kube-apiserver-arg", b"--datastore-endpoint", b"--cluster-init", b"--server"]
        if any(a == flag or a.startswith(flag + b"=") for a in arguments for flag in flags):
            raise Refused("custom API, datastore or config CLI arguments require review")
        database = Path("/var/lib/rancher/k3s/server/db/state.db")
        if database.is_symlink() or not database.is_file() or Path("/var/lib/rancher/k3s/server/db/etcd/member").exists():
            raise Refused("only the reviewed SQLite single-node datastore is supported")

    def restart(self):
        self.run(["systemctl", "restart", "k3s"], timeout=45)

    def wait(self, expected, budget):
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            try:
                if self.snapshot(expected) == budget:
                    return
            except (Refused, subprocess.TimeoutExpired, KeyError, ValueError):
                pass
            time.sleep(1)
        raise Refused("K3s did not recover the same Node UID and expected apiserver cache profile")


class Tuning:
    def __init__(self, expected, config_root=Path("/etc/rancher/k3s"), state_root=Path("/var/lib/msgctf-k3s-cache-profile"), system=None):
        self.expected = str(uuid.UUID(expected))
        self.root = config_root
        self.path = config_root / "config.yaml.d" / DROPIN_NAME
        self.state_path = state_root / (self.expected + ".json")
        self.system = system or System()

    def config_hashes(self):
        paths = [self.root / "config.yaml"] + sorted((self.root / "config.yaml.d").glob("*.yaml"))
        result = {}
        for path in paths:
            if path == self.path or not path.exists():
                continue
            if path.is_symlink() or not path.is_file():
                raise Refused("config path is not a regular file")
            content = path.read_bytes()
            if b"watch-cache" in content or b"datastore-endpoint" in content or b"cluster-init" in content:
                raise Refused("existing cache or datastore overrides require manual review")
            result[str(path)] = digest(content)
        return result

    def atomic(self, path, data):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink():
            raise Refused("owned output path is a symlink")
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".msgctf-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            temporary.chmod(0o600)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def save(self, state):
        self.atomic(self.state_path, json.dumps(state, sort_keys=True).encode())

    def plan(self):
        self.system.check_config_source()
        if self.root.is_symlink() or self.path.parent.is_symlink() or self.state_path.parent.is_symlink():
            raise Refused("config or checkpoint directory is a symlink")
        if self.path.exists() or self.path.is_symlink() or self.state_path.exists() or self.state_path.is_symlink():
            raise Refused("owned tuning/checkpoint already exists; inspect or restore first")
        before = self.config_hashes()
        if self.system.snapshot(self.expected) != BASE:
            raise Refused("apiserver does not have the reviewed default watch-cache baseline")
        return {"node_uid": self.expected, "before_config_hashes": before, "baseline": BASE,
                "target": TUNED, "candidate_sha256": digest(DROPIN), "phase": "planned"}

    def unchanged(self, state):
        if state["node_uid"] != self.expected or self.config_hashes() != state["before_config_hashes"]:
            raise Refused("node identity or another config file changed")

    def apply(self):
        state = self.plan()
        state["phase"] = "prepared"
        self.save(state)
        self.atomic(self.path, DROPIN)
        restarted = False
        try:
            self.unchanged(state)
            if self.system.snapshot(self.expected) != BASE:
                raise Refused("node state changed before restart")
            restarted = True
            self.system.restart()
            self.system.wait(self.expected, TUNED)
            self.unchanged(state)
        except Exception:
            if self.path.is_file() and not self.path.is_symlink() and self.path.read_bytes() == DROPIN:
                self.unchanged(state)
                if restarted:
                    self.system.snapshot(self.expected)
                self.path.unlink()
                if restarted:
                    self.system.restart()
                    self.system.wait(self.expected, BASE)
                state["phase"] = "automatically_restored" if restarted else "withdrawn_before_restart"
                self.save(state)
            raise
        state["phase"] = "applied_verified"
        self.save(state)
        return state

    def restore(self):
        if self.state_path.is_symlink():
            raise Refused("checkpoint path is a symlink")
        state = json.loads(self.state_path.read_text())
        self.system.check_config_source()
        self.unchanged(state)
        if state["phase"] not in ["applied_verified", "prepared"] or self.path.is_symlink() or self.path.read_bytes() != DROPIN:
            raise Refused("owned drop-in changed or checkpoint is not restorable")
        current = self.system.snapshot(self.expected)
        if current not in [BASE, TUNED]:
            raise Refused("unexpected live cache profile")
        self.path.unlink()
        self.system.restart()
        self.system.wait(self.expected, BASE)
        self.unchanged(state)
        state["phase"] = "restored_verified"
        self.save(state)
        return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["plan", "apply", "restore"])
    parser.add_argument("--expected-node-uid", required=True)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise Refused("run as root on the reviewed Linux K3s execution node")
    import fcntl
    tuning = Tuning(args.expected_node_uid)
    if args.mode == "plan":
        print(json.dumps(tuning.plan()))
        return
    directory = tuning.state_path.parent
    if directory.is_symlink():
        raise Refused("checkpoint directory is a symlink")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = directory / (tuning.expected + ".lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Refused("another node-profile operation is running") from error
        print(json.dumps(getattr(tuning, args.mode)()))



if __name__ == "__main__":
    main()
