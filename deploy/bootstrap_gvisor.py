#!/usr/bin/env python3
"""Install the reviewed gVisor bundle on an idle, single-node K3s target.

Run as root with Python 3.12+. This never advertises a Runtime capability:
an actual sandbox smoke test must pass before updating the target registry.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = "20261012.0"
URL = f"https://storage.googleapis.com/gvisor/releases/release/{VERSION}/x86_64/gvisor.tar.bz2"
SHA512 = "9606445eed5aedfcf05310e7ccef61d994089914c6622fc82624c24d2b18db1b2210f40e40a7be27b8b7772859de7d95c501b4eba66423053c960bf671377c5e"
CONTAINERD = """[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
"""
RUNSC = '[runsc_config]\n  platform = "systrap"\n  systemd-cgroup = "true"\n'


def kube(*args, body=None):
    return subprocess.check_output(
        ["k3s", "kubectl", *args],
        input=json.dumps(body).encode() if body else None,
        timeout=110 if args and args[0] == "wait" else 40,
    )


def check_idle(pods):
    if any(p["metadata"]["namespace"].startswith("ctf-") for p in pods):
        raise RuntimeError("Delete challenge workloads before restarting K3s")


def write_reviewed_file(target, data, mode):
    if target.is_symlink():
        raise RuntimeError(f"Refusing a symlink: {target}")
    if target.exists():
        if target.read_bytes() != data:
            raise RuntimeError(f"An existing file differs; review it first: {target}")
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(mode)
    return True


def main():
    if os.geteuid() != 0 or os.uname().machine != "x86_64":
        raise RuntimeError("This reviewed installer requires root on Linux x86_64")
    check_idle(json.loads(kube("get", "pods", "-A", "-o", "json"))["items"])
    config = Path("/var/lib/rancher/k3s/agent/etc/containerd/config.toml")
    if 'config-v3.toml.d/*.toml' not in config.read_text():
        raise RuntimeError("K3s must support containerd v3 configuration drop-ins")
    changed = False
    with tempfile.TemporaryDirectory(prefix="msgctf-gvisor-") as folder:
        root = Path(folder)
        with urllib.request.urlopen(URL, timeout=60) as response:
            contents = response.read(250 * 1024 * 1024)
        if hashlib.sha512(contents).hexdigest() != SHA512:
            raise RuntimeError("gVisor archive checksum mismatch")
        bundle = root / "gvisor.tar.bz2"
        bundle.write_bytes(contents)
        unpacked = root / "bundle"
        with tarfile.open(bundle, "r:bz2") as archive:
            archive.extractall(unpacked, filter="data")
        for name in ["runsc", "containerd-shim-runsc-v1", "gvisor-bin"]:
            if not (unpacked / name).exists():
                raise RuntimeError(f"gVisor bundle is missing {name}")
        files = [p for p in unpacked.rglob("*") if p.is_file()]
        for source in files:
            relative = source.relative_to(unpacked)
            if relative.parts[0] not in ["runsc", "containerd-shim-runsc-v1", "gvisor-bin"]:
                continue
            changed |= write_reviewed_file(Path("/usr/local/bin") / relative, source.read_bytes(), 0o755)
    changed |= write_reviewed_file(config.parent / "config-v3.toml.d/20-gvisor.toml", CONTAINERD.encode(), 0o644)
    changed |= write_reviewed_file(Path("/etc/containerd/runsc.toml"), RUNSC.encode(), 0o644)
    if changed:
        subprocess.run(["systemctl", "restart", "k3s"], check=True, timeout=120)
    kube("wait", "--for=condition=Ready", "nodes", "--all", "--timeout=90s")
    runtime_class = {"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass", "metadata": {"name": "gvisor"}, "handler": "runsc"}
    kube("apply", "-f", "-", body=runtime_class)
    print(json.dumps({"version": VERSION, "changed": changed, "runtime_class": "gvisor", "registry_advertised": False}))


if __name__ == "__main__":
    main()
