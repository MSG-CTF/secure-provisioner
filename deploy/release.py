#!/usr/bin/env python3
"""Fixed server-side deployment entry point; accepts only a data-only release bundle."""
import contextlib
import fcntl
import grp
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

MAX_BUNDLE_BYTES = 256 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")
CONFIG = {
    "scheduler": {"service": "mjsec-scheduler", "artifact": "/opt/msgctf-scheduler/scheduler.jar", "env": "/etc/default/mjsec-scheduler", "marker": "/opt/msgctf-scheduler/release.json", "group": "root", "mode": 0o644},
    "runtime": {"service": "secure-provisioner", "artifact": "/opt/secure-provisioner/secure-provisioner", "env": "/etc/secure-provisioner/provisioner.env", "marker": "/opt/secure-provisioner/release.json", "group": "provisioner", "mode": 0o755},
}

class DeploymentError(Exception):
    pass

def environment_values(raw):
    if len(raw) > 65536 or b"\0" in raw:
        raise DeploymentError("invalid environment")
    result = {}
    for line in raw.decode("utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if not match or match[1] in result or not match[1].startswith(("SCHEDULER_", "SPRING_", "SERVER_", "PROVISIONER_")):
            raise DeploymentError("unsupported environment entry")
        values = shlex.split(match[2], comments=False)
        if len(values) > 1:
            raise DeploymentError("unquoted environment value")
        result[match[1]] = values[0] if values else ""
    return result

def read_bundle(stream, component):
    names = {"release.json", "artifact", "app.env"}
    if component == "runtime":
        names.add("service-token")
    files = {}
    total = 0
    with tarfile.open(fileobj=stream, mode="r|gz") as archive:
        for member in archive:
            if member.name not in names or member.name in files or not member.isfile():
                raise DeploymentError("unexpected bundle entry")
            total += member.size
            if total > MAX_BUNDLE_BYTES or member.size < 0:
                raise DeploymentError("bundle too large")
            if member.name != "artifact" and member.size > 65536:
                raise DeploymentError("configuration too large")
            with archive.extractfile(member) as entry:
                files[member.name] = entry.read(member.size + 1)
            if len(files[member.name]) != member.size:
                raise DeploymentError("truncated bundle")
    if set(files) != names or not files["artifact"]:
        raise DeploymentError("missing bundle entry")
    manifest = json.loads(files["release.json"])
    if manifest.get("component") != component or not SHA.fullmatch(manifest.get("source_sha", "")):
        raise DeploymentError("invalid release identity")
    for name in names - {"release.json"}:
        if manifest.get("checksums", {}).get(name) != hashlib.sha256(files[name]).hexdigest():
            raise DeploymentError("bundle checksum mismatch")
    values = environment_values(files["app.env"])
    if component == "scheduler":
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", values.get("SCHEDULER_API_TOKEN", "")):
            raise DeploymentError("scheduler API token is missing")
        if values.get("SPRING_DOCKER_COMPOSE_ENABLED") != "false" or values.get("SPRING_PROFILES_ACTIVE") != "dev":
            raise DeploymentError("server profile must use managed dependencies")
        required = ("SPRING_DATASOURCE_URL", "SPRING_DATASOURCE_USERNAME", "SPRING_DATASOURCE_PASSWORD", "SPRING_DATA_REDIS_HOST", "SPRING_DATA_REDIS_PORT")
        if not all(values.get(key) for key in required):
            raise DeploymentError("database and Redis configuration is required")
    else:
        if not re.fullmatch(rb"[A-Za-z0-9_-]{43,128}\n?", files["service-token"]):
            raise DeploymentError("invalid runtime service token")
        if values.get("PROVISIONER_SERVICE_TOKEN_FILE") != "/etc/secure-provisioner/service-token" or values.get("PROVISIONER_SERVICE_TOKEN"):
            raise DeploymentError("runtime token file contract mismatch")
        if values.get("PROVISIONER_IMAGE_POLICIES") != "/etc/secure-provisioner/image-policies.json":
            raise DeploymentError("runtime image policy path changed")
    return manifest, files, values

def atomic_write(path, data, mode, gid=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise DeploymentError("deployment target must not be a symlink")
    descriptor, temporary = tempfile.mkstemp(prefix=".deploy-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
            os.fchmod(file.fileno(), mode)
            if os.geteuid() == 0:
                os.fchown(file.fileno(), 0, gid)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)

class SystemService:
    def reload(self):
        subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True, timeout=30)

    def restart(self, service):
        subprocess.run(["systemctl", "restart", service], check=True, capture_output=True, timeout=120)

    def active(self, service):
        return subprocess.run(["systemctl", "is-active", "--quiet", service], capture_output=True, timeout=10).returncode == 0

    def request(self, path, token=None):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args):
                return None
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request("http://127.0.0.1:8080" + path, headers=headers)
        try:
            response = urllib.request.build_opener(NoRedirect()).open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(1024 * 1024)
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                value = None
            return response.code, value

def verify(component, config, values, token, service, attempts=45, delay=2):
    for attempt in range(attempts):
        try:
            if service.active(config["service"]):
                if component == "scheduler":
                    code, health = service.request("/actuator/health")
                    code2, page = service.request("/api/instances?limit=1", token)
                    valid = code == 200 and isinstance(health, dict) and health.get("status") == "UP" and code2 == 200 and isinstance(page, dict) and page.get("code") == "SUCCESS" and isinstance(page.get("data"), dict) and isinstance(page["data"].get("items"), list) and "next_cursor" in page["data"]
                    path = "/api/instances?limit=1"
                else:
                    path = "/internal/v1/operations/ci-deployment-healthcheck"
                    code, body = service.request(path, token)
                    valid = code == 404 and isinstance(body, dict) and body.get("error", {}).get("code") == "OPERATION_NOT_FOUND"
                if valid and service.request(path)[0] == 401 and service.request(path, "invalid-deployment-credential")[0] == 401:
                    return
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        if attempt + 1 < attempts:
            time.sleep(delay)
    raise DeploymentError("service verification failed")

def deploy(component, stream, root=Path("/"), service=None, attempts=45, delay=2):
    if component not in CONFIG:
        raise DeploymentError("unknown component")
    service = service or SystemService()
    config = CONFIG[component]
    path = lambda name: root / name.lstrip("/")
    state = path("/var/lib/msgctf-deploy/" + component)
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    with (state / "deploy.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DeploymentError("deployment already running") from error
        manifest, files, values = read_bundle(stream, component)
        artifact, env, marker = (path(config[key]) for key in ("artifact", "env", "marker"))
        artifact.parent.mkdir(parents=True, exist_ok=True)
        if artifact.parent.is_symlink():
            raise DeploymentError("artifact directory must not be a symlink")
        artifact.parent.chmod(0o755)
        entries = [(artifact, files["artifact"], config["mode"], 0), (env, files["app.env"], 0o600, 0)]
        token = values.get("SCHEDULER_API_TOKEN")
        if component == "runtime":
            gid = grp.getgrnam(config["group"]).gr_gid if root == Path("/") else os.getgid()
            entries[1] = (env, files["app.env"], 0o640, gid)
            entries.append((path("/etc/secure-provisioner/service-token"), files["service-token"], 0o640, gid))
            token = files["service-token"].decode().strip()
        else:
            dropin = b"[Service]\nExecStart=\nExecStart=/opt/temurin-24/bin/java -jar /opt/msgctf-scheduler/scheduler.jar\n"
            entries.append((path("/etc/systemd/system/mjsec-scheduler.service.d/60-ci-artifact.conf"), dropin, 0o644, 0))
        entries.append((marker, (json.dumps({"source_commit": manifest["source_sha"], "artifact_sha256": manifest["checksums"]["artifact"], "component": component, "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}) + "\n").encode(), 0o644, 0))
        with tempfile.TemporaryDirectory(prefix="transaction-", dir=state) as temporary:
            backup = Path(temporary)
            snapshots = []
            for index, (target, _, _, _) in enumerate(entries):
                if target.is_symlink() or (target.exists() and not target.is_file()):
                    raise DeploymentError("unsafe deployment target")
                saved = backup / str(index)
                stat = target.stat() if target.exists() else None
                if stat:
                    shutil.copy2(target, saved)
                snapshots.append((target, saved, stat))
            try:
                for target, data, mode, gid in entries:
                    atomic_write(target, data, mode, gid)
                service.reload()
                service.restart(config["service"])
                verify(component, config, values, token, service, attempts, delay)
            except BaseException:
                for target, saved, stat in snapshots:
                    if stat:
                        atomic_write(target, saved.read_bytes(), stat.st_mode & 0o777, stat.st_gid)
                    else:
                        target.unlink(missing_ok=True)
                service.reload()
                service.restart(config["service"])
                old_values = environment_values(env.read_bytes())
                old_token = old_values.get("SCHEDULER_API_TOKEN") if component == "scheduler" else path("/etc/secure-provisioner/service-token").read_text().strip()
                verify(component, config, old_values, old_token, service, attempts, delay)
                print("ROLLBACK_RESULT=" + json.dumps({"component": component, "status": "verified"}))
                raise DeploymentError("deployment failed; previous service verified") from None
        return {"component": component, "source_commit": manifest["source_sha"], "artifact_sha256": manifest["checksums"]["artifact"], "status": "verified", "authentication_verified": True}

def main():
    os.umask(0o077)
    if len(sys.argv) != 2 or sys.argv[1] not in CONFIG or os.geteuid() != 0:
        raise SystemExit(2)
    def interrupted(*_):
        raise DeploymentError("deployment interrupted")
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(number, interrupted)
    try:
        result = deploy(sys.argv[1], sys.stdin.buffer)
        print("DEPLOYMENT_RESULT=" + json.dumps(result))
    except Exception as error:
        print("Deployment did not pass verification (" + type(error).__name__ + ")", file=sys.stderr)
        raise SystemExit(1) from None

if __name__ == "__main__":
    main()
