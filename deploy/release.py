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
import selectors
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
RUNTIME_STRATEGY = "runtime_api_bridge_v1"
RUNTIME_BRIDGE = "secure-provisioner-bridge"
RUNTIME_UPSTREAM = "/etc/nginx/snippets/msgctf-runtime-upstream.conf"
PRIMARY_PROXY = b"proxy_pass http://127.0.0.1:8080;\n"
CONFIG = {
    "scheduler": {
        "service": "mjsec-scheduler",
        "artifact": "/opt/msgctf-scheduler/scheduler.jar",
        "env": "/etc/default/mjsec-scheduler",
        "marker": "/opt/msgctf-scheduler/release.json",
        "group": "root",
        "mode": 0o644,
    },
    "runtime": {
        "service": "secure-provisioner",
        "artifact": "/opt/secure-provisioner/secure-provisioner",
        "env": "/etc/secure-provisioner/provisioner.env",
        "marker": "/opt/secure-provisioner/release.json",
        "group": "provisioner",
        "mode": 0o755,
    },
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
        if (
            not match
            or match[1] in result
            or not match[1].startswith(
                ("SCHEDULER_", "SPRING_", "SERVER_", "PROVISIONER_")
            )
        ):
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
    if manifest.get("component") != component or not SHA.fullmatch(
        manifest.get("source_sha", "")
    ):
        raise DeploymentError("invalid release identity")
    for name in names - {"release.json"}:
        if (
            manifest.get("checksums", {}).get(name)
            != hashlib.sha256(files[name]).hexdigest()
        ):
            raise DeploymentError("bundle checksum mismatch")
    values = environment_values(files["app.env"])
    if component == "scheduler":
        if not re.fullmatch(
            r"[A-Za-z0-9_-]{32,256}", values.get("SCHEDULER_API_TOKEN", "")
        ):
            raise DeploymentError("scheduler API token is missing")
        if (
            values.get("SPRING_DOCKER_COMPOSE_ENABLED") != "false"
            or values.get("SPRING_PROFILES_ACTIVE") != "dev"
        ):
            raise DeploymentError("server profile must use managed dependencies")
        required = (
            "SPRING_DATASOURCE_URL",
            "SPRING_DATASOURCE_USERNAME",
            "SPRING_DATASOURCE_PASSWORD",
            "SPRING_DATA_REDIS_HOST",
            "SPRING_DATA_REDIS_PORT",
        )
        if not all(values.get(key) for key in required):
            raise DeploymentError("database and Redis configuration is required")
    else:
        if manifest.get("deployment_strategy") != RUNTIME_STRATEGY:
            raise DeploymentError("runtime API bridge protocol is required")
        if not re.fullmatch(rb"[A-Za-z0-9_-]{43,128}\n?", files["service-token"]):
            raise DeploymentError("invalid runtime service token")
        if values.get(
            "PROVISIONER_SERVICE_TOKEN_FILE"
        ) != "/etc/secure-provisioner/service-token" or values.get(
            "PROVISIONER_SERVICE_TOKEN"
        ):
            raise DeploymentError("runtime token file contract mismatch")
        if (
            values.get("PROVISIONER_IMAGE_POLICIES")
            != "/etc/secure-provisioner/image-policies.json"
        ):
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
        subprocess.run(
            ["systemctl", "daemon-reload"], check=True, capture_output=True, timeout=30
        )

    def restart(self, service):
        subprocess.run(
            ["systemctl", "restart", service],
            check=True,
            capture_output=True,
            timeout=120,
        )

    def active(self, service):
        return (
            subprocess.run(
                ["systemctl", "is-active", "--quiet", service],
                capture_output=True,
                timeout=10,
            ).returncode
            == 0
        )

    def request(self, path, token=None):
        return self.port_request(path, token, 8080)

    def port_request(self, path, token=None, port=8080):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args):
                return None

        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}" + path, headers=headers
        )
        try:
            response = urllib.request.build_opener(NoRedirect()).open(
                request, timeout=5
            )
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(1024 * 1024)
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                value = None
            return response.code, value

    def reload_proxy(self):
        master = subprocess.run(
            ["systemctl", "show", "nginx", "--property=MainPID", "--value"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        if not master.isdecimal() or int(master) <= 1:
            raise DeploymentError("nginx master is not active")
        workers = proxy_workers(master)
        if not workers:
            raise DeploymentError("nginx has no serving workers")
        subprocess.run(
            ["/usr/sbin/nginx", "-t"], check=True, capture_output=True, timeout=10
        )
        subprocess.run(
            ["systemctl", "reload", "nginx"],
            check=True,
            capture_output=True,
            timeout=20,
        )
        wait_proxy_drain(workers)

    def start_bridge(self):
        # An old binary ignores command-line arguments. Probe with NO application
        # environment so it cannot initialize a worker if it lacks the protocol.
        result = subprocess.run(
            [
                "runuser",
                "-u",
                "provisioner",
                "--",
                "/opt/secure-provisioner/bridge",
                "--deployment-capabilities",
            ],
            env={"PATH": "/usr/bin:/bin"},
            check=True,
            capture_output=True,
            timeout=10,
        )
        if json.loads(result.stdout) != {
            "protocol": 1,
            "api_only": True,
            "handoff_lock": True,
        }:
            raise DeploymentError("candidate does not support the safe bridge protocol")
        identity = subprocess.run(
            [
                "systemctl",
                "show",
                "secure-provisioner",
                "--property=User",
                "--property=Group",
                "--property=WorkingDirectory",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        if dict(line.split("=", 1) for line in identity.splitlines()) != {
            "User": "provisioner",
            "Group": "provisioner",
            "WorkingDirectory": "/var/lib/secure-provisioner",
        }:
            raise DeploymentError("unexpected runtime service identity")
        subprocess.run(
            ["systemctl", "reset-failed", RUNTIME_BRIDGE],
            capture_output=True,
            timeout=10,
        )
        subprocess.run(
            [
                "systemd-run",
                "--quiet",
                "--collect",
                "--unit=" + RUNTIME_BRIDGE,
                "--property=Type=exec",
                "--property=Restart=no",
                "--property=User=provisioner",
                "--property=Group=provisioner",
                "--property=WorkingDirectory=/var/lib/secure-provisioner",
                "--property=EnvironmentFile=/etc/secure-provisioner/bridge.env",
                "--property=MemoryMax=384M",
                "--property=CPUQuota=100%",
                "--property=TasksMax=128",
                "--property=NoNewPrivileges=true",
                "--property=PrivateTmp=true",
                "--property=ProtectSystem=strict",
                "--property=ProtectHome=true",
                "/opt/secure-provisioner/bridge",
                "--deployment-api-only",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )

    def bridge_mode_verified(self):
        invocation = subprocess.run(
            ["systemctl", "show", RUNTIME_BRIDGE, "--property=InvocationID", "--value"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{32}", invocation):
            return False
        logs = subprocess.run(
            [
                "journalctl",
                "_SYSTEMD_INVOCATION_ID=" + invocation,
                "-o",
                "cat",
                "--no-pager",
                "-n",
                "100",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        return (
            "deployment API bridge: workers disabled; schema migrations disabled"
            in logs
        )

    def stop_bridge(self):
        subprocess.run(
            ["systemctl", "stop", RUNTIME_BRIDGE],
            check=True,
            capture_output=True,
            timeout=30,
        )
        if self.active(RUNTIME_BRIDGE):
            raise DeploymentError("bridge shutdown was not confirmed")

    def handoff_stop(self, values):
        # The fixed helper runs as the existing service identity. No DSN/token is
        # passed in argv, and the candidate cannot run with root privileges.
        environment = {
            "PATH": "/usr/bin:/bin",
            **{k: v for k, v in values.items() if k.startswith("PROVISIONER_")},
        }
        with subprocess.Popen(
            self.handoff_command(),
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as guard:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(guard.stdout, selectors.EVENT_READ)
                    if (
                        not selector.select(125)
                        or guard.stdout.readline(128) != b"HANDOFF_READY\n"
                    ):
                        raise DeploymentError(
                            "active operations did not drain; primary is unchanged"
                        )
                self.stop_primary()
                guard.stdin.write(b"release\n")
                guard.stdin.flush()
                guard.stdin.close()
                if guard.wait(timeout=2) != 0:
                    raise DeploymentError("runtime handoff fence expired")
            finally:
                if guard.poll() is None:
                    guard.kill()
                guard.wait(timeout=5)

    def handoff_command(self):
        return [
            "runuser",
            "-u",
            "provisioner",
            "--",
            "/opt/secure-provisioner/bridge",
            "--deployment-handoff-lock",
        ]

    def stop_primary(self):
        subprocess.run(
            ["systemctl", "stop", "secure-provisioner"],
            check=True,
            capture_output=True,
            timeout=2,
        )


def process_start(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
    except FileNotFoundError:
        return None


def proxy_workers(master):
    workers = {}
    for pid in Path(f"/proc/{master}/task/{master}/children").read_text().split():
        try:
            if (
                Path(f"/proc/{pid}/cmdline")
                .read_bytes()
                .startswith(b"nginx: worker process")
            ):
                start = process_start(pid)
                if start is not None:
                    workers[pid] = start
        except FileNotFoundError:
            pass
    return workers


def wait_proxy_drain(workers, timeout=20):
    deadline = time.monotonic() + timeout
    while any(process_start(pid) == start for pid, start in workers.items()):
        if time.monotonic() >= deadline:
            raise DeploymentError("previous nginx workers did not drain")
        time.sleep(0.05)


class RuntimeBridge:
    def __init__(self, root, service, attempts, delay):
        self.root, self.service, self.attempts, self.delay = (
            root,
            service,
            attempts,
            delay,
        )
        self.artifact = root / "opt/secure-provisioner/bridge"
        self.env = root / "etc/secure-provisioner/bridge.env"
        self.upstream = root / RUNTIME_UPSTREAM.lstrip("/")
        self.routed = False
        self.started = False

    def prepare(self, artifact, new_values, token):
        if any(
            p.exists() or p.is_symlink() for p in (self.artifact, self.env)
        ) or self.service.active(RUNTIME_BRIDGE):
            raise DeploymentError(
                "a previous bridge requires administrator verification"
            )
        old_raw = (self.root / CONFIG["runtime"]["env"].lstrip("/")).read_bytes()
        self.values = environment_values(old_raw)
        self.token = (
            (self.root / "etc/secure-provisioner/service-token").read_text().strip()
        )
        if (
            self.token != token
            or self.values.get("PROVISIONER_STORE_MODE") != "postgres"
            or new_values.get("PROVISIONER_STORE_MODE") != "postgres"
        ):
            raise DeploymentError(
                "bridge requires the same service credential and durable PostgreSQL store"
            )
        if any(
            v.get("PROVISIONER_ADDR", "127.0.0.1:8080") != "127.0.0.1:8080"
            for v in (self.values, new_values)
        ):
            raise DeploymentError(
                "primary runtime must use its fixed loopback listener"
            )
        for key in (
            "PROVISIONER_DATABASE_URL",
            "PROVISIONER_CLUSTER_REGISTRY",
            "PROVISIONER_IMAGE_POLICIES",
            "PROVISIONER_SERVICE_TOKEN_FILE",
            "PROVISIONER_PREVIOUS_SERVICE_TOKEN",
            "PROVISIONER_PREVIOUS_SERVICE_TOKEN_FILE",
            "PROVISIONER_CI_SMOKE_TOKEN",
            "PROVISIONER_CI_SMOKE_TOKEN_FILE",
            "PROVISIONER_CI_SMOKE_TEAM_ID",
            "PROVISIONER_CI_SMOKE_TARGET_ID",
        ):
            if self.values.get(key) != new_values.get(key):
                raise DeploymentError(
                    "runtime data and authentication configuration must be unchanged"
                )
        self.prepare_proxy()
        gid = (
            grp.getgrnam("provisioner").gr_gid
            if self.root == Path("/")
            else os.getgid()
        )
        atomic_write(self.artifact, artifact, 0o755)
        atomic_write(self.env, old_raw, 0o640, gid)
        # Treat an ambiguous systemd-run result as started: cleanup must prove
        # the transient unit is stopped before removing any of its files.
        self.started = True
        self.service.start_bridge()
        parent = self.service

        class Probe:
            def active(self, _):
                return parent.active(RUNTIME_BRIDGE)

            def request(self, path, token=None):
                return parent.port_request(path, token, 18080)

        verify(
            "runtime",
            CONFIG["runtime"],
            self.values,
            self.token,
            Probe(),
            self.attempts,
            self.delay,
        )
        if not self.service.bridge_mode_verified():
            raise DeploymentError("API-only bridge mode was not confirmed")
        self.route(18080)

    def prepare_proxy(self):
        source = self.root / "etc/nginx/sites-available/secure-provisioner-ip"
        if source.is_symlink() or not source.is_file():
            raise DeploymentError(
                "runtime HTTPS proxy must be installed by an administrator"
            )
        original = source.read_bytes()
        include = ("include " + RUNTIME_UPSTREAM + ";").encode()
        literal = PRIMARY_PROXY.strip()
        if (original.count(literal), original.count(include)) not in ((1, 0), (0, 1)):
            raise DeploymentError("unrecognized runtime HTTPS upstream")
        if (
            self.upstream.is_symlink()
            or self.upstream.exists()
            and self.upstream.read_bytes() != PRIMARY_PROXY
        ):
            raise DeploymentError("runtime proxy is not on the primary")
        if self.upstream.exists() and include in original:
            return
        try:
            atomic_write(self.upstream, PRIMARY_PROXY, 0o644)
            atomic_write(source, original.replace(literal, include), 0o644)
            self.service.reload_proxy()
        except BaseException:
            atomic_write(source, original, 0o644)
            self.service.reload_proxy()
            raise

    def route(self, port):
        if port not in (8080, 18080):
            raise DeploymentError("unsupported runtime upstream")
        self.routed = True  # A failed reload may already have switched traffic.
        atomic_write(
            self.upstream, f"proxy_pass http://127.0.0.1:{port};\n".encode(), 0o644
        )
        self.service.reload_proxy()
        self.routed = port != 8080

    def close(self):
        if self.started and not self.routed:
            self.service.stop_bridge()
            self.artifact.unlink(missing_ok=True)
            self.env.unlink(missing_ok=True)
            self.started = False


def deploy_runtime(manifest, files, values, root, state, service, attempts, delay):
    """An API-only candidate serves the durable queue while one worker is replaced."""
    backup = state / "previous"
    if backup.exists() or backup.is_symlink():
        raise DeploymentError(
            "previous runtime deployment requires administrator verification"
        )
    config = CONFIG["runtime"]
    path = lambda name: root / name.lstrip("/")
    gid = grp.getgrnam("provisioner").gr_gid if root == Path("/") else os.getgid()
    token = files["service-token"].decode().strip()
    entries = [
        (path(config["artifact"]), files["artifact"], 0o755, 0),
        (path(config["env"]), files["app.env"], 0o640, gid),
        (
            path("/etc/secure-provisioner/service-token"),
            files["service-token"],
            0o640,
            gid,
        ),
        (
            path(config["marker"]),
            (
                json.dumps(
                    {
                        "source_commit": manifest["source_sha"],
                        "artifact_sha256": manifest["checksums"]["artifact"],
                        "component": "runtime",
                        "deployment_strategy": RUNTIME_STRATEGY,
                        "deployed_at": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                        ),
                    }
                )
                + "\n"
            ).encode(),
            0o644,
            0,
        ),
    ]
    snapshots = []
    for target, _, _, _ in entries:
        if target.is_symlink() or not target.is_file():
            raise DeploymentError("runtime requires an existing regular deployment")
    verify("runtime", config, values, token, service, attempts, delay)
    backup.mkdir(mode=0o700)
    for index, (target, _, _, _) in enumerate(entries):
        saved = backup / str(index)
        metadata = target.stat()
        shutil.copy2(target, saved)
        snapshots.append((target, saved, metadata))
    bridge = RuntimeBridge(root, service, attempts, delay)
    changed = False
    try:
        bridge.prepare(files["artifact"], values, token)
        service.handoff_stop(bridge.values)
        changed = True
        for target, data, mode, group in entries:
            atomic_write(target, data, mode, group)
        service.restart(config["service"])
        verify("runtime", config, values, token, service, attempts, delay)
        bridge.route(8080)
    except BaseException:
        try:
            if changed:
                bridge.route(18080)
                # A failed readiness check may still have a live worker. Fence
                # and drain it too; never cancel an active create to roll back.
                service.handoff_stop(bridge.values)
                for target, saved, metadata in snapshots:
                    atomic_write(
                        target,
                        saved.read_bytes(),
                        metadata.st_mode & 0o777,
                        metadata.st_gid,
                    )
                service.restart(config["service"])
            elif not service.active(config["service"]):
                service.restart(config["service"])
            verify("runtime", config, values, token, service, attempts, delay)
            if bridge.routed:
                bridge.route(8080)
            bridge.close()
            shutil.rmtree(backup)
        except BaseException:
            # Bridge + snapshots remain intact for an authenticated operator.
            raise DeploymentError(
                "runtime rollback unverified; retain API bridge and snapshots"
            ) from None
        print(
            "ROLLBACK_RESULT="
            + json.dumps(
                {
                    "component": "runtime",
                    "status": "verified",
                    "deployment_strategy": RUNTIME_STRATEGY,
                }
            )
        )
        raise DeploymentError(
            "runtime deployment failed; previous service verified"
        ) from None
    bridge.close()
    shutil.rmtree(backup)
    return {
        "component": "runtime",
        "source_commit": manifest["source_sha"],
        "artifact_sha256": manifest["checksums"]["artifact"],
        "status": "verified",
        "authentication_verified": True,
        "deployment_strategy": RUNTIME_STRATEGY,
        "worker_handoff_verified": True,
    }


def verify(component, config, values, token, service, attempts=45, delay=2):
    for attempt in range(attempts):
        try:
            if service.active(config["service"]):
                if component == "scheduler":
                    code, health = service.request("/actuator/health")
                    code2, page = service.request("/api/instances?limit=1", token)
                    valid = (
                        code == 200
                        and isinstance(health, dict)
                        and health.get("status") == "UP"
                        and code2 == 200
                        and isinstance(page, dict)
                        and page.get("code") == "SUCCESS"
                        and isinstance(page.get("data"), dict)
                        and isinstance(page["data"].get("items"), list)
                        and "next_cursor" in page["data"]
                    )
                    path = "/api/instances?limit=1"
                else:
                    path = "/internal/v1/operations/ci-deployment-healthcheck"
                    code, body = service.request(path, token)
                    valid = (
                        code == 404
                        and isinstance(body, dict)
                        and body.get("error", {}).get("code") == "OPERATION_NOT_FOUND"
                    )
                if (
                    valid
                    and service.request(path)[0] == 401
                    and service.request(path, "invalid-deployment-credential")[0] == 401
                ):
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
        if component == "runtime":
            return deploy_runtime(
                manifest, files, values, root, state, service, attempts, delay
            )
        artifact, env, marker = (
            path(config[key]) for key in ("artifact", "env", "marker")
        )
        artifact.parent.mkdir(parents=True, exist_ok=True)
        if artifact.parent.is_symlink():
            raise DeploymentError("artifact directory must not be a symlink")
        artifact.parent.chmod(0o755)
        entries = [
            (artifact, files["artifact"], config["mode"], 0),
            (env, files["app.env"], 0o600, 0),
        ]
        token = values.get("SCHEDULER_API_TOKEN")
        if component == "runtime":
            gid = (
                grp.getgrnam(config["group"]).gr_gid
                if root == Path("/")
                else os.getgid()
            )
            entries[1] = (env, files["app.env"], 0o640, gid)
            entries.append(
                (
                    path("/etc/secure-provisioner/service-token"),
                    files["service-token"],
                    0o640,
                    gid,
                )
            )
            token = files["service-token"].decode().strip()
        else:
            dropin = b"[Service]\nExecStart=\nExecStart=/opt/temurin-24/bin/java -jar /opt/msgctf-scheduler/scheduler.jar\n"
            entries.append(
                (
                    path(
                        "/etc/systemd/system/mjsec-scheduler.service.d/60-ci-artifact.conf"
                    ),
                    dropin,
                    0o644,
                    0,
                )
            )
        entries.append(
            (
                marker,
                (
                    json.dumps(
                        {
                            "source_commit": manifest["source_sha"],
                            "artifact_sha256": manifest["checksums"]["artifact"],
                            "component": component,
                            "deployed_at": time.strftime(
                                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                            ),
                        }
                    )
                    + "\n"
                ).encode(),
                0o644,
                0,
            )
        )
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
                        atomic_write(
                            target,
                            saved.read_bytes(),
                            stat.st_mode & 0o777,
                            stat.st_gid,
                        )
                    else:
                        target.unlink(missing_ok=True)
                service.reload()
                service.restart(config["service"])
                old_values = environment_values(env.read_bytes())
                old_token = (
                    old_values.get("SCHEDULER_API_TOKEN")
                    if component == "scheduler"
                    else path("/etc/secure-provisioner/service-token")
                    .read_text()
                    .strip()
                )
                verify(
                    component, config, old_values, old_token, service, attempts, delay
                )
                print(
                    "ROLLBACK_RESULT="
                    + json.dumps({"component": component, "status": "verified"})
                )
                raise DeploymentError(
                    "deployment failed; previous service verified"
                ) from None
        return {
            "component": component,
            "source_commit": manifest["source_sha"],
            "artifact_sha256": manifest["checksums"]["artifact"],
            "status": "verified",
            "authentication_verified": True,
        }


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
        print(
            "Deployment did not pass verification (" + type(error).__name__ + ")",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
