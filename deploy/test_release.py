import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from release import CONFIG, DeploymentError, deploy, read_bundle

TOKEN = "a" * 48
ENV = (
    "SCHEDULER_API_TOKEN="
    + TOKEN
    + "\nSPRING_PROFILES_ACTIVE=dev\nSPRING_DOCKER_COMPOSE_ENABLED=false\nSPRING_DATASOURCE_URL=jdbc:postgresql://127.0.0.1/db\nSPRING_DATASOURCE_USERNAME=test\nSPRING_DATASOURCE_PASSWORD=test\nSPRING_DATA_REDIS_HOST=127.0.0.1\nSPRING_DATA_REDIS_PORT=6379\n"
).encode()
RUNTIME_ENV = b"PROVISIONER_SERVICE_TOKEN_FILE=/etc/secure-provisioner/service-token\nPROVISIONER_IMAGE_POLICIES=/etc/secure-provisioner/image-policies.json\nPROVISIONER_STORE_MODE=postgres\nPROVISIONER_DATABASE_URL=postgresql://localhost/test\n"


def bundle(
    component="scheduler", extra=None, corrupt=False, artifact=b"new artifact", env=None
):
    files = {
        "artifact": artifact,
        "app.env": env or (ENV if component == "scheduler" else RUNTIME_ENV),
    }
    if component == "runtime":
        files["service-token"] = TOKEN.encode()
    manifest = {
        "component": component,
        "source_sha": "b" * 40,
        "checksums": {k: hashlib.sha256(v).hexdigest() for k, v in files.items()},
    }
    if component == "runtime":
        manifest["deployment_strategy"] = "runtime_api_bridge_v1"
    if corrupt:
        manifest["checksums"]["artifact"] = "0" * 64
    files["release.json"] = json.dumps(manifest).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if extra:
            archive.addfile(extra)
    buffer.seek(0)
    return buffer


class Service:
    def __init__(self, root, component, fail=False):
        self.root, self.component, self.fail = root, component, fail
        self.restarts = 0
        self.bridge_started = False
        self.events = []

    def reload(self):
        pass

    def restart(self, service):
        self.restarts += 1
        self.events.append("restart")

    def active(self, service):
        if service == "secure-provisioner-bridge":
            return self.bridge_started
        return True

    def reload_proxy(self):
        self.events.append(
            "proxy:"
            + (self.root / "etc/nginx/snippets/msgctf-runtime-upstream.conf")
            .read_text()
            .strip()
        )

    def start_bridge(self):
        self.bridge_started = True
        self.events.append("start_bridge")

    def bridge_mode_verified(self):
        return True

    def stop_bridge(self):
        self.bridge_started = False
        self.events.append("stop_bridge")

    def handoff_stop(self, values):
        self.events.append("handoff_stop")

    def port_request(self, path, token=None, port=8080):
        return (
            (404, {"error": {"code": "OPERATION_NOT_FOUND"}})
            if token == TOKEN
            else (401, {})
        )

    def request(self, path, token=None):
        artifact = self.root / CONFIG[self.component]["artifact"].lstrip("/")
        if self.fail and artifact.read_bytes() == b"new artifact":
            return 503, {}
        if path == "/actuator/health":
            return 200, {"status": "UP"}
        if token != TOKEN:
            return 401, {}
        if self.component == "runtime":
            return 404, {"error": {"code": "OPERATION_NOT_FOUND"}}
        return 200, {"code": "SUCCESS", "data": {"items": [], "next_cursor": None}}


class DeploymentTests(unittest.TestCase):
    def fixture(self, root, component):
        for key, value in (
            ("artifact", b"old artifact"),
            ("env", ENV if component == "scheduler" else RUNTIME_ENV),
            ("marker", b'{"source_commit":"old"}'),
        ):
            target = root / CONFIG[component][key].lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
            target.chmod(0o600)
        if component == "runtime":
            (root / "etc/secure-provisioner/service-token").write_text(TOKEN)
            site = root / "etc/nginx/sites-available/secure-provisioner-ip"
            site.parent.mkdir(parents=True)
            site.write_text("location / { proxy_pass http://127.0.0.1:8080; }\n")

    def test_success_updates_artifact_metadata_and_authentication(self):
        for component in CONFIG:
            with self.subTest(
                component=component
            ), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                self.fixture(root, component)
                service = Service(root, component)
                result = deploy(component, bundle(component), root, service, 1, 0)
                self.assertEqual(result["status"], "verified")
                self.assertEqual(service.restarts, 1)
                self.assertEqual(
                    (root / CONFIG[component]["artifact"].lstrip("/")).read_bytes(),
                    b"new artifact",
                )
                env = root / CONFIG[component]["env"].lstrip("/")
                self.assertEqual(
                    env.stat().st_mode & 0o777,
                    0o640 if component == "runtime" else 0o600,
                )

    def test_failed_health_restores_artifact_environment_marker_and_dropin(self):
        for component in CONFIG:
            with self.subTest(
                component=component
            ), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                self.fixture(root, component)
                before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
                service = Service(root, component, fail=True)
                with self.assertRaises(DeploymentError):
                    deploy(component, bundle(component), root, service, 1, 0)
                self.assertEqual(service.restarts, 2)
                for p, data in before.items():
                    if component == "runtime" and "nginx" in p.parts:
                        self.assertIn(
                            "include /etc/nginx/snippets/msgctf-runtime-upstream.conf;",
                            p.read_text(),
                        )
                        continue
                    self.assertEqual(p.read_bytes(), data)
                self.assertFalse(
                    (
                        root
                        / "etc/systemd/system/mjsec-scheduler.service.d/60-ci-artifact.conf"
                    ).exists()
                )

    def test_corrupt_artifact_changes_no_service_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root, "scheduler")
            service = Service(root, "scheduler")
            with self.assertRaises(DeploymentError):
                deploy("scheduler", bundle(corrupt=True), root, service, 1, 0)
            self.assertEqual(service.restarts, 0)
            self.assertEqual(
                (root / "opt/msgctf-scheduler/scheduler.jar").read_bytes(),
                b"old artifact",
            )

    def test_service_can_read_artifact_directory_with_private_umask(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root, "scheduler")
            directory = root / "opt/msgctf-scheduler"
            directory.chmod(0o700)
            previous = os.umask(0o077)
            try:
                deploy("scheduler", bundle(), root, Service(root, "scheduler"), 1, 0)
            finally:
                os.umask(previous)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)

    def test_rejects_traversal_symlink_and_duplicate_entries(self):
        for name, kind in (
            ("../escape", tarfile.REGTYPE),
            ("app.env", tarfile.SYMTYPE),
            ("artifact", tarfile.REGTYPE),
        ):
            with self.subTest(name=name, kind=kind):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "/etc/passwd"
                with self.assertRaises(DeploymentError):
                    read_bundle(bundle(extra=entry), "scheduler")

    def test_rejects_component_and_unsafe_environment(self):
        with self.assertRaises(DeploymentError):
            read_bundle(bundle(), "runtime")
        for suffix in (
            b"LD_PRELOAD=/tmp/code\n",
            b"SCHEDULER_API_TOKEN=duplicate\n",
            b"not an env file\n",
        ):
            with self.assertRaises(DeploymentError):
                read_bundle(bundle(env=ENV + suffix), "scheduler")

    def test_html_or_unprotected_api_fails_verification(self):
        for insecure in (False, True):
            with tempfile.TemporaryDirectory() as name:
                root = Path(name)
                self.fixture(root, "scheduler")
                service = Service(root, "scheduler")
                original = service.request

                def request(path, token=None):
                    current = (root / "opt/msgctf-scheduler/scheduler.jar").read_bytes()
                    if current == b"new artifact":
                        if insecure and path == "/actuator/health":
                            return 200, {"status": "UP"}
                        return (
                            (
                                200,
                                {
                                    "code": "SUCCESS",
                                    "data": {"items": [], "next_cursor": None},
                                },
                            )
                            if insecure
                            else (200, None)
                        )
                    return original(path, token)

                service.request = request
                with self.assertRaises(DeploymentError):
                    deploy("scheduler", bundle(), root, service, 1, 0)
                self.assertEqual(service.restarts, 2)

    def test_lock_prevents_parallel_deploy_without_restart(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root, "scheduler")
            service = Service(root, "scheduler")
            with patch("release.fcntl.flock", side_effect=BlockingIOError):
                with self.assertRaises(DeploymentError):
                    deploy("scheduler", bundle(), root, service, 1, 0)
            self.assertEqual(service.restarts, 0)

    def test_token_change_is_restored_after_failed_deployment(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root, "scheduler")
            service = Service(root, "scheduler")
            changed = ENV.replace(TOKEN.encode(), b"z" * 48)
            with self.assertRaises(DeploymentError):
                deploy("scheduler", bundle(env=changed), root, service, 1, 0)
            self.assertEqual((root / "etc/default/mjsec-scheduler").read_bytes(), ENV)
            self.assertEqual(service.restarts, 2)

    def test_rollback_does_not_claim_success_if_old_service_is_broken(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root, "scheduler")
            service = Service(root, "scheduler")
            service.request = lambda *_: (503, {})
            with patch("builtins.print") as output:
                with self.assertRaises(DeploymentError):
                    deploy("scheduler", bundle(), root, service, 1, 0)
                self.assertFalse(
                    any(
                        "ROLLBACK_RESULT=" in str(call)
                        for call in output.call_args_list
                    )
                )


if __name__ == "__main__":
    unittest.main()
