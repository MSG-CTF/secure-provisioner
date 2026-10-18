"""Real Go processes, PostgreSQL queue and nginx; never runs against production."""

import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from release import (
    CONFIG,
    DeploymentError,
    RUNTIME_BRIDGE,
    RUNTIME_UPSTREAM,
    SystemService,
    deploy,
    environment_values,
    proxy_workers,
    wait_proxy_drain,
)
import test_release as fixtures

TOKEN = fixtures.TOKEN
PROBE_PATH = "/internal/v1/operations/ci-deployment-healthcheck"


def request(port, path=PROBE_PATH, token=TOKEN, method="GET", body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {"Content-Type": "application/json", "Connection": "close"}
        if token:
            headers["Authorization"] = "Bearer " + token
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class LocalSystem(SystemService):
    def __init__(self, root, binary, broken_rollback=False):
        self.root, self.binary = root, binary
        self.primary = self.bridge = None
        self.broken_rollback = broken_rollback
        self.restarts = 0
        self.logs = []
        self.created = []
        self.primary_gap = False
        self.queue_result = None
        self.nginx = None
        self.restart("secure-provisioner")
        self.restarts = 0
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.proxy_port = sock.getsockname()[1]
        self.proxy_conf = root / "nginx.conf"
        self.actual_upstream = root / "test-upstream.conf"
        self.actual_upstream.write_text("proxy_pass http://127.0.0.1:8080;\n")
        self.proxy_conf.write_text(
            f"""worker_processes 2;
pid {root}/nginx.pid;
error_log {root}/nginx-error.log notice;
events {{ worker_connections 256; }}
http {{ access_log off; keepalive_timeout 0; server {{ listen 127.0.0.1:{self.proxy_port};
location / {{ include {self.actual_upstream}; proxy_set_header Authorization $http_authorization; }} }} }}
"""
        )
        self.nginx = subprocess.Popen(
            ["nginx", "-p", str(root), "-c", str(self.proxy_conf), "-g", "daemon off;"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.wait_port(self.proxy_port)

    def wait_port(self, port):
        for _ in range(200):
            try:
                if request(port)[0] == 404:
                    return
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(0.02)
        raise AssertionError("fixture API did not initialize")

    def app_env(self, bridge=False):
        source = self.root / (
            "etc/secure-provisioner/bridge.env"
            if bridge
            else "etc/secure-provisioner/provisioner.env"
        )
        values = environment_values(source.read_bytes())
        values["PROVISIONER_SERVICE_TOKEN_FILE"] = str(
            self.root / "etc/secure-provisioner/service-token"
        )
        values["PROVISIONER_IMAGE_POLICIES"] = ""
        values["PROVISIONER_CLUSTER_REGISTRY"] = str(self.root / "registry.json")
        return {"PATH": os.environ["PATH"], **values}

    def launch(self, artifact, bridge=False):
        log = tempfile.TemporaryFile()
        self.logs.append(log)
        process = subprocess.Popen(
            [str(artifact)] + (["--deployment-api-only"] if bridge else []),
            env=self.app_env(bridge),
            stdout=log,
            stderr=log,
        )
        self.created.append(process)
        return process

    def active(self, service):
        process = self.bridge if service == RUNTIME_BRIDGE else self.primary
        return process is not None and process.poll() is None

    def start_bridge(self):
        binary = self.root / "opt/secure-provisioner/bridge"
        proof = subprocess.run(
            [str(binary), "--deployment-capabilities"],
            env={"PATH": os.environ["PATH"]},
            capture_output=True,
            check=True,
            timeout=5,
        )
        if json.loads(proof.stdout).get("api_only") is not True:
            raise AssertionError("missing capabilities")
        self.bridge = self.launch(binary, True)
        self.wait_port(18080)

    def bridge_mode_verified(self):
        self.logs[-1].seek(0)
        return (
            b"deployment API bridge: workers disabled; schema migrations disabled"
            in self.logs[-1].read()
        )

    def handoff_command(self):
        return [
            str(self.root / "opt/secure-provisioner/bridge"),
            "--deployment-handoff-lock",
        ]

    def stop_primary(self):
        if self.primary and self.primary.poll() is None:
            self.primary.terminate()
            self.primary.wait(timeout=2)

    def restart(self, service):
        self.restarts += 1
        if self.primary and self.primary.poll() is None:
            raise AssertionError("primary was not fenced and stopped")
        if self.broken_rollback and self.restarts >= 2:
            return
        if self.primary_gap:
            # This is an actual accepted Go HTTP create while NO primary exists.
            # The bridge must persist it, deduplicate it and leave attempt=0.
            body = json.dumps(
                {
                    "request_id": "bridge-" + uuid.uuid4().hex,
                    "instance_id": str(uuid.uuid4()),
                    "team_id": "00000000-0000-4000-8000-000000000018",
                    "isolation_profile": "WEB",
                    "target": {
                        "runtime_type": "KUBERNETES",
                        "target_id": "unconfigured-target",
                    },
                    "workload": {
                        "image": "registry.example.test/challenge@sha256:" + "a" * 64,
                        "container_port": 8080,
                        "resource_limits": {
                            "cpu_millicores": 100,
                            "memory_mib": 128,
                            "ephemeral_storage_mib": 128,
                        },
                    },
                }
            )
            code, operation = request(
                self.proxy_port, "/internal/v1/instances", method="POST", body=body
            )
            if code != 202:
                raise AssertionError("bridge did not accept create: " + str(operation))
            duplicate_code, duplicate = request(
                self.proxy_port, "/internal/v1/instances", method="POST", body=body
            )
            if (
                duplicate_code != 202
                or duplicate["operation_id"] != operation["operation_id"]
            ):
                raise AssertionError("bridge lost idempotency")
            code, state = request(
                self.proxy_port, "/internal/v1/operations/" + operation["operation_id"]
            )
            if code != 200 or state["status"] != "QUEUED" or state["attempt"] != 0:
                raise AssertionError("API bridge executed work")
            self.queue_result = operation["operation_id"]
            self.primary_gap = False
            time.sleep(0.25)
        self.primary = self.launch(
            self.root / "opt/secure-provisioner/secure-provisioner"
        )

    def stop_bridge(self):
        if self.bridge and self.bridge.poll() is None:
            self.bridge.terminate()
            self.bridge.wait(timeout=3)

    def reload_proxy(self):
        workers = proxy_workers(self.nginx.pid)
        source = self.root / RUNTIME_UPSTREAM.lstrip("/")
        self.actual_upstream.write_bytes(source.read_bytes())
        subprocess.run(
            ["nginx", "-t", "-p", str(self.root), "-c", str(self.proxy_conf)],
            check=True,
            capture_output=True,
            timeout=5,
        )
        self.nginx.send_signal(signal.SIGHUP)
        wait_proxy_drain(workers, 5)

    def close(self):
        for process in self.created:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if self.nginx:
            self.nginx.send_signal(signal.SIGQUIT)
            self.nginx.wait(timeout=5)
        for log in self.logs:
            log.close()


@unittest.skipUnless(
    os.environ.get("RUNTIME_TEST_BINARY")
    and os.environ.get("PROVISIONER_TEST_DATABASE_URL")
    and shutil.which("nginx"),
    "requires the built Go binary, disposable PostgreSQL and real nginx",
)
class RuntimeIntegrationTests(unittest.TestCase):
    def run_scenario(self, failure=None):
        binary = Path(os.environ["RUNTIME_TEST_BINARY"]).resolve()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures.DeploymentTests().fixture(root, "runtime")
            env = fixtures.RUNTIME_ENV.replace(
                b"postgresql://localhost/test",
                os.environ["PROVISIONER_TEST_DATABASE_URL"].encode(),
            )
            (root / "etc/secure-provisioner/provisioner.env").write_bytes(env)
            (root / "opt/secure-provisioner/secure-provisioner").write_bytes(
                binary.read_bytes()
            )
            (root / "opt/secure-provisioner/secure-provisioner").chmod(0o755)
            (root / "registry.json").write_text('{"clusters":[]}')
            service = LocalSystem(root, binary, failure == "rollback")
            service.primary_gap = True
            stop = threading.Event()
            outcomes = []

            def probe():
                while not stop.is_set():
                    try:
                        code, value = request(service.proxy_port)
                        outcomes.append(
                            code == 404
                            and value.get("error", {}).get("code")
                            == "OPERATION_NOT_FOUND"
                        )
                    except Exception:
                        outcomes.append(False)
                    stop.wait(0.005)

            watcher = threading.Thread(target=probe)
            watcher.start()
            try:
                artifact = (
                    binary.read_bytes()
                    if not failure
                    else (
                        '#!/bin/sh\nif [ "$#" -eq 0 ]; then exit 1; fi\nexec "'
                        + str(binary)
                        + '" "$@"\n'
                    ).encode()
                )
                if failure:
                    with self.assertRaises(DeploymentError):
                        deploy(
                            "runtime",
                            fixtures.bundle("runtime", artifact=artifact, env=env),
                            root,
                            service,
                            5,
                            0.05,
                        )
                else:
                    result = deploy(
                        "runtime",
                        fixtures.bundle("runtime", artifact=artifact, env=env),
                        root,
                        service,
                        30,
                        0.05,
                    )
                    self.assertTrue(result["worker_handoff_verified"])
                self.assertEqual(request(service.proxy_port, token=None)[0], 401)
                self.assertEqual(request(service.proxy_port, token="wrong")[0], 401)
                if failure == "rollback":
                    self.assertTrue(service.active(RUNTIME_BRIDGE))
                    self.assertTrue(
                        (root / "var/lib/msgctf-deploy/runtime/previous").exists()
                    )
                else:
                    self.assertFalse(service.active(RUNTIME_BRIDGE))
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        code, operation = request(
                            service.proxy_port,
                            "/internal/v1/operations/" + service.queue_result,
                        )
                        if code == 200 and operation["status"] == "FAILED":
                            break
                        time.sleep(0.02)
                    self.assertEqual(operation["attempt"], 1)
                    self.assertEqual(operation["last_error_code"], "TARGET_NOT_FOUND")
                time.sleep(0.1)
            finally:
                stop.set()
                watcher.join(timeout=6)
                service.close()
            self.assertGreater(len(outcomes), 10)
            self.assertTrue(
                all(outcomes),
                f"HTTP failures during {failure or 'handoff'}: {outcomes.count(False)}/{len(outcomes)}",
            )

    def test_live_http_and_durable_queue_survive_handoff(self):
        self.run_scenario()

    def test_live_http_and_durable_queue_survive_verified_rollback(self):
        self.run_scenario("candidate")

    def test_failed_rollback_keeps_live_bridge(self):
        self.run_scenario("rollback")


if __name__ == "__main__":
    unittest.main()
