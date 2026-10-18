import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from release import (
    DeploymentError,
    RUNTIME_BRIDGE,
    RUNTIME_UPSTREAM,
    deploy,
    read_bundle,
)
import test_release as fixtures
from test_release import RUNTIME_ENV, Service, TOKEN, bundle


class RuntimeBridgeTests(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        fixtures.DeploymentTests().fixture(root, "runtime")
        return root, Service(root, "runtime")

    def test_handoff_orders_proxy_drain_before_stop_and_return_before_bridge_stop(self):
        root, service = self.fixture()
        result = deploy("runtime", bundle("runtime"), root, service, 1, 0)
        self.assertEqual(result["deployment_strategy"], "runtime_api_bridge_v1")
        self.assertTrue(result["worker_handoff_verified"])
        self.assertEqual(
            service.events,
            [
                "proxy:proxy_pass http://127.0.0.1:8080;",
                "start_bridge",
                "proxy:proxy_pass http://127.0.0.1:18080;",
                "handoff_stop",
                "restart",
                "proxy:proxy_pass http://127.0.0.1:8080;",
                "stop_bridge",
            ],
        )
        self.assertFalse((root / "var/lib/msgctf-deploy/runtime/previous").exists())

    def test_bridge_proof_failure_never_stops_or_replaces_primary(self):
        for failure in ("auth", "worker", "start"):
            with self.subTest(failure=failure):
                root, service = self.fixture()
                if failure == "auth":
                    service.port_request = lambda *a: (200, None)
                if failure == "worker":
                    service.bridge_mode_verified = lambda: False
                if failure == "start":
                    service.start_bridge = lambda: (_ for _ in ()).throw(
                        DeploymentError()
                    )
                with self.assertRaises(DeploymentError):
                    deploy("runtime", bundle("runtime"), root, service, 1, 0)
                self.assertEqual(service.restarts, 0)
                self.assertNotIn("handoff_stop", service.events)
                self.assertEqual(
                    (root / "opt/secure-provisioner/secure-provisioner").read_bytes(),
                    b"old artifact",
                )

    def test_changed_database_or_authentication_is_rejected_before_cutover(self):
        for raw in (
            RUNTIME_ENV.replace(b"localhost/test", b"localhost/other"),
            RUNTIME_ENV.replace(b"MODE=postgres", b"MODE=memory"),
            RUNTIME_ENV + b"PROVISIONER_PREVIOUS_SERVICE_TOKEN=changed\n",
            RUNTIME_ENV + b"PROVISIONER_CI_SMOKE_TEAM_ID=changed\n",
            RUNTIME_ENV + b"PROVISIONER_ADDR=0.0.0.0:8080\n",
        ):
            root, service = self.fixture()
            with self.assertRaises(DeploymentError):
                deploy("runtime", bundle("runtime", env=raw), root, service, 1, 0)
            self.assertEqual(service.events, [])

    def test_active_work_timeout_keeps_previous_worker_and_primary(self):
        root, service = self.fixture()
        service.handoff_stop = lambda _: (_ for _ in ()).throw(
            DeploymentError("not idle")
        )
        with self.assertRaises(DeploymentError):
            deploy("runtime", bundle("runtime"), root, service, 1, 0)
        self.assertEqual(service.restarts, 0)
        self.assertFalse(service.bridge_started)
        self.assertEqual(
            (root / RUNTIME_UPSTREAM.lstrip("/")).read_text(),
            "proxy_pass http://127.0.0.1:8080;\n",
        )

    def test_failed_candidate_readiness_drains_before_restoring_previous_release(self):
        root, service = self.fixture()
        service.fail = True
        with self.assertRaises(DeploymentError):
            deploy("runtime", bundle("runtime"), root, service, 1, 0)
        self.assertEqual(service.events.count("handoff_stop"), 2)
        self.assertEqual(service.restarts, 2)
        self.assertFalse(service.bridge_started)
        self.assertEqual(
            (root / "opt/secure-provisioner/secure-provisioner").read_bytes(),
            b"old artifact",
        )

    def test_failed_rollback_retains_bridge_and_private_previous_release(self):
        root, service = self.fixture()
        normal = service.request
        service.request = lambda *a: normal(*a) if service.restarts == 0 else (503, {})
        with patch("builtins.print") as output:
            with self.assertRaisesRegex(DeploymentError, "rollback unverified"):
                deploy("runtime", bundle("runtime"), root, service, 1, 0)
            self.assertFalse(
                any("ROLLBACK_RESULT=" in str(c) for c in output.call_args_list)
            )
        self.assertTrue(service.bridge_started)
        self.assertIn(":18080;", (root / RUNTIME_UPSTREAM.lstrip("/")).read_text())
        backup = root / "var/lib/msgctf-deploy/runtime/previous"
        self.assertTrue(backup.is_dir())
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(DeploymentError, "previous runtime deployment"):
            deploy("runtime", bundle("runtime"), root, service, 1, 0)

    def test_proxy_reload_ambiguity_retains_api_until_old_route_verified(self):
        root, service = self.fixture()
        original = service.reload_proxy
        count = 0

        def reload():
            nonlocal count
            count += 1
            original()
            if count >= 2:
                raise DeploymentError("nginx reload failed")

        service.reload_proxy = reload
        with self.assertRaisesRegex(DeploymentError, "rollback unverified"):
            deploy("runtime", bundle("runtime"), root, service, 1, 0)
        self.assertTrue(service.bridge_started)
        self.assertEqual(service.restarts, 0)

    def test_existing_bridge_or_symlink_never_overwritten(self):
        for kind in ("file", "symlink", "active"):
            root, service = self.fixture()
            artifact = root / "opt/secure-provisioner/bridge"
            if kind == "file":
                artifact.write_text("previous")
            if kind == "symlink":
                artifact.symlink_to(root / "opt/secure-provisioner/secure-provisioner")
            if kind == "active":
                service.bridge_started = True
            with self.assertRaises(DeploymentError):
                deploy("runtime", bundle("runtime"), root, service, 1, 0)
            self.assertEqual(service.restarts, 0)


if __name__ == "__main__":
    unittest.main()
