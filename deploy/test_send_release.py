import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import send_release


class SenderTests(unittest.TestCase):
    def invoke(self, report):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact"
            artifact.write_bytes(b"artifact")
            environment = {
                "DEPLOY_HOST": "example.test",
                "DEPLOY_USER": "msgctf-deploy",
                "DEPLOY_ENV": "private-environment",
                "DEPLOY_SERVICE_TOKEN": "private-token",
                "DEPLOY_SSH_KEY": "private-key",
                "DEPLOY_KNOWN_HOSTS": "pinned-host",
            }

            def ssh(command, **kwargs):
                self.assertEqual(command[-1], "deploy")
                self.assertTrue(all(not k.startswith("DEPLOY_") for k in kwargs["env"]))
                with tarfile.open(fileobj=kwargs["stdin"], mode="r:gz") as archive:
                    self.assertEqual(
                        set(archive.getnames()),
                        {"artifact", "app.env", "service-token", "release.json"},
                    )
                    manifest = json.load(archive.extractfile("release.json"))
                    self.assertEqual(
                        manifest["deployment_strategy"], "runtime_api_bridge_v1"
                    )
                return subprocess.CompletedProcess(
                    command, 0, "DEPLOYMENT_RESULT=" + json.dumps(report), ""
                )

            with patch.dict(os.environ, environment), patch(
                "sys.argv",
                [
                    "send_release.py",
                    "runtime",
                    "--artifact",
                    str(artifact),
                    "--source-sha",
                    "b" * 40,
                ],
            ), patch.object(
                send_release.subprocess, "run", side_effect=ssh
            ), contextlib.redirect_stdout(
                io.StringIO()
            ) as output:
                send_release.main()
                self.assertNotIn("private-", output.getvalue())

    def valid(self):
        return {
            "component": "runtime",
            "source_commit": "b" * 40,
            "artifact_sha256": hashlib.sha256(b"artifact").hexdigest(),
            "status": "verified",
            "authentication_verified": True,
            "deployment_strategy": "runtime_api_bridge_v1",
            "worker_handoff_verified": True,
        }

    def test_accepts_matching_verified_handoff_without_echoing_credentials(self):
        self.invoke(self.valid())

    def test_rejects_legacy_restart_success_and_mismatched_release_proofs(self):
        for key, value in (
            ("deployment_strategy", "runtime_restart"),
            ("worker_handoff_verified", False),
            ("source_commit", "c" * 40),
            ("artifact_sha256", "0" * 64),
            ("authentication_verified", False),
            ("component", "scheduler"),
            ("status", "failed"),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.invoke({**self.valid(), key: value})


if __name__ == "__main__":
    unittest.main()
