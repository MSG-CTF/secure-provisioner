import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import published_image_sync as sync
import release
import test_release as fixtures
from test_release import Service, CONFIG

REPO = "MSG-CTF/2026_MSG_CTF"
WORKFLOW = ".github/workflows/challenge-validation.yml"
OLD = "ghcr.io/msg-ctf/challenges/web-demo/app@sha256:" + "a" * 64
NEW = OLD[:-64] + "b" * 64


def publication():
    artifact = {"id": 123, "expired": False, "name": "web-demo-456-1-" + "f" * 32 + "-publish-bundle",
                "workflow_run": {"id": 456, "head_sha": "a" * 40, "head_branch": "main"}}
    run = {"id": 456, "status": "completed", "conclusion": "success", "event": "push", "head_branch": "main",
           "repository": {"full_name": REPO}, "path": WORKFLOW, "head_sha": "a" * 40, "run_attempt": 1, "run_number": 42}
    document = {"schema_version": "2.0", "challenge_slug": "web-demo", "source_sha": "a" * 40,
                "source_ref": "refs/heads/main", "registry_revision": 42, "scan_result": "PASS",
                "architecture": "AMD64", "runtime_type": "KUBERNETES", "isolation_profile": "WEB",
                "workload": {"containers": [{"name": "app", "image": NEW, "ports": [{"port": 8080, "public": True}]}]}}
    return artifact, run, document


def policy():
    return {"schema_version": 1, "managed_repositories": [OLD.split("@")[0]], "images": [{
        "image": OLD, "container": "app", "isolation_profile": "WEB", "status": "create_enabled", "ports": [8080],
        "exposed_ports": [8080], "requires_flag": True, "run_as_user": 10001,
        "writable_paths": [{"path": "/tmp", "size_mib": 32}], "shutdown_grace_seconds": 1,
    }], "endpoint_protocols": [{"image": OLD, "port": 8080, "protocol": "HTTP"}]}


class API:
    def __init__(self):
        self.artifact, self.run, self.document = publication()
        self.calls = []
    def request(self, suffix, archive=False):
        self.calls.append(suffix)
        if suffix.startswith("/actions/artifacts?"):
            return {"total_count": 1, "artifacts": [self.artifact]}
        if not archive:
            return self.run
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as zipped:
            zipped.writestr("artifact-v2.json", json.dumps(self.document))
        return stream.getvalue()


class PublicationTests(unittest.TestCase):
    def test_provenance_and_scan_are_independently_checked(self):
        mutations = [lambda a: a.run.update(conclusion="failure"), lambda a: a.run.update(head_branch="attacker"),
                     lambda a: a.run.update(event="pull_request"), lambda a: a.run.update(path="unreviewed.yml"),
                     lambda a: a.run.update(repository={"full_name": "elsewhere/fork"}),
                     lambda a: a.document.update(source_sha="b" * 40), lambda a: a.document.update(scan_result="FAIL"),
                     lambda a: a.document.update(registry_revision=41), lambda a: a.artifact.update(expired=True),
                     lambda a: a.document["workload"]["containers"][0].update(image=NEW.replace("web-demo", "web-other"))]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                api = API(); mutate(api)
                with self.assertRaises(sync.SyncError):
                    sync.verified_bundle(api, api.artifact, repository=REPO, branch="main", workflow=WORKFLOW)
        api = API()
        self.assertEqual(sync.verified_bundle(api, api.artifact, repository=REPO, branch="main", workflow=WORKFLOW), api.document)

    def test_only_digest_changes_all_operator_requirements_are_preserved(self):
        old = policy()
        updated, images = sync.extend_policy(old, publication()[2])
        self.assertEqual(images, [NEW])
        self.assertEqual(len(old["images"]), 1)
        clone = dict(updated["images"][-1]); clone["image"] = OLD
        self.assertEqual(clone, old["images"][0])
        self.assertEqual(updated["endpoint_protocols"][-1]["image"], NEW)
        self.assertEqual(sync.extend_policy(updated, publication()[2])[1], [])

    def test_unknown_repository_changed_profile_and_explicit_block_fail_closed(self):
        for mutate in [lambda p: p.update(managed_repositories=[]),
                       lambda p: p["images"][0].update(ports=[9000]),
                       lambda p: p["images"].append({**p["images"][0], "image": NEW, "status": "blocked"}),
                       lambda p: p["images"].append({**p["images"][0], "image": OLD[:-64]+"c"*64, "requires_flag": False})]:
            p = policy(); mutate(p)
            with self.assertRaises(sync.SyncError):
                sync.extend_policy(p, publication()[2])

    def test_reviewed_network_graph_follows_exact_new_image_set(self):
        p = policy(); p["network_required_repositories"] = p["managed_repositories"]
        p["workload_networks"] = [{"id": "reviewed", "isolation_profile": "WEB", "containers": [
            {"name": "app", "image": OLD, "ports": [8080]}], "edges": []}]
        updated, _ = sync.extend_policy(p, publication()[2])
        self.assertEqual(updated["workload_networks"][-1]["containers"][0]["image"], NEW)
        self.assertEqual(updated["workload_networks"][-1]["edges"], [])
        p["workload_networks"] = []
        with self.assertRaises(sync.SyncError): sync.extend_policy(p, publication()[2])

    def fixture(self, directory):
        p = Path(directory)
        config = {"repository": REPO, "branch": "main", "workflow": WORKFLOW, "policy_file": str(p/"policy.json"),
                  "state_file": str(p/"state.json"), "max_pages": 1}
        (p/"policy.json").write_text(json.dumps(policy()))
        return config

    def test_marker_commits_only_after_reload_and_restart_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.fixture(directory); state = {}; calls = []
            def reload(data, expected):
                self.assertEqual(expected, hashlib.sha256(Path(config["policy_file"]).read_bytes()).hexdigest())
                calls.append(data); Path(config["policy_file"]).write_bytes(data)
                return {"status": "verified"}
            sync.synchronize(config, API(), state, reload)
            self.assertEqual(state["artifacts"]["123"]["status"], "APPLIED")
            state = json.loads(Path(config["state_file"]).read_bytes())
            sync.synchronize(config, API(), state, reload)
            self.assertEqual(len(calls), 1)

    def test_crash_after_catalog_write_replays_fenced_reload_before_applied_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.fixture(directory); state = {}
            def crash(data, expected):
                Path(config["policy_file"]).write_bytes(data)
                raise RuntimeError("simulated crash")
            with self.assertRaises(RuntimeError): sync.synchronize(config, API(), state, crash)
            state = json.loads(Path(config["state_file"]).read_bytes())
            self.assertNotIn("123", state["artifacts"])
            calls = []
            result = sync.synchronize(config, API(), state, lambda data, expected: calls.append(data) or {"status": "verified"})
            self.assertTrue(result["recovered_pending_reload"])
            self.assertEqual(len(calls), 1)
            self.assertEqual(state["artifacts"]["123"]["status"], "APPLIED")

    def test_failed_or_unverified_reload_is_never_marked_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.fixture(directory); state = {}
            with self.assertRaises(sync.SyncError): sync.synchronize(config, API(), state, lambda *a: None)
            self.assertNotIn("123", state["artifacts"])


class PolicyHandoffTests(unittest.TestCase):
    def fixture(self, root):
        fixtures.DeploymentTests().fixture(root, "runtime")
        (root/"etc/secure-provisioner/image-policies.json").write_bytes(b'{"old":true}')
        marker = root/CONFIG["runtime"]["marker"].lstrip("/")
        marker.write_text(json.dumps({"source_commit": "a"*40, "artifact_sha256": hashlib.sha256(b"old artifact").hexdigest()}))

    def test_reload_uses_current_binary_api_bridge_and_worker_fence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.fixture(root); service = Service(root, "runtime")
            with patch("release.subprocess.run") as validator:
                validator.return_value.returncode = 0
                result = release.reload_image_policies(b'{"new":true}', hashlib.sha256(b'{"old":true}').hexdigest(), root, service, 1, 0)
            self.assertEqual(result["status"], "verified")
            self.assertEqual((root/"etc/secure-provisioner/image-policies.json").read_bytes(), b'{"new":true}')
            self.assertIn("handoff_stop", service.events)
            self.assertLess(service.events.index("start_bridge"), service.events.index("handoff_stop"))
            self.assertEqual((root/CONFIG["runtime"]["artifact"].lstrip("/")).read_bytes(), b"old artifact")

    def test_stale_policy_validator_failure_and_bridge_failure_preserve_previous_catalog(self):
        for mode in ["stale", "validator", "bridge"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); self.fixture(root); service = Service(root, "runtime")
                digest = hashlib.sha256(b'{"old":true}').hexdigest() if mode != "stale" else "f"*64
                with patch("release.subprocess.run") as validator, patch.object(release.RuntimeBridge, "prepare") as bridge:
                    validator.return_value.returncode = 1 if mode == "validator" else 0
                    if mode == "bridge": bridge.side_effect = release.DeploymentError("bridge failed")
                    with self.assertRaises(release.DeploymentError):
                        release.reload_image_policies(b'{"new":true}', digest, root, service, 1, 0)
                self.assertEqual((root/"etc/secure-provisioner/image-policies.json").read_bytes(), b'{"old":true}')

    def test_failed_worker_health_restores_catalog_and_fences_before_rollback(self):
        class FailedWorker(Service):
            def request(self, path, token=None):
                return (503, {}) if self.restarts == 1 else super().request(path, token)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.fixture(root); service = FailedWorker(root, "runtime")
            with patch("release.subprocess.run") as validator:
                validator.return_value.returncode = 0
                with self.assertRaises(release.DeploymentError):
                    release.reload_image_policies(b'{"new":true}', hashlib.sha256(b'{"old":true}').hexdigest(), root, service, 1, 0)
            self.assertEqual((root/"etc/secure-provisioner/image-policies.json").read_bytes(), b'{"old":true}')
            self.assertEqual(service.events.count("handoff_stop"), 2)
            self.assertEqual(service.restarts, 2)


if __name__ == "__main__": unittest.main()
