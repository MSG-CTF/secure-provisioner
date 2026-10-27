import copy
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError

import image_preparation_evidence as evidence
import image_prefetch_enroll as enroll
import test_image_prefetch_enroll as enrollment_tests
from test_image_prefetch_enroll import Cluster, TARGET


IMAGE = "ghcr.io/msg-ctf/challenges/test/web@sha256:" + "a" * 64
RESOLVED = "sha256:" + "b" * 64
CONFIG_ID = "sha256:" + "c" * 64
RELEASE = "6ab6c71d-bd53-46d0-b6b3-71f927b20ada"
OP = "39871efb-b67b-90f6-a76e-c5f57b79e3c7"


def scope():
    return {"release_id": RELEASE, "request_id": "backend-test", "architecture": "AMD64",
        "target_ids": [TARGET], "images": [IMAGE], "image_set_id": evidence.image_set_id("AMD64", [IMAGE])}


def operation():
    return {"operation_id": OP, "release_id": RELEASE, "request_id": "backend-test", "architecture": "AMD64",
        "image_set_id": evidence.image_set_id("AMD64", [IMAGE]), "status": "SUCCEEDED", "nodes": [
            {"target_id": TARGET, "node_uid": "uid-new", "node_name": "runtime-a", "architecture": "AMD64",
                "status": "READY", "observed_at": None, "images": [{"image": IMAGE,
                    "resolved_manifest_digest": RESOLVED, "status": "READY", "attempts": 1, "observed_at": None}]}]}


def readiness():
    return {"image_set_id": evidence.image_set_id("AMD64", [IMAGE]), "architecture": "AMD64", "targets": [
        {"target_id": TARGET, "ready": False, "ready_node_count": 0, "eligible_node_count": 0,
            "observed_at": None, "valid_until": None}]}


class HTTPFixture:
    def __init__(self):
        self.calls = []
        self.op = operation()
        self.ready = readiness()
        self.error = None
        self.raw = None

    def open(self, request, timeout):
        self.calls.append((request.get_method(), request.full_url, request.data))
        if self.error:
            raise self.error
        self.assert_path(request)
        value = self.op if request.get_method() == "GET" else self.ready
        return io.BytesIO(self.raw if self.raw is not None else json.dumps(value).encode())

    def assert_path(self, request):
        if request.get_method() == "GET":
            assert request.full_url.endswith("/v1/image-preparations/" + OP)
        else:
            assert request.get_method() == "POST" and request.full_url.endswith("/v1/image-readiness/query")


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.token = self.directory / "manager.token"
        self.token.write_text("x" * 64)
        self.token.chmod(0o600)
        self.http = HTTPFixture()
        self.api = evidence.RuntimeAPI("https://runtime.example", self.token, opener=self.http)

    def test_collect_checks_one_existing_operation_and_current_readiness_only(self):
        report = evidence.collect(self.api, scope(), OP)
        self.assertEqual(report["operation"]["status"], "SUCCEEDED")
        self.assertFalse(report["readiness"]["targets"][0]["ready"])
        self.assertIsNone(report["readiness"]["targets"][0]["observed_at"])
        self.assertIsNone(report["readiness"]["targets"][0]["valid_until"])
        self.assertEqual(report["pull_telemetry"], "UNKNOWN")
        self.assertEqual([c[0] for c in self.http.calls], ["GET", "POST"])
        self.assertNotIn("x" * 64, json.dumps(report))

    def test_operation_scope_mismatch_stops_before_readiness(self):
        for key, value in [("release_id", "other"), ("request_id", "other"), ("operation_id", "other"),
                ("architecture", "ARM64"), ("image_set_id", "sha256:" + "0" * 64)]:
            self.http.op = operation()
            self.http.op[key] = value
            with self.assertRaises(enroll.EnrollmentError):
                evidence.collect(self.api, scope(), OP)
        self.assertTrue(all(c[0] == "GET" for c in self.http.calls))

    def test_unexpected_target_image_or_duplicate_node_is_rejected(self):
        mutations = [lambda o: o["nodes"][0].update(target_id="other"),
            lambda o: o["nodes"][0]["images"][0].update(image=IMAGE.replace("test", "other")),
            lambda o: o["nodes"].append(copy.deepcopy(o["nodes"][0]))]
        for mutate in mutations:
            self.http.op = operation()
            mutate(self.http.op)
            with self.assertRaises(enroll.EnrollmentError): evidence.collect(self.api, scope(), OP)

    def test_missing_nodes_are_explicitly_unverified_not_ready(self):
        self.http.op.update(status="QUEUED", nodes=[])
        result = evidence.collect(self.api, scope(), OP)
        self.assertEqual(result["operation_target_scope"], "UNVERIFIED_NO_NODES")

    def test_readiness_scope_timestamps_and_expiry_are_preserved(self):
        now = datetime.now(timezone.utc)
        observed = (now - timedelta(minutes=2)).isoformat()
        expiry = (now - timedelta(minutes=1)).isoformat()
        self.http.ready["targets"][0].update(ready=True, ready_node_count=1, eligible_node_count=1,
            observed_at=observed, valid_until=expiry)
        report = evidence.collect(self.api, scope(), OP)
        self.assertEqual(report["readiness"]["targets"][0]["valid_until"], expiry)
        self.assertFalse(report["current_readiness"][TARGET])
        self.http.ready["targets"][0]["target_id"] = "other"
        with self.assertRaises(enroll.EnrollmentError): evidence.collect(self.api, scope(), OP)

    def test_runtime_partial_readiness_is_valid_advisory_evidence(self):
        now = datetime.now(timezone.utc)
        self.http.ready["targets"][0].update(ready=True, ready_node_count=1, eligible_node_count=2,
            observed_at=now.isoformat(), valid_until=(now + timedelta(minutes=1)).isoformat())
        result = evidence.collect(self.api, scope(), OP)
        self.assertTrue(result["current_readiness"][TARGET])
        self.assertEqual(result["readiness"]["targets"][0]["eligible_node_count"], 2)

    def test_runtime_no_eligible_nodes_failure_remains_reportable(self):
        self.http.op.update(status="FAILED", nodes=[], error_code="NO_ELIGIBLE_NODES")
        result = evidence.collect(self.api, scope(), OP)
        self.assertEqual(result["operation"]["error_code"], "NO_ELIGIBLE_NODES")
        self.assertEqual(result["operation_target_scope"], "UNVERIFIED_NO_NODES")

    def test_original_request_target_coverage_is_not_claimed_from_frozen_nodes(self):
        result = evidence.collect(self.api, scope(), OP)
        self.assertEqual(result["original_request_target_scope"], "UNAVAILABLE_IN_API")

    def test_cached_snapshot_never_claims_measured_cold_pull_or_zero_pull(self):
        snapshot = {"version": 1, "target_id": TARGET, "architecture": "AMD64", "node_uid": "uid-new",
            "machine_id": "machine-a", "boot_id": "boot-a", "observed_at": "2026-10-28T00:00:00Z",
            "images": [{"image": IMAGE, "cache_state": "PRESENT_VERIFIED", "resolved_manifest_digest": RESOLVED,
                "cri_config_image_id": CONFIG_ID}], "inspection_elapsed_seconds": 1.0}
        result = evidence.collect(self.api, scope(), OP, before=snapshot, after=copy.deepcopy(snapshot))
        self.assertEqual(result["cache_classification"], "PRESENT_AT_BOTH_SNAPSHOTS")
        self.assertEqual(result["pull_telemetry"], "UNKNOWN")
        self.assertIsNone(result["pull_elapsed_seconds"])
        self.assertEqual(result["before_cache"]["images"][0]["cri_config_image_id"], CONFIG_ID)
        snapshot["target_id"] = "other"
        with self.assertRaises(enroll.EnrollmentError):
            evidence.collect(self.api, scope(), OP, before=snapshot)

    def test_http_and_malformed_errors_are_fixed_codes_without_response_body(self):
        self.http.error = HTTPError("https://runtime.example", 403, "SECRET", {}, io.BytesIO(b"SECRET"))
        with self.assertRaisesRegex(enroll.EnrollmentError, "^RUNTIME_HTTP_403$"):
            evidence.collect(self.api, scope(), OP)
        self.http.error.close()
        self.http.error = None
        for raw in (b'{"status":"SECRET","status":"other"}', b"SECRET", b"a" * (enroll.LIMIT + 1)):
            self.http.raw = raw
            with self.assertRaises(enroll.EnrollmentError): evidence.collect(self.api, scope(), OP)

    def test_origin_validation_and_redirect_denial(self):
        for origin in ("http://runtime.example", "https://user:pass@runtime.example", "https://runtime.example/path",
                "https://runtime.example?token=SECRET", "https://runtime.example#fragment"):
            with self.assertRaises(enroll.EnrollmentError): evidence.RuntimeAPI(origin, self.token, opener=self.http)
        with self.assertRaises(enroll.EnrollmentError):
            evidence.NoRedirect().redirect_request(None, None, 302, "SECRET", {}, "https://other.example")

    def test_image_set_id_matches_runtime_go_serialization(self):
        daily = "ghcr.io/msg-ctf/challenges/web-daily-point/web@sha256:fc7c762ba95b154c2b00154ed89aedd1ba5f86020408a5300d06a9f8d92a4816"
        self.assertEqual(evidence.image_set_id("AMD64", [daily]),
            "sha256:fd4376ea144b5d1ffe96e6661ecfc1b8d1a6c603f6d65593ba1c325aedb42db2")

    def test_partially_observed_targets_are_explicit(self):
        expected = scope()
        expected["target_ids"].append("078d76df-9692-4574-8234-ed874f66c977")
        second = copy.deepcopy(self.http.ready["targets"][0])
        second["target_id"] = expected["target_ids"][1]
        self.http.ready["targets"].append(second)
        self.assertEqual(evidence.collect(self.api, expected, OP)["operation_target_scope"], "UNVERIFIED_PARTIAL_TARGETS")

    def test_unrelated_sensitive_fields_are_removed_and_malformed_values_rejected(self):
        self.http.op["environment"] = {"FLAG": "SECRET"}
        self.http.op["nodes"][0]["environment"] = {"PASSWORD": "SECRET"}
        self.http.ready["secret"] = "SECRET"
        self.assertNotIn("SECRET", json.dumps(evidence.collect(self.api, scope(), OP)))
        self.http.op["status"] = {"secret": "SECRET"}
        with self.assertRaises(enroll.EnrollmentError): evidence.collect(self.api, scope(), OP)

    @unittest.skipIf(os.name != "posix", "POSIX token mode")
    def test_world_readable_token_is_rejected(self):
        self.token.chmod(0o644)
        with self.assertRaises(enroll.EnrollmentError):
            evidence.RuntimeAPI("https://runtime.example", self.token, opener=self.http)


class InspectCluster(Cluster):
    def query(self, kubeconfig, args, *, source=None):
        if args[0] != "exec":
            return super().query(kubeconfig, args)
        self.queries.append((str(kubeconfig), args))
        assert args[-2:] == ["/usr/local/bin/image-agent", "--kubernetes"] or args[-2:] == ["inspecti", IMAGE]
        if args[-1] == "--kubernetes":
            assert json.loads(source) == {"image": IMAGE, "architecture": "AMD64", "pull": False}
            return {"evidence": {"image": IMAGE, "node_uid": "uid-new", "machine_id": "machine-a", "boot_id": "boot-a",
                "os": "linux", "architecture": "AMD64", "resolved_manifest_digest": RESOLVED, "complete": True}}
        return {"status": {"id": CONFIG_ID, "repoDigests": [IMAGE], "size": "46439641"}}


class SnapshotTests(unittest.TestCase):
    setUp = enrollment_tests.EnrollmentTests.setUp
    write = enrollment_tests.EnrollmentTests.write

    def test_snapshot_validates_current_node_and_uses_fixed_inspect_only_exec(self):
        client = InspectCluster()
        report = evidence.snapshot(self.policy, self.registry, scope(), client=client)
        self.assertEqual(report["images"][0]["cache_state"], "PRESENT_VERIFIED")
        self.assertEqual(report["images"][0]["cri_config_image_id"], CONFIG_ID)
        self.assertEqual(report["images"][0]["resolved_manifest_digest"], RESOLVED)
        self.assertEqual(report["node_uid"], "uid-new")
        self.assertEqual(len([c for c in client.queries if c[1][0] == "exec"]), 2)

    def test_unapproved_identity_never_gets_exec(self):
        client = InspectCluster()
        client.node["status"]["nodeInfo"]["machineID"] = "other-machine"
        with self.assertRaises(enroll.EnrollmentError):
            evidence.snapshot(self.policy, self.registry, scope(), client=client)
        self.assertFalse(any(args[0] == "exec" for _, args in client.queries))

    def test_boot_change_during_inspection_rejects_the_whole_snapshot(self):
        client = InspectCluster()
        original = client.query
        def changed(path, args, **kwargs):
            result = original(path, args, **kwargs)
            if args[0] == "exec":
                client.node["status"]["nodeInfo"]["bootID"] = "new-boot"
            return result
        client.query = changed
        with self.assertRaisesRegex(enroll.EnrollmentError, "SNAPSHOT_GENERATION_CHANGED"):
            evidence.snapshot(self.policy, self.registry, scope(), client=client)


if __name__ == "__main__":
    unittest.main()
