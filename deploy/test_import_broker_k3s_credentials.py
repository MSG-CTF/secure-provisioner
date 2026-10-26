import base64
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import import_broker_k3s_credentials as importer


RESOURCE = "de42849c-e0dc-43d4-8e63-9bb2bd056db4"
NODE = "99f2f3b0-495a-4a7a-9e84-b4b35a7d21b8"
OTHER = "bc53bb1f-baa7-4d2e-9036-1b6d17f9302d"


@unittest.skipUnless(os.name == "posix", "Linux deployment tool")
class CredentialImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = os.environ.get("RUNTIME_REGISTRY_VALIDATOR")
        if not cls.validator:
            raise unittest.SkipTest("Set RUNTIME_REGISTRY_VALIDATOR to a built Runtime binary")
        cls.certs = tempfile.TemporaryDirectory()
        root = Path(cls.certs.name)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-subj", "/CN=system:admin", "-days", "1", "-keyout", str(root / "key"),
                        "-out", str(root / "cert")], check=True, capture_output=True)
        cls.certificate = (root / "cert").read_text()
        cls.private_key = (root / "key").read_text()
        cls.expiry = subprocess.run(["openssl", "x509", "-noout", "-enddate"], input=cls.certificate,
                                    text=True, capture_output=True, check=True).stdout.strip().split("=", 1)[1]

    @classmethod
    def tearDownClass(cls):
        cls.certs.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.registry = self.root / "registry.json"
        self.candidate = self.root / "registry.candidate.json"
        self.original = {"clusters": [{"target_id": "unrelated-target", "enabled": False}]}
        self.registry.write_text(json.dumps(self.original))
        self.credentials = self.root / "credentials"
        self.template = {"provider": "GCP", "region": "us-central1", "architecture": "AMD64",
                         "public_gateway": "http://192.0.2.10", "exposure_mode": "NODE_PORT",
                         "enabled": False, "security_capabilities": {}}
        encoded = lambda value: base64.b64encode(value.encode()).decode()
        self.config = {"apiVersion": "v1", "kind": "Config", "current-context": "default",
                       "clusters": [{"name": "default", "cluster": {"server": "https://192.0.2.10:6443",
                                      "certificate-authority-data": encoded(self.certificate)}}],
                       "users": [{"name": "default", "user": {"client-certificate-data": encoded(self.certificate),
                                   "client-key-data": encoded(self.private_key)}}],
                       "contexts": [{"name": "default", "context": {"cluster": "default", "user": "default"}}]}
        self.raw_config = json.dumps(self.config)
        other_config = self.root / "other-kubeconfig.json"
        other_config.write_text(self.raw_config)
        self.original = {"clusters": [{**self.template, "target_id": "unrelated-target",
                                      "kubeconfig_path": str(other_config)}]}
        self.registry.write_text(json.dumps(self.original))
        expires = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(self.expiry), datetime.timezone.utc)
        self.credential = {"schema_version": 1, "resource_target_id": RESOURCE, "target_id": NODE,
                           "server_url": "https://192.0.2.10:6443", "kubeconfig_base64": encoded(self.raw_config),
                           "client_certificate_fingerprint_sha256": hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.certificate)).hexdigest(),
                           "client_certificate_not_after": expires.isoformat()}
        self.nodes = {"items": [{"metadata": {"uid": NODE}, "status": {
            "conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"architecture": "amd64"}}}]}

    def runner(self, args, *, input=None):
        if args[0] == "openssl" or "--validate-registry" in args:
            return importer.run_command(args, input=input)
        self.assertEqual(input, self.raw_config)
        if "view" in args:
            return json.dumps(self.config)
        return json.dumps(self.nodes)

    def perform(self, **extra):
        return importer.import_credential(self.credential, RESOURCE, self.registry,
                                          self.template, self.credentials, runner=self.runner,
                                          output_registry=self.candidate, validator_binary=self.validator, **extra)

    def test_import_registers_verified_scheduler_id_and_preserves_resource_identity(self):
        result = self.perform()
        entries = json.loads(self.candidate.read_text())["clusters"]
        self.assertEqual(entries[0], self.original["clusters"][0])
        self.assertEqual(entries[1]["target_id"], NODE)
        self.assertEqual(entries[1]["broker_resource_target_id"], RESOURCE)
        self.assertFalse(entries[1]["enabled"])
        secret = Path(entries[1]["kubeconfig_path"])
        self.assertEqual(secret.read_text(), self.raw_config)
        self.assertEqual(secret.stat().st_mode & 0o777, 0o640)
        self.assertEqual(result["target_id"], NODE)
        self.assertNotIn(self.private_key, json.dumps(result))
        self.assertNotIn(self.credential["kubeconfig_base64"], json.dumps(result))

    def test_reimport_updates_one_target_and_preserves_existing_policy(self):
        self.perform()
        self.registry.write_bytes(self.candidate.read_bytes())  # Simulate reviewed activation.
        self.template["enabled"] = True
        self.perform()
        entries = json.loads(self.candidate.read_text())["clusters"]
        self.assertEqual(len(entries), 2)
        self.assertFalse(entries[1]["enabled"])
        self.assertEqual(len(list(self.credentials.glob("*.yaml"))), 1)

    def test_explicit_legacy_migration_preserves_disabled_maintenance_route(self):
        legacy = {**self.original["clusters"][0], "target_id": RESOURCE, "enabled": True}
        self.original["clusters"].append(legacy)
        self.registry.write_text(json.dumps(self.original))
        with self.assertRaises(importer.ImportFailure):
            self.perform()
        result = self.perform(migrate_legacy=True)
        entries = json.loads(self.candidate.read_text())["clusters"]
        old = next(entry for entry in entries if entry["target_id"] == RESOURCE)
        current = next(entry for entry in entries if entry["target_id"] == NODE)
        self.assertEqual(old, {**legacy, "enabled": False})
        self.assertEqual(current["broker_resource_target_id"], RESOURCE)
        self.assertEqual(current["target_id"], NODE)
        self.assertEqual(result["target_id"], NODE)
        self.assertEqual(json.loads(self.registry.read_text()), self.original)

    def test_missing_wrong_and_stale_node_identity_do_not_modify_registry(self):
        for value in (None, "", OTHER):
            with self.subTest(target_id=value):
                self.credential["target_id"] = value
                with self.assertRaises(importer.ImportFailure):
                    self.perform()
                self.assertEqual(json.loads(self.registry.read_text()), self.original)
                self.assertFalse(self.credentials.exists())

    def test_unreachable_node_does_not_expose_command_stderr_or_write_credentials(self):
        def unavailable(args, *, input=None):
            if "nodes" in args:
                raise subprocess.CalledProcessError(1, args, stderr=self.private_key)
            return self.runner(args, input=input)
        with self.assertRaises(importer.ImportFailure) as failure:
            importer.import_credential(self.credential, RESOURCE, self.registry, self.template,
                                       self.credentials, runner=unavailable, output_registry=self.candidate,
                                       validator_binary=self.validator)
        self.assertNotIn(self.private_key, str(failure.exception))
        self.assertFalse(self.credentials.exists())

    def test_unsafe_kubeconfig_is_rejected(self):
        for mutate in (
            lambda c: c["users"][0]["user"].update(exec={"command": "unexpected"}),
            lambda c: c["clusters"][0]["cluster"].update({"insecure-skip-tls-verify": True}),
            lambda c: c["clusters"][0]["cluster"].update(server="https://other.invalid:6443"),
            lambda c: c.update({"current-context": "missing"}),
        ):
            old = copy.deepcopy(self.config)
            mutate(self.config)
            with self.assertRaises(importer.ImportFailure):
                self.perform()
            self.config = old
        self.assertFalse(self.credentials.exists())

    def test_certificate_metadata_must_match_embedded_certificate(self):
        for key, value in (("client_certificate_fingerprint_sha256", "0" * 64),
                           ("client_certificate_not_after", "2000-01-01T00:00:00Z")):
            original = self.credential[key]
            self.credential[key] = value
            with self.assertRaises(importer.ImportFailure):
                self.perform()
            self.credential[key] = original
        self.assertFalse(self.credentials.exists())

    def test_zero_multiple_or_unready_nodes_are_not_registered(self):
        for items in ([], self.nodes["items"] * 2,
                      [{"metadata": {"uid": NODE}, "status": {"conditions": []}}]):
            self.nodes = {"items": items}
            with self.assertRaises(importer.ImportFailure):
                self.perform()
        self.assertEqual(json.loads(self.registry.read_text()), self.original)

    def test_legacy_resource_id_and_changed_uid_require_explicit_migration(self):
        for entry in ({"target_id": RESOURCE},
                      {"target_id": OTHER, "broker_resource_target_id": RESOURCE},
                      {"target_id": NODE, "broker_resource_target_id": OTHER}):
            original = {"clusters": [entry]}
            self.registry.write_text(json.dumps(original))
            with self.assertRaises(importer.ImportFailure):
                self.perform()
            self.assertEqual(json.loads(self.registry.read_text()), original)

    def test_concurrent_registry_edit_is_preserved(self):
        edited = {"clusters": [{"target_id": "concurrent-entry", "enabled": False}]}
        def edit_during_observation(args, *, input=None):
            if "nodes" in args:
                self.registry.write_text(json.dumps(edited))
            return self.runner(args, input=input)
        with self.assertRaises(importer.ImportFailure):
            importer.import_credential(self.credential, RESOURCE, self.registry, self.template,
                                       self.credentials, runner=edit_during_observation, output_registry=self.candidate,
                                       validator_binary=self.validator)
        self.assertEqual(json.loads(self.registry.read_text()), edited)
        self.assertFalse(self.credentials.exists())

    def test_symlink_registry_is_rejected(self):
        link = self.root / "linked.json"
        link.symlink_to(self.registry)
        with self.assertRaises(importer.ImportFailure):
            importer.import_credential(self.credential, RESOURCE, link, self.template,
                                       self.credentials, runner=self.runner, output_registry=self.candidate,
                                       validator_binary=self.validator)
        self.assertEqual(json.loads(self.registry.read_text()), self.original)

    def test_import_never_replaces_the_live_registry(self):
        original = self.registry.read_bytes()
        self.perform()
        self.assertEqual(self.registry.read_bytes(), original)

    def test_enabled_template_missing_security_policy_is_rejected(self):
        self.template["enabled"] = True
        self.template.pop("security_capabilities")
        with self.assertRaises(importer.ImportFailure):
            self.perform()
        self.assertEqual(json.loads(self.registry.read_text()), self.original)

    def test_invalid_template_fields_are_rejected_by_native_runtime_validation(self):
        for field, value in (("provider", "UNKNOWN"), ("exposure_mode", "UNKNOWN"), ("typo", True)):
            original = copy.deepcopy(self.template)
            self.template[field] = value
            with self.assertRaises(importer.ImportFailure):
                self.perform()
            self.assertEqual(json.loads(self.registry.read_text()), self.original)
            self.assertFalse(self.credentials.exists())
            self.template = original

    def test_non_cooperating_writer_at_candidate_commit_keeps_its_live_edit(self):
        edited = {"clusters": [{"target_id": "concurrent-new-entry"}]}
        actual_write = importer.write_atomic
        def edit_before_candidate(path, *args, **kwargs):
            if Path(path) == self.candidate:
                self.registry.write_text(json.dumps(edited))
            return actual_write(path, *args, **kwargs)
        with patch.object(importer, "write_atomic", side_effect=edit_before_candidate):
            self.perform()
        self.assertEqual(json.loads(self.registry.read_text()), edited)
        self.assertTrue(self.candidate.exists())

    def test_output_must_never_alias_live_registry(self):
        with self.assertRaises(importer.ImportFailure):
            importer.import_credential(self.credential, RESOURCE, self.registry, self.template,
                                       self.credentials, runner=self.runner, output_registry=self.registry,
                                       validator_binary=self.validator)


if __name__ == "__main__":
    unittest.main()
