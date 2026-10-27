import copy
import base64
import errno
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import image_prefetch_enroll as enroll


IMAGE = "ghcr.io/msg-ctf/runtime-image-agent@sha256:" + "a" * 64
TARGET = "de42849c-e0dc-43d4-8e63-9bb2bd056db4"


def static_kubeconfig():
    return {"kind": "Config", "apiVersion": "v1", "preferences": {},
        "clusters": [{"name": "default", "cluster": {"server": "https://192.0.2.10:6443", "certificate-authority-data": "Y2E="}}],
        "users": [{"name": "default", "user": {"client-certificate-data": "Y2VydA==", "client-key-data": "a2V5"}}],
        "contexts": [{"name": "default", "context": {"cluster": "default", "user": "default"}}], "current-context": "default"}


def node(uid="uid-new", machine="machine-a", provider="gce://project/zone/runtime-a"):
    return {"apiVersion": "v1", "kind": "Node", "metadata": {"name": "runtime-a", "uid": uid,
            "labels": {"msgctf.io/image-preparation-agent": "true"}},
            "spec": {"providerID": provider}, "status": {"nodeInfo": {"machineID": machine,
            "bootID": "boot-a", "operatingSystem": "linux", "architecture": "amd64",
            "containerRuntimeVersion": "containerd://2.1.4-k3s1", "kubeletVersion": "v1.34.1+k3s1"},
            "conditions": [{"type": "Ready", "status": "True"}]}}


def pod(image=IMAGE):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "runtime-image-agent-abc",
            "namespace": "runtime-image-preparation", "uid": "pod-a",
            "labels": {"app.kubernetes.io/name": "runtime-image-agent"}, "ownerReferences": [
            {"kind": "DaemonSet", "name": "runtime-image-agent", "controller": True}]},
            "spec": {"nodeName": "runtime-a", "serviceAccountName": "image-agent",
            "containers": [{"name": "agent", "image": image}]}, "status": {"phase": "Running",
            "conditions": [{"type": "Ready", "status": "True"}]}}


class Cluster:
    def static_config(self, source):
        return enroll.static_kubeconfig(json.loads(source))

    def __init__(self):
        self.node = node()
        self.pods = [pod()]
        self.list_kind = "PodList"
        self.queries = []

    def query(self, kubeconfig, args):
        self.queries.append((str(kubeconfig), args))
        if args == ["get", "node", "runtime-a", "-o", "json"]:
            return copy.deepcopy(self.node)
        if args == ["get", "pods", "--namespace", "runtime-image-preparation", "--field-selector",
                    "spec.nodeName=runtime-a", "--selector", "app.kubernetes.io/name=runtime-image-agent", "-o", "json"]:
            return {"kind": self.list_kind, "items": copy.deepcopy(self.pods)}
        raise AssertionError("unexpected Kubernetes command")


class EnrollmentTests(unittest.TestCase):
    def test_real_kubectl_generic_list_registers_the_ready_pod(self):
        self.cluster.list_kind = "List"
        result = self.run_enrollment(apply=True)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(json.loads(self.output.read_text())["nodes"][0]["node_uid"], "uid-new")

    def test_generic_list_with_non_pod_item_preserves_trust(self):
        self.cluster.list_kind = "List"
        self.cluster.pods[0]["kind"] = "Node"
        before = self.output.read_bytes()
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(apply=True)
        self.assertEqual(self.output.read_bytes(), before)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.policy = self.directory / "enrollment.json"
        self.registry = self.directory / "clusters.json"
        self.output = self.directory / "nodes.json"
        self.receipt = self.directory / "receipt.json"
        self.kubeconfig = self.directory / "runtime.kubeconfig"
        self.write(self.kubeconfig, {})
        self.policy_data = {"version": 1, "nodes": [{"target_id": TARGET, "node_name": "runtime-a",
            "machine_id": "machine-a", "provider_id": "gce://project/zone/runtime-a", "architecture": "AMD64",
            "namespace": "runtime-image-preparation", "agent_image": IMAGE, "allow_replacement": False}]}
        self.registry_data = {"clusters": [{"target_id": TARGET, "enabled": True, "architecture": "amd64",
            "kubeconfig_path": str(self.kubeconfig)}]}
        self.write(self.policy, self.policy_data)
        self.write(self.registry, self.registry_data)
        self.write(self.output, {"nodes": [{"node_uid": "old-uid"}]})
        self.cluster = Cluster()

    def write(self, path, data):
        path.write_text(json.dumps(data), encoding="utf-8")
        path.chmod(0o600)

    def run_enrollment(self, **kwargs):
        return enroll.reconcile(self.policy, self.registry, self.output, client=self.cluster, **kwargs)

    def test_recreated_node_uid_is_enrolled_without_new_target_or_command(self):
        result = self.run_enrollment(apply=True)
        self.assertTrue(result["changed"])
        self.assertEqual(json.loads(self.output.read_text()), {"nodes": [{"target_id": TARGET,
            "node_name": "runtime-a", "node_uid": "uid-new", "machine_id": "machine-a", "mode": "kubernetes",
            "namespace": "runtime-image-preparation", "agent_image": IMAGE}]})
        self.cluster.node["metadata"]["uid"] = "uid-recreated"
        self.run_enrollment(apply=True)
        self.assertEqual(json.loads(self.output.read_text())["nodes"][0]["node_uid"], "uid-recreated")

    def test_dry_run_and_unchanged_config_do_not_write(self):
        original = self.output.read_bytes()
        self.run_enrollment()
        self.assertEqual(self.output.read_bytes(), original)
        self.run_enrollment(apply=True)
        before = self.output.stat().st_mtime_ns
        self.assertFalse(self.run_enrollment(apply=True)["changed"])
        self.assertEqual(self.output.stat().st_mtime_ns, before)

    def test_real_agent_container_defaults_mounts_and_resources_are_accepted(self):
        self.cluster.pods[0]["spec"]["containers"][0].update({
            "args": ["--idle"], "imagePullPolicy": "IfNotPresent", "resources": {"requests": {"cpu": "10m"}},
            "volumeMounts": [{"name": "cri", "mountPath": "/run/k3s/containerd/containerd.sock"}],
            "securityContext": {"runAsUser": 0, "readOnlyRootFilesystem": True}})
        self.run_enrollment(apply=True)
        self.assertEqual(json.loads(self.output.read_text())["nodes"][0]["node_uid"], "uid-new")

    def test_identity_platform_and_readiness_failures_preserve_complete_config(self):
        mutations = [lambda n: n["metadata"].update(name="unknown"), lambda n: n["metadata"].update(uid=""),
            lambda n: n["metadata"].update(deletionTimestamp="now"), lambda n: n["metadata"]["labels"].clear(),
            lambda n: n["spec"].update(providerID="gce://other/zone/runtime-a"),
            lambda n: n["spec"].update(unschedulable=True),
            lambda n: n["spec"].update(taints=[{"effect": "NoSchedule"}]),
            lambda n: n["status"]["nodeInfo"].update(machineID="other-machine"),
            lambda n: n["status"]["nodeInfo"].update(architecture="arm64"),
            lambda n: n["status"]["nodeInfo"].update(operatingSystem="windows"),
            lambda n: n["status"]["nodeInfo"].update(containerRuntimeVersion="docker://1"),
            lambda n: n["status"]["nodeInfo"].update(kubeletVersion="v1.34.1"),
            lambda n: n["status"]["conditions"][0].update(status="False")]
        original = self.output.read_bytes()
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.cluster.node = node()
                mutate(self.cluster.node)
                with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)
                self.assertEqual(self.output.read_bytes(), original)

    def test_agent_image_owner_and_ambiguous_pod_fail_closed(self):
        mutations = [lambda p: p["spec"]["containers"][0].update(image=IMAGE.replace("a" * 64, "b" * 64)),
            lambda p: p["metadata"]["ownerReferences"].clear(),
            lambda p: p["spec"].update(serviceAccountName="default"),
            lambda p: p["metadata"].update(deletionTimestamp="now"),
            lambda p: p["status"]["conditions"][0].update(status="False")]
        for mutate in mutations:
            self.cluster.pods = [pod()]
            mutate(self.cluster.pods[0])
            with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)
        self.cluster.pods = [pod(), pod()]
        with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)

    def test_unknown_disabled_or_wrong_architecture_registry_target_is_never_queried(self):
        for field, value in [("target_id", "unknown"), ("enabled", False), ("architecture", "arm64")]:
            registry = copy.deepcopy(self.registry_data)
            registry["clusters"][0][field] = value
            self.write(self.registry, registry)
            with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)
        self.assertEqual(self.cluster.queries, [])

    def test_unreachable_allowlisted_node_is_not_silently_dropped(self):
        original = self.output.read_bytes()
        with patch.object(self.cluster, "query", side_effect=enroll.EnrollmentError("KUBERNETES_UNAVAILABLE")):
            with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)
        self.assertEqual(self.output.read_bytes(), original)

    def test_failure_on_second_approved_node_preserves_the_whole_previous_file(self):
        second = copy.deepcopy(self.policy_data["nodes"][0])
        second["node_name"] = "runtime-b"
        self.policy_data["nodes"].append(second)
        self.write(self.policy, self.policy_data)
        original = self.output.read_bytes()
        query = self.cluster.query
        def unavailable_second(kubeconfig, args):
            if args == ["get", "node", "runtime-b", "-o", "json"]:
                raise enroll.EnrollmentError("KUBERNETES_UNAVAILABLE")
            return query(kubeconfig, args)
        with patch.object(self.cluster, "query", side_effect=unavailable_second):
            with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)
        self.assertEqual(self.output.read_bytes(), original)

    def test_policy_rejects_commands_unknown_fields_duplicate_slots_and_unpinned_image(self):
        for field, value in [("command", "/bin/sh"), ("agent_image", "ghcr.io/msg-ctf/agent:latest"),
                             ("node_name", "--all"), ("machine_id", "")]:
            policy = copy.deepcopy(self.policy_data)
            policy["nodes"][0][field] = value
            self.write(self.policy, policy)
            with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)
        self.policy_data["nodes"].append(copy.deepcopy(self.policy_data["nodes"][0]))
        self.write(self.policy, self.policy_data)
        with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)

    def test_provisioning_receipt_updates_only_opted_in_same_target_slot(self):
        receipt = {"version": 1, "target_id": TARGET, "node_name": "runtime-a",
            "previous_machine_id": "machine-a", "previous_provider_id": "gce://project/zone/runtime-a",
            "machine_id": "machine-replacement", "provider_id": "gce://project/zone/runtime-a-new"}
        self.write(self.receipt, receipt)
        self.cluster.node = node(machine="machine-replacement", provider="gce://project/zone/runtime-a-new")
        with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True, receipt_path=self.receipt)
        self.policy_data["nodes"][0]["allow_replacement"] = True
        self.write(self.policy, self.policy_data)
        self.run_enrollment(apply=True, receipt_path=self.receipt)
        self.assertEqual(json.loads(self.policy.read_text())["nodes"][0]["machine_id"], "machine-replacement")
        self.assertEqual(json.loads(self.output.read_text())["nodes"][0]["node_uid"], "uid-new")
        with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True, receipt_path=self.receipt)

    def test_receipt_cannot_change_target_or_replay_stale_identity(self):
        self.policy_data["nodes"][0]["allow_replacement"] = True
        self.write(self.policy, self.policy_data)
        for target, previous in [("unknown-target", "machine-a"), (TARGET, "stale-machine")]:
            self.write(self.receipt, {"version": 1, "target_id": target, "node_name": "runtime-a",
                "previous_machine_id": previous, "previous_provider_id": "gce://project/zone/runtime-a",
                "machine_id": "machine-b", "provider_id": "gce://project/zone/runtime-b"})
            before = self.policy.read_bytes()
            with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True, receipt_path=self.receipt)
            self.assertEqual(self.policy.read_bytes(), before)

    def test_failed_replacement_verification_does_not_publish_new_identity(self):
        self.policy_data["nodes"][0]["allow_replacement"] = True
        self.write(self.policy, self.policy_data)
        self.write(self.receipt, {"version": 1, "target_id": TARGET, "node_name": "runtime-a",
            "previous_machine_id": "machine-a", "previous_provider_id": "gce://project/zone/runtime-a",
            "machine_id": "machine-b", "provider_id": "gce://project/zone/runtime-b"})
        before = self.policy.read_bytes()
        with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True, receipt_path=self.receipt)
        self.assertEqual(self.policy.read_bytes(), before)

    def test_operator_revocation_during_replacement_queries_is_not_overwritten(self):
        self.policy_data["nodes"][0]["allow_replacement"] = True
        self.write(self.policy, self.policy_data)
        self.write(self.receipt, {"version": 1, "target_id": TARGET, "node_name": "runtime-a",
            "previous_machine_id": "machine-a", "previous_provider_id": "gce://project/zone/runtime-a",
            "machine_id": "machine-b", "provider_id": "gce://project/zone/runtime-b"})
        self.cluster.node = node(machine="machine-b", provider="gce://project/zone/runtime-b")
        original_output = self.output.read_bytes()
        query = self.cluster.query
        def revoke_after_pod_query(kubeconfig, args):
            result = query(kubeconfig, args)
            if args[1] == "pods":
                revoked = copy.deepcopy(self.policy_data)
                revoked["nodes"][0]["allow_replacement"] = False
                replacement = self.directory / "operator-policy.json"
                self.write(replacement, revoked)
                os.replace(replacement, self.policy)
            return result
        with patch.object(self.cluster, "query", side_effect=revoke_after_pod_query):
            with self.assertRaisesRegex(enroll.EnrollmentError, "POLICY_CHANGED"):
                self.run_enrollment(apply=True, receipt_path=self.receipt)
        self.assertFalse(json.loads(self.policy.read_text())["nodes"][0]["allow_replacement"])
        self.assertEqual(self.output.read_bytes(), original_output)

    def test_operator_policy_change_during_ordinary_reconcile_does_not_publish_stale_trust(self):
        original_output = self.output.read_bytes()
        query = self.cluster.query
        def repin_after_query(kubeconfig, args):
            result = query(kubeconfig, args)
            if args[1] == "pods":
                repinned = copy.deepcopy(self.policy_data)
                repinned["nodes"][0]["machine_id"] = "other-approved-machine"
                replacement = self.directory / "operator-policy.json"
                self.write(replacement, repinned)
                os.replace(replacement, self.policy)
            return result
        with patch.object(self.cluster, "query", side_effect=repin_after_query):
            with self.assertRaisesRegex(enroll.EnrollmentError, "POLICY_CHANGED"):
                self.run_enrollment(apply=True)
        self.assertEqual(self.output.read_bytes(), original_output)

    def test_supported_operator_policy_publish_shares_the_enrollment_lock(self):
        candidate = self.directory / "reviewed-policy.json"
        revoked = copy.deepcopy(self.policy_data)
        revoked["nodes"][0]["allow_replacement"] = False
        self.write(candidate, revoked)
        original = self.policy.read_bytes()
        with enroll.enrollment_lock(self.output):
            with self.assertRaisesRegex(enroll.EnrollmentError, "ENROLLMENT_BUSY"):
                enroll.publish_policy(self.policy, self.output, candidate, apply=True)
        self.assertEqual(self.policy.read_bytes(), original)
        output = io.StringIO()
        with redirect_stdout(output):
            status = enroll.main(["publish-policy", "--policy", str(self.policy), "--output", str(self.output),
                                  "--candidate", str(candidate), "--apply"])
        self.assertEqual(status, 0)
        self.assertFalse(json.loads(self.policy.read_text())["nodes"][0]["allow_replacement"])
        self.assertEqual(json.loads(output.getvalue())["status"], "APPLIED")

    @unittest.skipIf(os.name != "nt", "native Windows byte-range locking")
    def test_windows_lock_initialization_conflict_is_classified_as_busy(self):
        with patch.object(enroll.os, "write", side_effect=PermissionError(errno.EACCES, "simulated lock conflict")):
            with self.assertRaisesRegex(enroll.EnrollmentError, "ENROLLMENT_BUSY"):
                with enroll.enrollment_lock(self.output): self.fail("conflicting lock was acquired")

    @unittest.skipIf(os.name != "nt", "native Windows byte-range locking")
    def test_windows_lock_preserves_unrelated_io_failure(self):
        with patch("msvcrt.locking", side_effect=OSError(errno.EIO, "simulated unrelated IO failure")):
            with self.assertRaises(OSError) as caught:
                with enroll.enrollment_lock(self.output): self.fail("broken lock was acquired")
        self.assertEqual(caught.exception.errno, errno.EIO)

    @unittest.skipIf(os.name != "posix", "POSIX output ownership/mode preservation")
    def test_atomic_refresh_preserves_read_only_root_operator_output_mode(self):
        self.output.chmod(0o440)
        before = self.output.stat()
        self.run_enrollment(apply=True)
        after = self.output.stat()
        self.assertEqual(after.st_mode & 0o777, 0o440)
        self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
        self.assertEqual(json.loads(self.output.read_text())["nodes"][0]["node_uid"], "uid-new")

    @unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "actual service-owned credential fixture requires Linux root")
    def test_root_job_accepts_only_explicit_runtime_credential_owner(self):
        import pwd
        runtime_uid = pwd.getpwnam("nobody").pw_uid
        os.chown(self.kubeconfig, runtime_uid, -1)
        self.kubeconfig.chmod(0o600)
        with self.assertRaisesRegex(enroll.EnrollmentError, "UNTRUSTED_FILE"):
            self.run_enrollment(apply=True)
        output = io.StringIO()
        with patch.object(enroll, "KubernetesClient", return_value=self.cluster), redirect_stdout(output):
            status = enroll.main(["reconcile", "--policy", str(self.policy), "--registry", str(self.registry),
                "--output", str(self.output), "--runtime-user", "nobody", "--apply"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(self.output.read_text())["nodes"][0]["node_uid"], "uid-new")
        os.chown(self.policy, runtime_uid, -1)
        with self.assertRaisesRegex(enroll.EnrollmentError, "UNTRUSTED_FILE"):
            self.run_enrollment(apply=True, runtime_uid=runtime_uid)

    def test_locked_operator_revocation_is_never_reenabled_by_a_provisioning_hook(self):
        self.policy_data["nodes"][0]["allow_replacement"] = True
        self.write(self.policy, self.policy_data)
        candidate = self.directory / "reviewed-policy.json"
        revoked = copy.deepcopy(self.policy_data)
        revoked["nodes"][0]["allow_replacement"] = False
        self.write(candidate, revoked)
        self.write(self.receipt, {"version": 1, "target_id": TARGET, "node_name": "runtime-a",
            "previous_machine_id": "machine-a", "previous_provider_id": "gce://project/zone/runtime-a",
            "machine_id": "machine-b", "provider_id": "gce://project/zone/runtime-b"})
        query = self.cluster.query
        def revoke_while_hook_is_running(kubeconfig, args):
            result = query(kubeconfig, args)
            with self.assertRaisesRegex(enroll.EnrollmentError, "ENROLLMENT_BUSY"):
                enroll.publish_policy(self.policy, self.output, candidate, apply=True)
            return result
        self.cluster.node = node(machine="machine-b", provider="gce://project/zone/runtime-b")
        with patch.object(self.cluster, "query", side_effect=revoke_while_hook_is_running):
            self.run_enrollment(apply=True, receipt_path=self.receipt)
        # The supported operator retries only after acquiring the same lock.
        enroll.publish_policy(self.policy, self.output, candidate, apply=True)
        before = self.policy.read_bytes()
        with self.assertRaisesRegex(enroll.EnrollmentError, "REPLACEMENT_NOT_ALLOWED"):
            self.run_enrollment(apply=True, receipt_path=self.receipt)
        self.assertEqual(self.policy.read_bytes(), before)
        self.assertFalse(json.loads(self.policy.read_text())["nodes"][0]["allow_replacement"])

    def test_trusted_provisioning_cli_hook_publishes_replacement_without_request_fields(self):
        self.policy_data["nodes"][0]["allow_replacement"] = True
        self.write(self.policy, self.policy_data)
        self.write(self.receipt, {"version": 1, "target_id": TARGET, "node_name": "runtime-a",
            "previous_machine_id": "machine-a", "previous_provider_id": "gce://project/zone/runtime-a",
            "machine_id": "machine-b", "provider_id": "gce://project/zone/runtime-b"})
        self.cluster.node = node(machine="machine-b", provider="gce://project/zone/runtime-b")
        output = io.StringIO()
        with patch.object(enroll, "KubernetesClient", return_value=self.cluster), redirect_stdout(output):
            status = enroll.main(["accept-provisioned", "--policy", str(self.policy), "--registry", str(self.registry),
                                  "--output", str(self.output), "--receipt", str(self.receipt), "--apply"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue()), {"status": "APPLIED", "nodes": 1, "changed": True, "replacement": True})
        self.assertEqual(json.loads(self.output.read_text())["nodes"][0]["node_uid"], "uid-new")

    def test_cli_never_prints_upstream_exception_or_config_contents(self):
        error = io.StringIO()
        with patch.object(enroll, "KubernetesClient", return_value=self.cluster), \
                patch.object(self.cluster, "query", side_effect=OSError("secret-in-upstream-diagnostic")), redirect_stderr(error):
            status = enroll.main(["reconcile", "--policy", str(self.policy), "--registry", str(self.registry), "--output", str(self.output)])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(error.getvalue()), {"status": "FAILED", "error_code": "ENROLLMENT_FAILED"})

    def test_kubectl_boundary_uses_read_only_fixed_arguments_and_validates_tls(self):
        captured = []
        config = static_kubeconfig()
        self.write(self.kubeconfig, config)
        def run(command, **kwargs):
            captured.append((command, kwargs))
            if "config" in command:
                self.assertEqual(json.loads(kwargs["input"]), config)
                response = config
            else:
                snapshot = Path(command[2])
                self.assertNotEqual(snapshot, self.kubeconfig)
                self.assertEqual(json.loads(snapshot.read_bytes()), config)
                if os.name == "posix":
                    self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(snapshot.stat().st_uid, os.geteuid())
                response = node()
            kwargs["stdout"].write(json.dumps(response).encode())
            return type("Result", (), {"returncode": 0})()
        with patch.object(enroll.subprocess, "run", side_effect=run):
            client = enroll.KubernetesClient(str(self.directory / "kubectl"))
            observed = client.query(self.kubeconfig, ["get", "node", "runtime-a", "-o", "json"])
        self.assertEqual(observed["metadata"]["uid"], "uid-new")
        self.assertEqual(captured[0][0], [str(self.directory / "kubectl"), "--kubeconfig", "/dev/stdin", "config", "view", "--raw", "-o", "json"])
        command, options = captured[1]
        self.assertEqual(command[3:], ["--request-timeout=15s", "--insecure-skip-tls-verify=false", "get", "node", "runtime-a", "-o", "json"])
        self.assertFalse(Path(command[2]).exists())
        self.assertEqual(options["stderr"], enroll.subprocess.DEVNULL)
        self.assertEqual(options["timeout"], 20)

    def test_kubeconfig_plugins_references_and_nonstatic_auth_are_rejected_before_get(self):
        mutations = [lambda c: c["users"][0]["user"].update(exec={"command": "/bin/sh", "args": ["-c", "malicious"]}),
            lambda c: c["users"][0]["user"].update({"auth-provider": {"name": "gcp"}}),
            lambda c: c["users"][0]["user"].update(tokenFile="/etc/shadow"),
            lambda c: c["users"][0]["user"].update({"client-key": "/root/private.key"}),
            lambda c: c["users"][0]["user"].update({"client-certificate": "/root/private.crt"}),
            lambda c: c["users"][0]["user"].update(username="root", password="password"),
            lambda c: c["users"][0]["user"].update({"as": "system:admin"}),
            lambda c: c["clusters"][0]["cluster"].update({"certificate-authority": "/root/private-ca"}),
            lambda c: c["clusters"][0]["cluster"].update({"proxy-url": "http://localhost:8080"}),
            lambda c: c["clusters"][0]["cluster"].update({"insecure-skip-tls-verify": True}),
            lambda c: c["clusters"][0]["cluster"].update(server="http://192.0.2.10:6443")]
        for mutate in mutations:
            config = static_kubeconfig()
            mutate(config)
            commands = []
            def run(command, **kwargs):
                commands.append(command)
                self.assertIn("config", command)
                kwargs["stdout"].write(json.dumps(config).encode())
                return type("Result", (), {"returncode": 0})()
            with patch.object(enroll.subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(enroll.EnrollmentError, "UNSUPPORTED_KUBECONFIG"):
                    enroll.KubernetesClient(str(self.directory / "kubectl")).query(self.kubeconfig, ["get", "node", "runtime-a", "-o", "json"])
            self.assertEqual(len(commands), 1)

    def test_mutating_original_kubeconfig_cannot_change_the_frozen_get(self):
        original = static_kubeconfig()
        malicious = copy.deepcopy(original)
        malicious["users"][0]["user"]["exec"] = {"command": "/bin/sh"}
        self.write(self.kubeconfig, original)
        snapshots = []
        def run(command, **kwargs):
            if "config" in command:
                self.assertEqual(json.loads(kwargs["input"]), original)
                self.write(self.kubeconfig, malicious)
                response = original
            else:
                snapshots.append(Path(command[2]))
                self.assertEqual(json.loads(snapshots[-1].read_bytes()), original)
                response = node()
            kwargs["stdout"].write(json.dumps(response).encode())
            return type("Result", (), {"returncode": 0})()
        with patch.object(enroll.subprocess, "run", side_effect=run):
            observed = enroll.KubernetesClient(str(self.directory / "kubectl")).query(self.kubeconfig, ["get", "node", "runtime-a", "-o", "json"])
        self.assertEqual(observed["metadata"]["uid"], "uid-new")
        self.assertEqual(len(snapshots), 1)
        self.assertFalse(snapshots[0].exists())

    def test_static_token_snapshot_is_cleaned_up_when_get_fails(self):
        config = static_kubeconfig()
        config["users"][0]["user"] = {"token": "embedded-test-token"}
        snapshots = []
        def run(command, **kwargs):
            if "config" in command:
                kwargs["stdout"].write(json.dumps(config).encode())
                return type("Result", (), {"returncode": 0})()
            snapshots.append(Path(command[2]))
            self.assertEqual(json.loads(snapshots[-1].read_bytes())["users"][0]["user"], {"token": "embedded-test-token"})
            return type("Result", (), {"returncode": 1})()
        with patch.object(enroll.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(enroll.EnrollmentError, "KUBERNETES_UNAVAILABLE"):
                enroll.KubernetesClient(str(self.directory / "kubectl")).query(self.kubeconfig, ["get", "node", "runtime-a", "-o", "json"])
        self.assertEqual(len(snapshots), 1)
        self.assertFalse(snapshots[0].exists())

    @unittest.skipUnless(os.name == "posix" and shutil.which("kubectl"), "local Linux kubectl conversion")
    def test_real_config_view_does_not_execute_a_credential_plugin(self):
        marker = self.directory / "plugin-executed"
        config = static_kubeconfig()
        config["users"][0]["user"]["exec"] = {"apiVersion": "client.authentication.k8s.io/v1beta1",
            "command": "/usr/bin/touch", "args": [str(marker)], "interactiveMode": "Never"}
        self.write(self.kubeconfig, config)
        client = enroll.KubernetesClient(shutil.which("kubectl"))
        original = client.json_command
        def conversion_only(command, **kwargs):
            self.assertEqual(command[3:5], ["config", "view"])
            return original(command, **kwargs)
        with patch.object(client, "json_command", side_effect=conversion_only):
            with self.assertRaisesRegex(enroll.EnrollmentError, "UNSUPPORTED_KUBECONFIG"):
                client.query(self.kubeconfig, ["get", "node", "runtime-a", "-o", "json"])
        self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix" and shutil.which("kubectl"), "local Linux kubectl conversion")
    def test_real_config_view_static_conversion_uses_only_frozen_get_config(self):
        config = static_kubeconfig()
        self.write(self.kubeconfig, config)
        client = enroll.KubernetesClient(shutil.which("kubectl"))
        original = client.json_command
        def local_conversion_fake_network(command, **kwargs):
            if command[3:5] == ["config", "view"]:
                return original(command, **kwargs)
            self.assertNotEqual(Path(command[2]), self.kubeconfig)
            self.assertEqual(json.loads(Path(command[2]).read_bytes()), config)
            return node()
        with patch.object(client, "json_command", side_effect=local_conversion_fake_network):
            self.assertEqual(client.query(self.kubeconfig, ["get", "node", "runtime-a", "-o", "json"])["metadata"]["uid"], "uid-new")

    @unittest.skipIf(os.name != "posix", "POSIX ancestor no-follow checks")
    def test_credential_ancestor_symlink_cannot_redirect_root_read(self):
        actual = self.directory / "actual"
        leaf = actual / "leaf"
        leaf.mkdir(parents=True, mode=0o700)
        credential = leaf / "config"
        self.write(credential, static_kubeconfig())
        link = self.directory / "linked"
        link.symlink_to(actual, target_is_directory=True)
        with patch.object(enroll.subprocess, "run") as command:
            with self.assertRaises(enroll.EnrollmentError):
                enroll.KubernetesClient(str(self.directory / "kubectl")).query(link / "leaf" / "config", ["get", "node", "runtime-a", "-o", "json"])
        command.assert_not_called()

    @unittest.skipIf(os.name != "posix", "POSIX ownership/mode enforcement")
    def test_world_writable_policy_or_symlink_cannot_authorize_enrollment(self):
        self.policy.chmod(0o666)
        with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)
        self.policy.chmod(0o600)
        link = self.directory / "symlink.json"
        link.symlink_to(self.policy)
        with self.assertRaises(enroll.EnrollmentError):
            enroll.reconcile(link, self.registry, self.output, client=self.cluster, apply=True)


class BrokerEnrollmentTests(unittest.TestCase):
    setUp = EnrollmentTests.setUp
    write = EnrollmentTests.write
    run_enrollment = EnrollmentTests.run_enrollment

    def broker(self, uid="uid-new"):
        self.state = self.directory / "targets.json"
        approved = self.policy_data["nodes"][0]
        approved.update(target_id=uid, broker_resource_target_id=TARGET)
        self.write(self.policy, self.policy_data)
        self.write(self.registry, {"clusters": []})
        self.state_data = {"version": 1, "targets": {uid: {
            "config": {"target_id": uid, "broker_resource_target_id": TARGET,
                "architecture": "amd64", "enabled": True, "kubeconfig_path": "broker://" + TARGET + "/" + uid},
            "credential": {"schema_version": 1, "resource_target_id": TARGET, "target_id": uid,
                "server_url": "https://192.0.2.10:6443",
                "kubeconfig_base64": base64.b64encode(json.dumps(static_kubeconfig()).encode()).decode()},
            "desired_enabled": True}}}
        self.write(self.state, self.state_data)

    def test_admitted_broker_target_does_not_need_static_materialization(self):
        self.broker()
        result = self.run_enrollment(apply=True, broker_state_path=self.state)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(json.loads(self.output.read_text())["nodes"][0]["target_id"], "uid-new")
        self.assertTrue(self.cluster.queries)
        for path, _ in self.cluster.queries:
            self.assertFalse(Path(path).exists(), "temporary credential must be removed")

    def test_canonical_rotation_requires_opt_in_and_keeps_machine_pins(self):
        self.broker()
        self.policy_data["nodes"][0]["target_id"] = "uid-old"
        self.write(self.policy, self.policy_data)
        before = self.output.read_bytes()
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(apply=True, broker_state_path=self.state)
        self.assertEqual(self.output.read_bytes(), before)
        self.policy_data["nodes"][0]["allow_target_rotation"] = True
        self.write(self.policy, self.policy_data)
        self.run_enrollment(apply=True, broker_state_path=self.state)
        self.cluster.node["status"]["nodeInfo"]["machineID"] = "unapproved"
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(apply=True, broker_state_path=self.state)

    def test_invalid_admitted_entries_never_query_or_replace(self):
        mutations = [lambda e: e["config"].update(enabled=False),
            lambda e: e.update(desired_enabled=False), lambda e: e["config"].update(architecture="arm64"),
            lambda e: e["credential"].update(target_id="other"),
            lambda e: e["credential"].update(resource_target_id="other"),
            lambda e: e["config"].update(target_id="other"),
            lambda e: e["config"].update(kubeconfig_path="/tmp/config"),
            lambda e: e["credential"].update(server_url="http://insecure"),
            lambda e: e["credential"].update(kubeconfig_base64="!invalid!")]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.broker()
                mutate(self.state_data["targets"]["uid-new"])
                self.write(self.state, self.state_data)
                before = self.output.read_bytes()
                with self.assertRaises(enroll.EnrollmentError):
                    self.run_enrollment(apply=True, broker_state_path=self.state)
                self.assertEqual(self.output.read_bytes(), before)
        self.assertEqual(self.cluster.queries, [])

    def test_static_collision_and_duplicate_resource_fail_closed(self):
        self.broker()
        self.registry_data["clusters"][0]["target_id"] = "uid-new"
        self.write(self.registry, self.registry_data)
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(broker_state_path=self.state)
        self.write(self.registry, {"clusters": []})
        other = copy.deepcopy(self.state_data["targets"]["uid-new"])
        self.state_data["targets"]["other-uid"] = other
        self.write(self.state, self.state_data)
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(broker_state_path=self.state)
        self.assertEqual(self.cluster.queries, [])

    def test_actual_node_uid_must_match_admitted_canonical_target(self):
        self.broker()
        self.cluster.node["metadata"]["uid"] = "not-admitted"
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(apply=True, broker_state_path=self.state)

    def test_broker_edit_during_remote_validation_preserves_registration(self):
        self.broker()
        query = self.cluster.query
        def changed_source(path, args):
            result = query(path, args)
            self.state_data["targets"]["uid-new"]["desired_enabled"] = False
            self.write(self.state, self.state_data)
            return result
        before = self.output.read_bytes()
        with patch.object(self.cluster, "query", side_effect=changed_source):
            with self.assertRaisesRegex(enroll.EnrollmentError, "BROKER_STATE_CHANGED"):
                self.run_enrollment(apply=True, broker_state_path=self.state)
        self.assertEqual(self.output.read_bytes(), before)
        self.assertFalse(Path(self.cluster.queries[0][0]).exists())

    def test_broker_embedded_plugins_and_server_mismatch_never_query(self):
        for mutation in ("exec", "server"):
            self.broker()
            entry = self.state_data["targets"]["uid-new"]
            if mutation == "exec":
                config = static_kubeconfig()
                config["users"][0]["user"]["exec"] = {"command": "must-never-execute"}
                entry["credential"]["kubeconfig_base64"] = base64.b64encode(json.dumps(config).encode()).decode()
            else:
                entry["credential"]["server_url"] = "https://other.example"
            self.write(self.state, self.state_data)
            with self.assertRaises(enroll.EnrollmentError):
                self.run_enrollment(broker_state_path=self.state)
        self.assertEqual(self.cluster.queries, [])


class RegistrationReceiptTests(unittest.TestCase):
    setUp = EnrollmentTests.setUp
    write = EnrollmentTests.write
    run_enrollment = EnrollmentTests.run_enrollment

    def events(self):
        return self.directory / "events"

    def test_only_successful_apply_emits_deduplicated_generation(self):
        events = self.events()
        self.run_enrollment(events_dir=events)
        self.assertFalse(events.exists())
        self.run_enrollment(apply=True, events_dir=events)
        files = list(events.glob("*.json"))
        self.assertEqual(len(files), 1)
        original = files[0].read_bytes()
        event = json.loads(original)
        self.assertEqual(event["generation"]["boot_id"], "boot-a")
        self.assertEqual(event["generation"]["target_id"], TARGET)
        self.assertNotIn("kubeconfig", original.decode())
        self.run_enrollment(apply=True, events_dir=events)
        self.assertEqual(files[0].read_bytes(), original)
        self.cluster.node["status"]["nodeInfo"]["bootID"] = "boot-b"
        self.assertFalse(self.run_enrollment(apply=True, events_dir=events)["changed"])
        self.assertEqual(len(list(events.glob("*.json"))), 2)

    def test_failed_validation_or_publication_emits_nothing(self):
        self.cluster.pods = []
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(apply=True, events_dir=self.events())
        self.assertFalse(self.events().exists())
        self.cluster.pods = [pod()]
        with patch.object(enroll, "atomic_json", side_effect=enroll.EnrollmentError("CONFIG_WRITE_FAILED")):
            with self.assertRaises(enroll.EnrollmentError):
                self.run_enrollment(apply=True, events_dir=self.events())
        self.assertFalse(self.events().exists())

    def test_backfills_after_output_publication_without_touching_output(self):
        self.run_enrollment(apply=True)
        before = self.output.stat().st_mtime_ns
        self.run_enrollment(apply=True, events_dir=self.events())
        self.assertEqual(self.output.stat().st_mtime_ns, before)
        self.assertEqual(len(list(self.events().glob("*.json"))), 1)

    def test_conflicting_existing_receipt_is_not_overwritten(self):
        self.run_enrollment(apply=True, events_dir=self.events())
        event = next(self.events().glob("*.json"))
        self.write(event, {"conflict": True})
        before = event.read_bytes()
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(apply=True, events_dir=self.events())
        self.assertEqual(event.read_bytes(), before)

    @unittest.skipIf(os.name != "posix", "POSIX ancestor no-follow checks")
    def test_receipt_ancestor_symlink_is_rejected(self):
        actual = self.directory / "actual"
        actual.mkdir(mode=0o700)
        leaf = actual / "leaf"
        leaf.mkdir(mode=0o700)
        link = self.directory / "linked"
        link.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(apply=True, events_dir=link / "leaf" / "events")
        self.assertFalse((leaf / "events").exists())

    @unittest.skipIf(os.name != "posix", "POSIX directory permissions")
    def test_world_writable_or_symlink_receipt_directory_is_rejected(self):
        self.events().mkdir(mode=0o777)
        self.events().chmod(0o777)
        with self.assertRaises(enroll.EnrollmentError):
            self.run_enrollment(apply=True, events_dir=self.events())



if __name__ == "__main__":
    unittest.main()
