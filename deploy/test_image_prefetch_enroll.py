import copy
import errno
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import image_prefetch_enroll as enroll


IMAGE = "ghcr.io/msg-ctf/runtime-image-agent@sha256:" + "a" * 64
TARGET = "de42849c-e0dc-43d4-8e63-9bb2bd056db4"


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
    def __init__(self):
        self.node = node()
        self.pods = [pod()]
        self.queries = []

    def query(self, kubeconfig, args):
        self.queries.append((str(kubeconfig), args))
        if args == ["get", "node", "runtime-a", "-o", "json"]:
            return copy.deepcopy(self.node)
        if args == ["get", "pods", "--namespace", "runtime-image-preparation", "--field-selector",
                    "spec.nodeName=runtime-a", "--selector", "app.kubernetes.io/name=runtime-image-agent", "-o", "json"]:
            return {"kind": "PodList", "items": copy.deepcopy(self.pods)}
        raise AssertionError("unexpected Kubernetes command")


class EnrollmentTests(unittest.TestCase):
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
        def run(command, **kwargs):
            captured.append((command, kwargs))
            kwargs["stdout"].write(json.dumps(node()).encode())
            return type("Result", (), {"returncode": 0})()
        with patch.object(enroll.subprocess, "run", side_effect=run):
            client = enroll.KubernetesClient(str(self.directory / "kubectl"))
            observed = client.query(self.kubeconfig, ["get", "node", "runtime-a", "-o", "json"])
        self.assertEqual(observed["metadata"]["uid"], "uid-new")
        command, options = captured[0]
        self.assertEqual(command, [str(self.directory / "kubectl"), "--kubeconfig", str(self.kubeconfig),
            "--request-timeout=15s", "--insecure-skip-tls-verify=false", "get", "node", "runtime-a", "-o", "json"])
        self.assertEqual(options["stderr"], enroll.subprocess.DEVNULL)
        self.assertEqual(options["timeout"], 20)

    @unittest.skipIf(os.name != "posix", "POSIX ownership/mode enforcement")
    def test_world_writable_policy_or_symlink_cannot_authorize_enrollment(self):
        self.policy.chmod(0o666)
        with self.assertRaises(enroll.EnrollmentError): self.run_enrollment(apply=True)
        self.policy.chmod(0o600)
        link = self.directory / "symlink.json"
        link.symlink_to(self.policy)
        with self.assertRaises(enroll.EnrollmentError):
            enroll.reconcile(link, self.registry, self.output, client=self.cluster, apply=True)


if __name__ == "__main__":
    unittest.main()
