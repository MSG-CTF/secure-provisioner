#!/usr/bin/env python3
"""Reconcile operator-approved K3s identities into Runtime's trusted agent file.

This host-side tool only reads Kubernetes. It never deploys agents, pulls images,
executes pods, or accepts an enrollment request from an HTTP caller.
"""

import argparse
from contextlib import contextmanager
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


LIMIT = 1 << 20
LABEL = "msgctf.io/image-preparation-agent"
AGENT_LABEL = "app.kubernetes.io/name"
DNS = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*\Z")
IMAGE = re.compile(r"ghcr\.io/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}\Z")


class EnrollmentError(Exception):
    """Only fixed, non-sensitive error codes cross the CLI boundary."""


def identifier(value):
    return isinstance(value, str) and 0 < len(value) <= 128 and value.strip() == value and not any(
        char in value for char in "\r\n\0")


def unique_object(pairs):
    result = {}
    seen = set()
    for key, value in pairs:
        if key.lower() in seen:
            raise EnrollmentError("INVALID_JSON")
        seen.add(key.lower())
        result[key] = value
    return result


def decode(raw):
    try:
        if len(raw) > LIMIT:
            raise EnrollmentError("CONFIG_TOO_LARGE")
        return json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        raise EnrollmentError("INVALID_JSON") from None


def trusted_stat(info, *, credential_owner_uid=None):
    if not stat.S_ISREG(info.st_mode):
        raise EnrollmentError("UNTRUSTED_FILE")
    if os.name == "posix" and (info.st_uid not in (0, os.geteuid(), credential_owner_uid) or info.st_mode & 0o022):
        raise EnrollmentError("UNTRUSTED_FILE")


def trusted_parent(path, *, credential_owner_uid=None):
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise EnrollmentError("UNTRUSTED_DIRECTORY")
    if os.name == "posix":
        info = parent.stat()
        if info.st_uid not in (0, os.geteuid(), credential_owner_uid) or info.st_mode & 0o022:
            raise EnrollmentError("UNTRUSTED_DIRECTORY")


def revision(info, raw):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, hashlib.sha256(raw).digest())


def read_bytes(path, *, with_revision=False, credential_owner_uid=None):
    path = Path(path)
    trusted_parent(path, credential_owner_uid=credential_owner_uid)
    if path.is_symlink():
        raise EnrollmentError("UNTRUSTED_FILE")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as file:
            before = os.fstat(file.fileno())
            trusted_stat(before, credential_owner_uid=credential_owner_uid)
            raw = file.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise EnrollmentError("CONFIG_TOO_LARGE")
            after = os.fstat(file.fileno())
            trusted_stat(after, credential_owner_uid=credential_owner_uid)
            if revision(before, raw) != revision(after, raw):
                raise EnrollmentError("CONFIG_CHANGED")
            return (raw, revision(after, raw)) if with_revision else raw
    except OSError:
        raise EnrollmentError("CONFIG_UNAVAILABLE") from None


def read_json(path):
    return decode(read_bytes(path))


def validate_policy(value):
    if not isinstance(value, dict) or set(value) != {"version", "nodes"} or type(value["version"]) is not int or value["version"] != 1:
        raise EnrollmentError("INVALID_POLICY")
    nodes = value["nodes"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 256:
        raise EnrollmentError("INVALID_POLICY")
    required = {"target_id", "node_name", "machine_id", "provider_id", "architecture", "namespace", "agent_image"}
    seen = set()
    for node in nodes:
        if not isinstance(node, dict) or not required <= node.keys() or node.keys() - required - {"allow_replacement"}:
            raise EnrollmentError("INVALID_POLICY")
        key = (node["target_id"], node["node_name"]) if all(isinstance(node[k], str) for k in ("target_id", "node_name")) else None
        if key is None or key in seen or not identifier(node["target_id"]) or not identifier(node["machine_id"]):
            raise EnrollmentError("INVALID_POLICY")
        seen.add(key)
        if (len(node["node_name"]) > 253 or not DNS.fullmatch(node["node_name"]) or
                not isinstance(node["namespace"], str) or len(node["namespace"]) > 63 or "." in node["namespace"] or not DNS.fullmatch(node["namespace"]) or
                node["architecture"] not in ("AMD64", "ARM64") or
                not isinstance(node["provider_id"], str) or len(node["provider_id"]) > 512 or any(c in node["provider_id"] for c in "\r\n\0") or
                type(node.get("allow_replacement", False)) is not bool):
            raise EnrollmentError("INVALID_POLICY")
        image = node["agent_image"]
        if not isinstance(image, str) or len(image) > 512 or not IMAGE.fullmatch(image) or any(p in ("", ".", "..") for p in image.split("@")[0].split("/")[1:]):
            raise EnrollmentError("INVALID_POLICY")
    return value


def apply_receipt(policy, receipt):
    fields = {"version", "target_id", "node_name", "previous_machine_id", "previous_provider_id", "machine_id", "provider_id"}
    if not isinstance(receipt, dict) or set(receipt) != fields or type(receipt["version"]) is not int or receipt["version"] != 1:
        raise EnrollmentError("INVALID_PROVISIONING_RECEIPT")
    updated = copy.deepcopy(policy)
    selected = next((n for n in updated["nodes"] if n["target_id"] == receipt["target_id"] and n["node_name"] == receipt["node_name"]), None)
    if selected is None or not selected.get("allow_replacement", False):
        raise EnrollmentError("REPLACEMENT_NOT_ALLOWED")
    if selected["machine_id"] != receipt["previous_machine_id"] or selected["provider_id"] != receipt["previous_provider_id"] or selected["machine_id"] == receipt["machine_id"]:
        raise EnrollmentError("STALE_PROVISIONING_RECEIPT")
    selected["machine_id"] = receipt["machine_id"]
    selected["provider_id"] = receipt["provider_id"]
    return validate_policy(updated)


def registered_targets(registry, policy, *, runtime_uid=None):
    if not isinstance(registry, dict) or set(registry) != {"clusters"} or not isinstance(registry["clusters"], list):
        raise EnrollmentError("INVALID_RUNTIME_REGISTRY")
    targets = {}
    for cluster in registry["clusters"]:
        if not isinstance(cluster, dict) or not identifier(cluster.get("target_id")) or cluster["target_id"] in targets:
            raise EnrollmentError("INVALID_RUNTIME_REGISTRY")
        targets[cluster["target_id"]] = cluster
    selected = {}
    for node in policy["nodes"]:
        cluster = targets.get(node["target_id"])
        if (cluster is None or cluster.get("enabled") is not True or not isinstance(cluster.get("architecture"), str) or
                cluster["architecture"].upper() != node["architecture"] or not isinstance(cluster.get("kubeconfig_path"), str) or
                not Path(cluster["kubeconfig_path"]).is_absolute()):
            raise EnrollmentError("TARGET_NOT_REGISTERED_OR_ENABLED")
        # Reuse the registry's exact trusted kubeconfig, never a receipt-supplied path.
        read_bytes(cluster["kubeconfig_path"], credential_owner_uid=runtime_uid)
        selected[node["target_id"]] = Path(cluster["kubeconfig_path"])
    return selected


class KubernetesClient:
    def __init__(self, binary="/usr/local/bin/kubectl"):
        if not Path(binary).is_absolute():
            raise EnrollmentError("INVALID_KUBECTL_PATH")
        self.binary = binary

    def query(self, kubeconfig, args):
        command = [self.binary, "--kubeconfig", str(kubeconfig), "--request-timeout=15s", "--insecure-skip-tls-verify=false", *args]
        try:
            # Never retain or print kubectl stderr, which may contain credentials.
            # Disk-backed stdout prevents an unbounded response in process memory.
            with tempfile.TemporaryFile() as output:
                completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                                           timeout=20, check=False)
                if completed.returncode:
                    raise EnrollmentError("KUBERNETES_UNAVAILABLE")
                output.seek(0)
                return decode(output.read(LIMIT + 1))
        except (OSError, subprocess.TimeoutExpired):
            raise EnrollmentError("KUBERNETES_UNAVAILABLE") from None


def ready(conditions):
    return isinstance(conditions, list) and any(isinstance(c, dict) and c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)


def verify_node(node, expected):
    try:
        meta, spec, status = node["metadata"], node["spec"], node["status"]
        info = status["nodeInfo"]
        matches = (node.get("kind") == "Node" and meta["name"] == expected["node_name"] and identifier(meta["uid"]) and
            not meta.get("deletionTimestamp") and meta.get("labels", {}).get(LABEL) == "true" and
            not spec.get("unschedulable", False) and spec.get("providerID", "") == expected["provider_id"] and
            not any(t.get("effect") in ("NoSchedule", "NoExecute") for t in spec.get("taints", [])) and
            info["machineID"] == expected["machine_id"] and identifier(info["bootID"]) and info["operatingSystem"] == "linux" and
            info["architecture"].upper() == expected["architecture"] and info["containerRuntimeVersion"].startswith("containerd://") and
            "+k3s" in info["kubeletVersion"] and ready(status.get("conditions")))
        if matches:
            return {"target_id": expected["target_id"], "node_name": expected["node_name"], "node_uid": meta["uid"],
                    "machine_id": expected["machine_id"], "mode": "kubernetes", "namespace": expected["namespace"], "agent_image": expected["agent_image"]}
    except (KeyError, TypeError, AttributeError):
        pass
    raise EnrollmentError("NODE_IDENTITY_OR_PLATFORM_MISMATCH")


def verify_agent(pods, expected):
    candidates = []
    try:
        if pods.get("kind") != "PodList" or not isinstance(pods["items"], list):
            raise EnrollmentError("AGENT_UNAVAILABLE")
        for pod in pods["items"]:
            meta, spec, status = pod["metadata"], pod["spec"], pod["status"]
            if (meta.get("namespace") == expected["namespace"] and identifier(meta.get("uid")) and not meta.get("deletionTimestamp") and
                meta.get("labels", {}).get(AGENT_LABEL) == "runtime-image-agent" and
                any(o.get("kind") == "DaemonSet" and o.get("name") == "runtime-image-agent" and o.get("controller") is True for o in meta.get("ownerReferences", [])) and
                spec.get("nodeName") == expected["node_name"] and spec.get("serviceAccountName") == "image-agent" and
                isinstance(spec.get("containers"), list) and len(spec["containers"]) == 1 and
                spec["containers"][0].get("name") == "agent" and spec["containers"][0].get("image") == expected["agent_image"] and
                status.get("phase") == "Running" and ready(status.get("conditions"))):
                candidates.append(pod)
    except (KeyError, TypeError, AttributeError):
        raise EnrollmentError("AGENT_UNAVAILABLE") from None
    if len(candidates) != 1:
        raise EnrollmentError("AGENT_UNAVAILABLE")


def encoded_json(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def assert_policy_revision(expected):
    if expected is None:
        return
    path, original = expected
    try:
        _, current = read_bytes(path, with_revision=True)
    except EnrollmentError:
        raise EnrollmentError("POLICY_CHANGED") from None
    if current != original:
        raise EnrollmentError("POLICY_CHANGED")


def atomic_json(path, value, *, expected_policy=None):
    path = Path(path)
    trusted_parent(path)
    mode = 0o640
    owner = None
    if path.exists() or path.is_symlink():
        read_bytes(path)
        info = path.stat()
        mode = stat.S_IMODE(info.st_mode)
        owner = (info.st_uid, info.st_gid)
    descriptor, temporary = tempfile.mkstemp(prefix=".image-prefetch-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as file:
            os.chmod(temporary, mode)
            if owner is not None and hasattr(os, "fchown"):
                os.fchown(file.fileno(), *owner)
            file.write(encoded_json(value))
            file.flush()
            os.fsync(file.fileno())
        # Check after preparing/fsyncing the replacement, immediately before
        # publication, so an independent operator edit during remote calls wins.
        assert_policy_revision(expected_policy)
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError:
        raise EnrollmentError("CONFIG_WRITE_FAILED") from None
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def enrollment_lock(output):
    path = Path(str(output) + ".lock")
    trusted_parent(path)
    if path.is_symlink():
        raise EnrollmentError("UNTRUSTED_FILE")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        trusted_stat(os.fstat(descriptor))
        if os.name == "posix":
            import fcntl
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise EnrollmentError("ENROLLMENT_BUSY") from None
        else:
            import msvcrt
            try:
                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"0")
                os.lseek(descriptor, 0, 0)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as error:
                if error.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK) or getattr(error, "winerror", None) in (32, 33):
                    raise EnrollmentError("ENROLLMENT_BUSY") from None
                raise
        yield
    finally:
        os.close(descriptor)


def reconcile(policy_path, registry_path, output_path, *, client=None, apply=False, receipt_path=None, runtime_uid=None):
    policy_path, output_path = Path(policy_path), Path(output_path)
    if policy_path.absolute() == output_path.absolute() or Path(registry_path).absolute() == output_path.absolute():
        raise EnrollmentError("INVALID_OUTPUT_PATH")
    with enrollment_lock(output_path):
        policy_raw, original_revision = read_bytes(policy_path, with_revision=True)
        policy = validate_policy(decode(policy_raw))
        updated = apply_receipt(policy, read_json(receipt_path)) if receipt_path else policy
        targets = registered_targets(read_json(registry_path), updated, runtime_uid=runtime_uid)
        client = client or KubernetesClient()
        nodes = []
        for expected in updated["nodes"]:
            kubeconfig = targets[expected["target_id"]]
            current = client.query(kubeconfig, ["get", "node", expected["node_name"], "-o", "json"])
            entry = verify_node(current, expected)
            pods = client.query(kubeconfig, ["get", "pods", "--namespace", expected["namespace"], "--field-selector",
                "spec.nodeName=" + expected["node_name"], "--selector", "app.kubernetes.io/name=runtime-image-agent", "-o", "json"])
            verify_agent(pods, expected)
            nodes.append(entry)
        result = {"nodes": sorted(nodes, key=lambda n: (n["target_id"], n["node_name"]))}
        changed = not output_path.exists() or read_json(output_path) != result
        if apply:
            expected_policy = (policy_path, original_revision)
            if receipt_path:
                atomic_json(policy_path, updated, expected_policy=expected_policy)
                published, updated_revision = read_bytes(policy_path, with_revision=True)
                if published != encoded_json(updated):
                    raise EnrollmentError("POLICY_CHANGED")
                expected_policy = (policy_path, updated_revision)
            if changed:
                atomic_json(output_path, result, expected_policy=expected_policy)
            else:
                assert_policy_revision(expected_policy)
        return {"status": "APPLIED" if apply else "DRY_RUN", "nodes": len(nodes), "changed": changed, "replacement": bool(receipt_path)}


def publish_policy(policy_path, output_path, candidate_path, *, apply=False):
    """Supported operator writer; shares the timer/provisioning transaction lock."""
    policy_path, output_path, candidate_path = Path(policy_path), Path(output_path), Path(candidate_path)
    if len({policy_path.absolute(), output_path.absolute(), candidate_path.absolute()}) != 3:
        raise EnrollmentError("INVALID_CANDIDATE_PATH")
    with enrollment_lock(output_path):
        candidate = validate_policy(read_json(candidate_path))
        original = None
        if policy_path.exists() or policy_path.is_symlink():
            raw, original = read_bytes(policy_path, with_revision=True)
            changed = decode(raw) != candidate
        else:
            changed = True
        if apply and changed:
            expected = (policy_path, original) if original is not None else None
            atomic_json(policy_path, candidate, expected_policy=expected)
        return {"status": "APPLIED" if apply else "DRY_RUN", "nodes": len(candidate["nodes"]),
                "changed": changed, "policy_published": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("reconcile", "accept-provisioned", "publish-policy"))
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--kubectl", default="/usr/local/bin/kubectl")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--runtime-user", help="Trusted installation user owning registry-selected kubeconfigs (Linux only)")
    parser.add_argument("--apply", action="store_true", help="Publish validated configuration; omitted means dry run")
    args = parser.parse_args(argv)
    if (args.action == "accept-provisioned") != bool(args.receipt):
        parser.error("accept-provisioned requires --receipt; reconcile forbids --receipt")
    if args.action == "publish-policy":
        if args.candidate is None or args.registry is not None:
            parser.error("publish-policy requires --candidate and does not use --registry")
    elif args.registry is None or args.candidate is not None:
        parser.error("reconcile and accept-provisioned require --registry and forbid --candidate")
    try:
        if args.action == "publish-policy":
            result = publish_policy(args.policy, args.output, args.candidate, apply=args.apply)
        else:
            runtime_uid = None
            if args.runtime_user:
                if os.name != "posix":
                    raise EnrollmentError("INVALID_RUNTIME_USER")
                import pwd
                try:
                    runtime_uid = pwd.getpwnam(args.runtime_user).pw_uid
                except KeyError:
                    raise EnrollmentError("INVALID_RUNTIME_USER") from None
            result = reconcile(args.policy, args.registry, args.output, client=KubernetesClient(args.kubectl),
                               apply=args.apply, receipt_path=args.receipt, runtime_uid=runtime_uid)
        print(json.dumps(result, sort_keys=True))
        return 0
    except EnrollmentError as error:
        print(json.dumps({"status": "FAILED", "error_code": str(error)}), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError):
        print(json.dumps({"status": "FAILED", "error_code": "ENROLLMENT_FAILED"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
