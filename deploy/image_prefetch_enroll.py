#!/usr/bin/env python3
"""Reconcile operator-approved K3s identities into Runtime's trusted agent file.

This host-side tool only reads Kubernetes. It never deploys agents, pulls images,
executes pods, or accepts an enrollment request from an HTTP caller.
"""

import argparse
import base64
import binascii
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
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
from urllib.parse import urlsplit


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


def open_trusted_source(path, credential_owner_uid):
    if os.name != "posix":
        return os.open(path, os.O_RDONLY)
    parts = Path(os.path.abspath(path)).parts[1:]
    if not parts:
        raise EnrollmentError("UNTRUSTED_FILE")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, component in enumerate(parts):
            info = os.fstat(directory)
            trusted_owner = info.st_uid in (0, os.geteuid(), credential_owner_uid)
            root_sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if not trusted_owner or (info.st_mode & 0o022 and not root_sticky):
                raise EnrollmentError("UNTRUSTED_DIRECTORY")
            if index == len(parts) - 1:
                return os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
    finally:
        os.close(directory)


def read_bytes(path, *, with_revision=False, credential_owner_uid=None):
    path = Path(path)
    trusted_parent(path, credential_owner_uid=credential_owner_uid)
    if path.is_symlink():
        raise EnrollmentError("UNTRUSTED_FILE")
    try:
        descriptor = open_trusted_source(path, credential_owner_uid)
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
        if not isinstance(node, dict) or not required <= node.keys() or node.keys() - required - {"allow_replacement", "broker_resource_target_id", "allow_target_rotation"}:
            raise EnrollmentError("INVALID_POLICY")
        key = (node["target_id"], node["node_name"]) if all(isinstance(node[k], str) for k in ("target_id", "node_name")) else None
        if key is None or key in seen or not identifier(node["target_id"]) or not identifier(node["machine_id"]):
            raise EnrollmentError("INVALID_POLICY")
        seen.add(key)
        if (len(node["node_name"]) > 253 or not DNS.fullmatch(node["node_name"]) or
                not isinstance(node["namespace"], str) or len(node["namespace"]) > 63 or "." in node["namespace"] or not DNS.fullmatch(node["namespace"]) or
                node["architecture"] not in ("AMD64", "ARM64") or
                not isinstance(node["provider_id"], str) or len(node["provider_id"]) > 512 or any(c in node["provider_id"] for c in "\r\n\0") or
                type(node.get("allow_replacement", False)) is not bool or
                type(node.get("allow_target_rotation", False)) is not bool or
                ("broker_resource_target_id" in node and not identifier(node["broker_resource_target_id"])) or
                (node.get("allow_target_rotation", False) and "broker_resource_target_id" not in node)):
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


@contextmanager
def approved_inventory(policy, registry_path, client, *, broker_state_path=None, runtime_uid=None):
    """Resolve only approved resources; keep embedded credentials private and short lived."""
    effective = copy.deepcopy(policy)
    registry = read_json(registry_path)
    static_policy = {"version": 1, "nodes": [n for n in effective["nodes"] if "broker_resource_target_id" not in n]}
    targets = registered_targets(registry, static_policy, runtime_uid=runtime_uid)
    broker_nodes = [n for n in effective["nodes"] if "broker_resource_target_id" in n]
    state_revision = None
    if broker_nodes:
        if broker_state_path is None:
            raise EnrollmentError("BROKER_STATE_REQUIRED")
        raw, state_revision = read_bytes(broker_state_path, with_revision=True, credential_owner_uid=runtime_uid)
        state = decode(raw)
        if (not isinstance(state, dict) or set(state) != {"version", "targets"} or type(state["version"]) is not int or
                state["version"] != 1 or not isinstance(state["targets"], dict) or len(state["targets"]) > 1024):
            raise EnrollmentError("INVALID_BROKER_STATE")
    with tempfile.TemporaryDirectory(prefix="image-prefetch-broker-") as directory:
        for index, expected in enumerate(broker_nodes):
            resource = expected["broker_resource_target_id"]
            matches = [(uid, entry) for uid, entry in state["targets"].items()
                if isinstance(entry, dict) and isinstance(entry.get("config"), dict) and
                entry["config"].get("broker_resource_target_id") == resource]
            if len(matches) != 1:
                raise EnrollmentError("BROKER_RESOURCE_AMBIGUOUS_OR_ABSENT")
            uid, entry = matches[0]
            config, credential = entry["config"], entry.get("credential")
            if (not identifier(uid) or not isinstance(credential, dict) or
                    config.get("target_id") != uid or credential.get("target_id") != uid or
                    credential.get("resource_target_id") != resource or type(credential.get("schema_version")) is not int or
                    credential["schema_version"] != 1 or config.get("enabled") is not True or entry.get("desired_enabled") is not True or
                    not isinstance(config.get("architecture"), str) or config["architecture"].upper() != expected["architecture"] or
                    config.get("kubeconfig_path") != "broker://" + resource + "/" + uid or
                    (uid != expected["target_id"] and not expected.get("allow_target_rotation", False))):
                raise EnrollmentError("BROKER_IDENTITY_OR_PLATFORM_MISMATCH")
            if any(c["target_id"] in (uid, expected["target_id"]) for c in registry["clusters"]):
                # Static target policy is authoritative; never silently shadow it.
                raise EnrollmentError("BROKER_STATIC_TARGET_COLLISION")
            try:
                value = credential["kubeconfig_base64"]
                if not isinstance(value, str) or not value or len(value) > LIMIT:
                    raise ValueError()
                frozen = client.static_config(base64.b64decode(value, validate=True))
            except (KeyError, ValueError, binascii.Error):
                raise EnrollmentError("INVALID_BROKER_CREDENTIAL") from None
            server = frozen["clusters"][0]["cluster"]["server"]
            if server != credential.get("server_url"):
                raise EnrollmentError("BROKER_SERVER_MISMATCH")
            snapshot = Path(directory) / (str(index) + ".json")
            with os.fdopen(os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
                file.write(encoded_json(frozen))
            expected["target_id"] = uid
            targets[uid] = snapshot
        yield effective, targets
        if state_revision is not None:
            _, current = read_bytes(broker_state_path, with_revision=True, credential_owner_uid=runtime_uid)
            if current != state_revision:
                raise EnrollmentError("BROKER_STATE_CHANGED")


def static_kubeconfig(config):
    """Accept embedded credentials only; normalized output has no executable/file hooks."""
    invalid = EnrollmentError("UNSUPPORTED_KUBECONFIG")
    required = {"kind", "apiVersion", "clusters", "users", "contexts", "current-context"}
    if (not isinstance(config, dict) or not required <= config.keys() or config.keys() - required - {"preferences"} or
            config["kind"] != "Config" or config["apiVersion"] != "v1" or config.get("preferences", {}) != {}):
        raise invalid

    def embedded(value):
        if not isinstance(value, str) or not value or len(value) > LIMIT:
            raise invalid
        try:
            if not base64.b64decode(value, validate=True):
                raise invalid
        except (ValueError, binascii.Error):
            raise invalid from None

    collections = {}
    for plural, singular in (("clusters", "cluster"), ("users", "user"), ("contexts", "context")):
        items = config[plural]
        if not isinstance(items, list) or not 1 <= len(items) <= 16:
            raise invalid
        selected = {}
        for item in items:
            if (not isinstance(item, dict) or set(item) != {"name", singular} or not identifier(item["name"]) or
                    item["name"] in selected or not isinstance(item[singular], dict)):
                raise invalid
            selected[item["name"]] = item[singular]
        collections[plural] = selected
    for cluster in collections["clusters"].values():
        if set(cluster) != {"server", "certificate-authority-data"} or not isinstance(cluster["server"], str):
            raise invalid
        try:
            server = urlsplit(cluster["server"])
            if (server.scheme != "https" or not server.hostname or any(c.isspace() or c == "\0" for c in cluster["server"]) or
                    server.username is not None or server.password is not None or
                    server.path not in ("", "/") or server.query or server.fragment or server.port == 0):
                raise invalid
        except ValueError:
            raise invalid from None
        embedded(cluster["certificate-authority-data"])
    for user in collections["users"].values():
        if (not user or user.keys() - {"client-certificate-data", "client-key-data", "token"} or
                ("client-certificate-data" in user) != ("client-key-data" in user)):
            raise invalid
        for key in ("client-certificate-data", "client-key-data"):
            if key in user:
                embedded(user[key])
        if "token" in user:
            token = user["token"]
            if not isinstance(token, str) or not token or len(token) > 65536 or not token.isascii() or any(c.isspace() or c == "\0" for c in token):
                raise invalid
    for context in collections["contexts"].values():
        if (not {"cluster", "user"} <= context.keys() or context.keys() - {"cluster", "user", "namespace"} or
                not isinstance(context["cluster"], str) or not isinstance(context["user"], str) or
                context["cluster"] not in collections["clusters"] or context["user"] not in collections["users"]):
            raise invalid
        if "namespace" in context and (not isinstance(context["namespace"], str) or len(context["namespace"]) > 63 or
                (context["namespace"] and ("." in context["namespace"] or not DNS.fullmatch(context["namespace"])) )):
            raise invalid
    name = config["current-context"]
    if not isinstance(name, str) or name not in collections["contexts"]:
        raise invalid
    context = collections["contexts"][name]
    return {"kind": "Config", "apiVersion": "v1", "preferences": {}, "current-context": name,
        "clusters": [{"name": context["cluster"], "cluster": collections["clusters"][context["cluster"]]}],
        "users": [{"name": context["user"], "user": collections["users"][context["user"]]}],
        "contexts": [{"name": name, "context": context}]}


class KubernetesClient:
    def __init__(self, binary="/usr/local/bin/kubectl", *, runtime_uid=None):
        if not Path(binary).is_absolute():
            raise EnrollmentError("INVALID_KUBECTL_PATH")
        self.binary = binary
        self.runtime_uid = runtime_uid

    def json_command(self, command, *, source=None):
        try:
            # Never retain or print kubectl stderr, which may contain credentials.
            # Disk-backed stdout prevents an unbounded response in process memory.
            with tempfile.TemporaryFile() as output:
                input_options = {"stdin": subprocess.DEVNULL} if source is None else {"input": source}
                completed = subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL,
                                           timeout=20, check=False, **input_options)
                if completed.returncode:
                    raise EnrollmentError("KUBERNETES_UNAVAILABLE")
                output.seek(0)
                return decode(output.read(LIMIT + 1))
        except (OSError, subprocess.TimeoutExpired):
            raise EnrollmentError("KUBERNETES_UNAVAILABLE") from None

    def static_config(self, source):
        # config view only parses/converts the bytes supplied on stdin. Never
        # flatten: file references must remain visible so validation can deny them.
        converted = self.json_command([self.binary, "--kubeconfig", "/dev/stdin", "config", "view", "--raw", "-o", "json"], source=source)
        return static_kubeconfig(converted)

    def query(self, kubeconfig, args):
        source = read_bytes(kubeconfig, credential_owner_uid=self.runtime_uid)
        config = self.static_config(source)
        with tempfile.TemporaryDirectory(prefix="image-prefetch-kubeconfig-") as directory:
            snapshot = Path(directory) / "static.json"
            descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as file:
                file.write(encoded_json(config))
            command = [self.binary, "--kubeconfig", str(snapshot), "--request-timeout=15s", "--insecure-skip-tls-verify=false", *args]
            return self.json_command(command)


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
        if pods.get("kind") not in ("PodList", "List") or not isinstance(pods["items"], list):
            raise EnrollmentError("AGENT_UNAVAILABLE")
        if pods.get("kind") == "List" and any(p.get("kind") != "Pod" for p in pods["items"]):
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


def registration_generation(entry, expected, current):
    return {"target_id": entry["target_id"], "broker_resource_target_id": expected.get("broker_resource_target_id"),
        "node_uid": entry["node_uid"], "node_name": entry["node_name"], "machine_id": entry["machine_id"],
        "provider_id": expected["provider_id"], "boot_id": current["status"]["nodeInfo"]["bootID"],
        "architecture": expected["architecture"], "namespace": entry["namespace"], "agent_image": entry["agent_image"]}


def emit_registration_event(directory, generation, *, expected_policy):
    """Immutable local outbox. A retry repairs a crash after nodes publication."""
    directory = Path(directory)
    trusted_parent(directory)
    if directory.is_symlink():
        raise EnrollmentError("UNTRUSTED_DIRECTORY")
    directory.mkdir(mode=0o700, exist_ok=True)
    trusted_parent(directory / "receipt")
    event_id = hashlib.sha256(encoded_json({"version": 1, "type": "agent.registration", "generation": generation})).hexdigest()
    path = directory / (event_id + ".json")
    assert_policy_revision(expected_policy)
    if path.exists() or path.is_symlink():
        existing = read_json(path)
        if (not isinstance(existing, dict) or set(existing) != {"version", "type", "event_id", "observed_at", "generation"} or
                type(existing["version"]) is not int or existing["version"] != 1 or existing["type"] != "agent.registration" or
                existing["event_id"] != event_id or existing["generation"] != generation or not isinstance(existing["observed_at"], str)):
            raise EnrollmentError("REGISTRATION_EVENT_CONFLICT")
        return
    # Count every directory entry, including unexpected files. Never delete pending events.
    with os.scandir(directory) as entries:
        if sum(1 for _ in entries) >= 4096:
            raise EnrollmentError("REGISTRATION_OUTBOX_FULL")
    event = {"version": 1, "type": "agent.registration", "event_id": event_id,
        "observed_at": datetime.now(timezone.utc).isoformat(), "generation": generation}
    descriptor, temporary = tempfile.mkstemp(prefix=".registration-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as file:
            os.chmod(temporary, 0o640)
            file.write(encoded_json(event))
            file.flush()
            os.fsync(file.fileno())
        assert_policy_revision(expected_policy)
        os.link(temporary, path)  # create-only: immutable receipts cannot be replaced
        if os.name == "posix":
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except OSError:
        raise EnrollmentError("REGISTRATION_EVENT_WRITE_FAILED") from None
    finally:
        os.unlink(temporary)


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


def reconcile(policy_path, registry_path, output_path, *, client=None, apply=False, receipt_path=None, runtime_uid=None,
              broker_state_path=None, events_dir=None):
    policy_path, output_path = Path(policy_path), Path(output_path)
    if output_path.absolute() in {Path(p).absolute() for p in (policy_path, registry_path, broker_state_path) if p is not None}:
        raise EnrollmentError("INVALID_OUTPUT_PATH")
    with enrollment_lock(output_path):
        policy_raw, original_revision = read_bytes(policy_path, with_revision=True)
        policy = validate_policy(decode(policy_raw))
        updated = apply_receipt(policy, read_json(receipt_path)) if receipt_path else policy
        client = client or KubernetesClient(runtime_uid=runtime_uid)
        nodes = []
        generations = []
        with approved_inventory(updated, registry_path, client, broker_state_path=broker_state_path, runtime_uid=runtime_uid) as (effective, targets):
            for expected in effective["nodes"]:
                kubeconfig = targets[expected["target_id"]]
                current = client.query(kubeconfig, ["get", "node", expected["node_name"], "-o", "json"])
                entry = verify_node(current, expected)
                if "broker_resource_target_id" in expected and entry["node_uid"] != expected["target_id"]:
                    raise EnrollmentError("BROKER_NODE_UID_MISMATCH")
                pods = client.query(kubeconfig, ["get", "pods", "--namespace", expected["namespace"], "--field-selector",
                    "spec.nodeName=" + expected["node_name"], "--selector", "app.kubernetes.io/name=runtime-image-agent", "-o", "json"])
                verify_agent(pods, expected)
                nodes.append(entry)
                generations.append(registration_generation(entry, expected, current))
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
            if events_dir is not None:
                for generation in generations:
                    emit_registration_event(events_dir, generation, expected_policy=expected_policy)
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
    parser.add_argument("--broker-state", type=Path, help="Protected Runtime-admitted targets.json (optional)")
    parser.add_argument("--events-dir", type=Path, help="Optional durable registration-generation metadata outbox")
    parser.add_argument("--runtime-user", help="Trusted installation user owning registry-selected kubeconfigs (Linux only)")
    parser.add_argument("--apply", action="store_true", help="Publish validated configuration; omitted means dry run")
    args = parser.parse_args(argv)
    if (args.action == "accept-provisioned") != bool(args.receipt):
        parser.error("accept-provisioned requires --receipt; reconcile forbids --receipt")
    if args.action == "publish-policy":
        if args.candidate is None or args.registry is not None or args.broker_state is not None or args.events_dir is not None:
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
            result = reconcile(args.policy, args.registry, args.output, client=KubernetesClient(args.kubectl, runtime_uid=runtime_uid),
                               apply=args.apply, receipt_path=args.receipt, runtime_uid=runtime_uid,
                               broker_state_path=args.broker_state, events_dir=args.events_dir)
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
