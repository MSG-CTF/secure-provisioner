#!/usr/bin/env python3
"""Collect one existing preparation's evidence; never create, retry or pull."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

import image_prefetch_enroll as enroll


Error = enroll.EnrollmentError
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
FAILURES = {"NETWORK_TIMEOUT", "REGISTRY_UNAVAILABLE", "RATE_LIMITED", "REGISTRY_UNAUTHORIZED", "MANIFEST_NOT_FOUND",
    "PLATFORM_MISMATCH", "RESOURCE_EXHAUSTED", "NODE_IDENTITY_MISMATCH", "AGENT_UNAVAILABLE", "CONTENT_INCOMPLETE", "POLICY_REJECTED"}


def require(condition, code="INVALID_EVIDENCE"):
    if not condition:
        raise Error(code)


def valid_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except (ValueError, AttributeError):
        return False


def image_set_id(architecture, images):
    # Field order and compact separators match imageprep.ImageSetID's Go struct.
    raw = json.dumps({"schema_version": 1, "architecture": architecture, "images": sorted(set(images))},
        separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_scope(value):
    required = {"release_id", "architecture", "target_ids", "images", "image_set_id"}
    require(isinstance(value, dict) and required <= value.keys() and not value.keys() - required - {"request_id"}, "INVALID_SCOPE")
    require(valid_uuid(value["release_id"]) and value["architecture"] in ("AMD64", "ARM64"), "INVALID_SCOPE")
    for field, limit, validator in (("target_ids", 50, valid_uuid), ("images", 32, lambda s: isinstance(s, str) and
            len(s) <= 512 and enroll.IMAGE.fullmatch(s) and all(p not in ("", ".", "..") for p in s.split("@")[0].split("/")[1:]))):
        values = value[field]
        require(isinstance(values, list) and 1 <= len(values) <= limit and all(validator(v) for v in values), "INVALID_SCOPE")
        require(len(set(values)) == len(values), "INVALID_SCOPE")
    require(value["image_set_id"] == image_set_id(value["architecture"], value["images"]), "INVALID_SCOPE")
    require("request_id" not in value or isinstance(value["request_id"], str) and ID.fullmatch(value["request_id"]), "INVALID_SCOPE")
    return value


def timestamp(value):
    if value is None:
        return None
    require(isinstance(value, str) and len(value) <= 40)
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.tzinfo is not None)
        return result
    except ValueError:
        raise Error("INVALID_EVIDENCE") from None


def safe_id(value):
    require(isinstance(value, str) and ID.fullmatch(value))
    return value


def failure(value):
    require(value is None or isinstance(value, str) and (value == "" or value in FAILURES))
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Error("RUNTIME_REDIRECT_DENIED")


class RuntimeAPI:
    def __init__(self, origin, token_file, *, opener=None):
        try:
            parts = urlsplit(origin)
            require(parts.scheme == "https" and parts.hostname and parts.username is None and parts.password is None and
                parts.path in ("", "/") and not parts.query and not parts.fragment and parts.port != 0 and
                not any(c.isspace() or c == "\0" for c in origin), "INVALID_RUNTIME_ORIGIN")
        except ValueError:
            raise Error("INVALID_RUNTIME_ORIGIN") from None
        self.origin = origin.rstrip("/")
        raw = enroll.read_bytes(token_file)
        if os.name == "posix":
            require(not Path(token_file).stat().st_mode & 0o007, "UNTRUSTED_TOKEN_FILE")
        try:
            self.token = raw.decode("ascii").strip()
        except UnicodeError:
            raise Error("INVALID_MANAGER_TOKEN") from None
        require(re.fullmatch(r"[A-Za-z0-9_-]{43,128}", self.token), "INVALID_MANAGER_TOKEN")
        # Direct TLS only: do not inherit environment proxies or redirect credentials.
        self.opener = opener or build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), NoRedirect())

    def _json(self, path, body=None):
        request = Request(self.origin + path, data=None if body is None else enroll.encoded_json(body),
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json", "Accept": "application/json"},
            method="GET" if body is None else "POST")
        try:
            with self.opener.open(request, timeout=20) as response:
                return enroll.decode(response.read(enroll.LIMIT + 1))
        except HTTPError as error:
            code = error.code if error.code in (400, 401, 403, 404, 409, 429, 500, 502, 503, 504) else "ERROR"
            raise Error("RUNTIME_HTTP_" + str(code)) from None
        except (URLError, OSError, TimeoutError):
            raise Error("RUNTIME_UNAVAILABLE") from None

    def operation(self, operation_id):
        require(isinstance(operation_id, str) and ID.fullmatch(operation_id), "INVALID_OPERATION_ID")
        return self._json("/v1/image-preparations/" + operation_id)

    def readiness(self, scope):
        return self._json("/v1/image-readiness/query", {k: scope[k] for k in ("architecture", "images", "target_ids")})


def checked_operation(raw, scope, operation_id):
    require(isinstance(raw, dict), "OPERATION_SCOPE_MISMATCH")
    require(raw.get("operation_id") == operation_id and all(raw.get(k) == scope[k] for k in
        ("release_id", "architecture", "image_set_id")) and ("request_id" not in scope or raw.get("request_id") == scope["request_id"]),
        "OPERATION_SCOPE_MISMATCH")
    status = raw.get("status")
    require(status in ("QUEUED", "RUNNING", "SUCCEEDED", "PARTIAL", "FAILED"))
    result = {k: raw[k] for k in ("operation_id", "release_id", "architecture", "image_set_id", "status")}
    result["request_id"] = safe_id(raw.get("request_id"))
    if "error_code" in raw:
        result["error_code"] = failure(raw["error_code"])
    nodes = raw.get("nodes")
    require(isinstance(nodes, list) and len(nodes) <= 256)
    result["nodes"], seen = [], set()
    for row in nodes:
        require(isinstance(row, dict) and row.get("target_id") in scope["target_ids"] and row.get("architecture") == scope["architecture"], "OPERATION_SCOPE_MISMATCH")
        uid = safe_id(row.get("node_uid"))
        require((row["target_id"], uid) not in seen)
        seen.add((row["target_id"], uid))
        require(isinstance(row.get("node_name"), str) and len(row["node_name"]) <= 253 and enroll.DNS.fullmatch(row["node_name"]))
        require(row.get("status") in ("QUEUED", "VERIFYING", "PULLING", "READY", "FAILED"))
        timestamp(row.get("observed_at"))
        node = {k: row[k] for k in ("target_id", "node_uid", "node_name", "architecture", "status", "observed_at")}
        images = row.get("images")
        require(isinstance(images, list) and len(images) == len(scope["images"]))
        require(all(isinstance(i, dict) and i.get("image") in scope["images"] for i in images), "OPERATION_SCOPE_MISMATCH")
        require(len({i["image"] for i in images}) == len(images))
        node["images"] = []
        for image in images:
            require(image.get("status") in ("QUEUED", "VERIFYING", "PULLING", "READY", "FAILED"))
            require(type(image.get("attempts")) is int and 0 <= image["attempts"] <= 1000)
            timestamp(image.get("observed_at"))
            entry = {k: image[k] for k in ("image", "status", "attempts", "observed_at")}
            if image.get("resolved_manifest_digest"):
                require(isinstance(image["resolved_manifest_digest"], str) and DIGEST.fullmatch(image["resolved_manifest_digest"]))
                entry["resolved_manifest_digest"] = image["resolved_manifest_digest"]
            if "error_code" in image:
                entry["error_code"] = failure(image["error_code"])
            node["images"].append(entry)
        result["nodes"].append(node)
    return result


def checked_readiness(raw, scope):
    require(isinstance(raw, dict) and raw.get("architecture") == scope["architecture"] and raw.get("image_set_id") == scope["image_set_id"], "READINESS_SCOPE_MISMATCH")
    targets = raw.get("targets")
    require(isinstance(targets, list) and len(targets) == len(scope["target_ids"]), "READINESS_SCOPE_MISMATCH")
    result, seen = [], set()
    for row in targets:
        require(isinstance(row, dict) and row.get("target_id") in scope["target_ids"] and row["target_id"] not in seen, "READINESS_SCOPE_MISMATCH")
        seen.add(row["target_id"])
        require(type(row.get("ready")) is bool and all(type(row.get(k)) is int and 0 <= row[k] <= 256 for k in ("ready_node_count", "eligible_node_count")))
        require(row["ready_node_count"] <= row["eligible_node_count"])
        observed, valid = timestamp(row.get("observed_at")), timestamp(row.get("valid_until"))
        require((observed is None) == (valid is None) and (valid is None or valid >= observed))
        require(not row["ready"] or observed is not None and row["ready_node_count"] == row["eligible_node_count"] > 0)
        result.append({k: row[k] for k in ("target_id", "ready", "ready_node_count", "eligible_node_count", "observed_at", "valid_until")})
    return {"architecture": scope["architecture"], "image_set_id": scope["image_set_id"], "targets": result}


def checked_snapshot(raw, scope):
    require(isinstance(raw, dict) and type(raw.get("version")) is int and raw["version"] == 1 and
        raw.get("target_id") in scope["target_ids"] and raw.get("architecture") == scope["architecture"], "SNAPSHOT_SCOPE_MISMATCH")
    result = {"version": 1, "target_id": raw["target_id"], "architecture": raw["architecture"]}
    for key in ("node_uid", "machine_id", "boot_id"):
        result[key] = safe_id(raw.get(key))
    require(timestamp(raw.get("observed_at")) is not None)
    result["observed_at"] = raw["observed_at"]
    elapsed = raw.get("inspection_elapsed_seconds")
    require(type(elapsed) in (int, float) and 0 <= elapsed <= 86400)
    result["inspection_elapsed_seconds"] = elapsed
    images = raw.get("images")
    require(isinstance(images, list) and len(images) == len(scope["images"]))
    require(all(isinstance(i, dict) and i.get("image") in scope["images"] for i in images), "SNAPSHOT_SCOPE_MISMATCH")
    require(len({i["image"] for i in images}) == len(images))
    result["images"] = []
    for image in images:
        require(image.get("cache_state") in ("PRESENT_VERIFIED", "UNKNOWN"))
        entry = {"image": image["image"], "cache_state": image["cache_state"]}
        for key in ("resolved_manifest_digest", "cri_config_image_id"):
            value = image.get(key)
            require(value is None or isinstance(value, str) and DIGEST.fullmatch(value))
            entry[key] = value
        require(entry["cache_state"] != "PRESENT_VERIFIED" or entry["resolved_manifest_digest"] is not None)
        if "error_code" in image:
            entry["error_code"] = failure(image["error_code"])
        result["images"].append(entry)
    return result


def collect(api, scope, operation_id, *, before=None, after=None):
    scope = validate_scope(scope)
    started = time.monotonic()
    operation = checked_operation(api.operation(operation_id), scope, operation_id)
    readiness = checked_readiness(api.readiness(scope), scope)
    now = datetime.now(timezone.utc)
    result = {"version": 1, "collected_at": now.isoformat(), "scope": scope, "operation": operation,
        "operation_target_scope": ("VERIFIED" if set(n["target_id"] for n in operation["nodes"]) == set(scope["target_ids"]) else
            "UNVERIFIED_PARTIAL_TARGETS" if operation["nodes"] else "UNVERIFIED_NO_NODES"),
        "readiness": readiness, "current_readiness": {r["target_id"]: bool(r["ready"] and timestamp(r["observed_at"]) <= now < timestamp(r["valid_until"])) for r in readiness["targets"]},
        "pull_telemetry": "UNKNOWN", "pull_elapsed_seconds": None, "cache_classification": "UNKNOWN"}
    for key, raw in (("before_cache", before), ("after_cache", after)):
        if raw is not None:
            result[key] = checked_snapshot(raw, scope)
            matching = [n for n in operation["nodes"] if n["target_id"] == result[key]["target_id"]]
            require(not matching or any(n["node_uid"] == result[key]["node_uid"] for n in matching), "SNAPSHOT_NODE_MISMATCH")
    if before is not None and after is not None:
        a, b = result["before_cache"], result["after_cache"]
        require(all(a[k] == b[k] for k in ("target_id", "node_uid", "machine_id", "boot_id")), "SNAPSHOT_GENERATION_CHANGED")
        require(timestamp(a["observed_at"]) <= timestamp(b["observed_at"]), "SNAPSHOT_TIME_ORDER")
        if all(i["cache_state"] == "PRESENT_VERIFIED" for s in (a, b) for i in s["images"]):
            result["cache_classification"] = "PRESENT_AT_BOTH_SNAPSHOTS"
    result["collection_elapsed_seconds"] = round(time.monotonic() - started, 6)
    return result


def snapshot(policy_path, registry_path, scope, *, broker_state_path=None, runtime_uid=None, client=None):
    scope = validate_scope(scope)
    require(len(scope["target_ids"]) == 1, "SNAPSHOT_REQUIRES_SINGLE_TARGET")
    started = time.monotonic()
    raw, revision = enroll.read_bytes(policy_path, with_revision=True)
    policy = enroll.validate_policy(enroll.decode(raw))
    client = client or enroll.KubernetesClient(runtime_uid=runtime_uid)
    with enroll.approved_inventory(policy, registry_path, client, broker_state_path=broker_state_path, runtime_uid=runtime_uid) as (effective, targets):
        selected = [n for n in effective["nodes"] if n["target_id"] == scope["target_ids"][0] and n["architecture"] == scope["architecture"]]
        require(len(selected) == 1, "SNAPSHOT_TARGET_NOT_APPROVED")
        expected = selected[0]
        kubeconfig = targets[expected["target_id"]]
        args = ["get", "node", expected["node_name"], "-o", "json"]
        current = client.query(kubeconfig, args)
        entry = enroll.verify_node(current, expected)
        require("broker_resource_target_id" not in expected or entry["node_uid"] == expected["target_id"], "BROKER_NODE_UID_MISMATCH")
        pods = client.query(kubeconfig, ["get", "pods", "--namespace", expected["namespace"], "--field-selector", "spec.nodeName=" + expected["node_name"],
            "--selector", "app.kubernetes.io/name=runtime-image-agent", "-o", "json"])
        pod = enroll.verify_agent(pods, expected)
        pod_name = pod["metadata"].get("name")
        require(isinstance(pod_name, str) and len(pod_name) <= 253 and enroll.DNS.fullmatch(pod_name), "AGENT_UNAVAILABLE")
        prefix = ["exec", "--namespace", expected["namespace"], pod_name, "--container", "agent"]
        result = {"version": 1, "target_id": expected["target_id"], "architecture": scope["architecture"], "node_uid": entry["node_uid"],
            "machine_id": entry["machine_id"], "boot_id": current["status"]["nodeInfo"]["bootID"], "images": []}
        for image in scope["images"]:
            row = {"image": image, "cache_state": "UNKNOWN", "resolved_manifest_digest": None, "cri_config_image_id": None}
            try:
                response = client.query(kubeconfig, [*prefix, "--stdin", "--", "/usr/local/bin/image-agent", "--kubernetes"],
                    source=enroll.encoded_json({"image": image, "architecture": scope["architecture"], "pull": False}))
                require(isinstance(response, dict), "INVALID_AGENT_EVIDENCE")
                proof = response.get("evidence")
                if proof is not None:
                    require(isinstance(proof, dict) and proof.get("complete") is True and all(proof.get(k) == v for k, v in
                        {"node_uid": result["node_uid"], "machine_id": result["machine_id"], "boot_id": result["boot_id"], "os": "linux",
                            "architecture": scope["architecture"], "image": image}.items()) and isinstance(proof.get("resolved_manifest_digest"), str) and DIGEST.fullmatch(proof["resolved_manifest_digest"]), "INVALID_AGENT_EVIDENCE")
                    row.update(cache_state="PRESENT_VERIFIED", resolved_manifest_digest=proof["resolved_manifest_digest"])
                else:
                    code = response.get("error_code")
                    row["error_code"] = code if isinstance(code, str) and code in FAILURES else "AGENT_UNAVAILABLE"
                cri = client.query(kubeconfig, [*prefix, "--", "/host-bin/k3s", "crictl", "--config", "/dev/null", "--runtime-endpoint",
                    "unix:///run/k3s/containerd/containerd.sock", "--image-endpoint", "unix:///run/k3s/containerd/containerd.sock", "inspecti", image])
                status = cri.get("status", {}) if isinstance(cri, dict) else {}
                if isinstance(status, dict) and isinstance(status.get("id"), str) and DIGEST.fullmatch(status["id"]) and isinstance(status.get("repoDigests"), list) and image in status["repoDigests"]:
                    row["cri_config_image_id"] = status["id"]
            except Error as error:
                if str(error) == "INVALID_AGENT_EVIDENCE":
                    raise
                row["error_code"] = "AGENT_UNAVAILABLE"
            result["images"].append(row)
        final = client.query(kubeconfig, args)
        require(enroll.verify_node(final, expected) == entry and final["status"]["nodeInfo"]["bootID"] == result["boot_id"], "SNAPSHOT_GENERATION_CHANGED")
    enroll.assert_policy_revision((policy_path, revision))
    result.update(observed_at=datetime.now(timezone.utc).isoformat(), inspection_elapsed_seconds=round(time.monotonic() - started, 6))
    return checked_snapshot(result, scope)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "snapshot"))
    for name in ("scope", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("token-file", "before", "after", "policy", "registry", "broker-state"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--origin")
    parser.add_argument("--operation-id")
    parser.add_argument("--runtime-user")
    parser.add_argument("--kubectl", default="/usr/local/bin/kubectl")
    args = parser.parse_args(argv)
    if args.action == "collect" and (not args.origin or not args.token_file or not args.operation_id):
        parser.error("collect requires --origin, --token-file, --operation-id")
    if args.action == "snapshot" and (not args.policy or not args.registry):
        parser.error("snapshot requires --policy and --registry")
    try:
        inputs = [getattr(args, k) for k in ("scope", "token_file", "before", "after", "policy", "registry", "broker_state")]
        require(all(args.output.absolute() != p.absolute() for p in inputs if p is not None), "INVALID_OUTPUT_PATH")
        scope = validate_scope(enroll.read_json(args.scope))
        if args.action == "collect":
            report = collect(RuntimeAPI(args.origin, args.token_file), scope, args.operation_id,
                before=enroll.read_json(args.before) if args.before else None, after=enroll.read_json(args.after) if args.after else None)
        else:
            runtime_uid = None
            if args.runtime_user:
                require(os.name == "posix", "INVALID_RUNTIME_USER")
                import pwd
                try:
                    runtime_uid = pwd.getpwnam(args.runtime_user).pw_uid
                except KeyError:
                    raise Error("INVALID_RUNTIME_USER") from None
            report = snapshot(args.policy, args.registry, scope, broker_state_path=args.broker_state, runtime_uid=runtime_uid,
                client=enroll.KubernetesClient(args.kubectl, runtime_uid=runtime_uid))
        enroll.atomic_json(args.output, report)
        print(json.dumps({"status": "COLLECTED", "action": args.action}))
        return 0
    except Error as error:
        print(json.dumps({"status": "FAILED", "error_code": str(error)}), file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print(json.dumps({"status": "FAILED", "error_code": "EVIDENCE_COLLECTION_FAILED"}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
