#!/usr/bin/env python3
"""Apply scoped KOTH environment versions without changing author images or policies.

Run as root on the fixed K3s VM. Configuration and journals must be root-only.
Neither request bodies, environment values nor subprocess stderr are logged.
"""
import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

OWNER = "msgctf.io/environment-owner"
APPLICATION = "msgctf.io/environment-application"
VERSION = "msgctf.io/environment-version"
DNS = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
IMAGE = re.compile(r"ghcr\.io/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\Z")
ERROR_CODES = {"ROLLOUT_FAILED", "ROLLBACK_CONFLICT", "IMAGE_MISMATCH", "ENVIRONMENT_MISMATCH",
               "VM_UNAVAILABLE", "GAME_ACTIVE", "SOURCE_CHANGED", "SECRET_CONFLICT"}


class Fault(Exception):
    def __init__(self, code):
        super().__init__(code if code in ERROR_CODES else "VM_UNAVAILABLE")
        self.code = str(self)


class NetworkUnavailable(Exception):
    pass


class Superseded(Exception):
    pass


def canonical_uuid(value):
    if not isinstance(value, str):
        raise ValueError("Invalid identifier")
    parsed = uuid.UUID(value)
    if not parsed.int or str(parsed) != value:
        raise ValueError("Invalid identifier")
    return value


def secure_read(path):
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("Root-only regular file required")
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_config(config):
    if set(config) != {"schema_version", "target_id", "base_url", "games"} or config["schema_version"] != 1:
        raise ValueError("Invalid agent configuration")
    url = urllib.parse.urlsplit(config["base_url"])
    if (url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment
            or url.path.rstrip("/") != "/internal/v1/koth_environments"):
        raise ValueError("Verified HTTPS backend required")
    if not re.fullmatch(r"gcp:[0-9]{1,25}", config["target_id"]):
        raise ValueError("Fixed VM target required")
    if not isinstance(config["games"], list) or not 1 <= len(config["games"]) <= 6:
        raise ValueError("Invalid game scope")
    seen, namespaces = set(), set()
    for game in config["games"]:
        if set(game) != {"challenge_id", "namespace", "deployment", "source_revision", "containers", "token"}:
            raise ValueError("Invalid game configuration")
        key = canonical_uuid(game["challenge_id"])
        if key in seen or game["namespace"] in namespaces:
            raise ValueError("Duplicate game scope")
        seen.add(key); namespaces.add(game["namespace"])
        if not all(isinstance(game[k], str) and DNS.fullmatch(game[k]) for k in ("namespace", "deployment")):
            raise ValueError("Fixed workload required")
        if not re.fullmatch(r"[0-9a-f]{40}", game["source_revision"]) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", game["token"]):
            raise ValueError("Invalid revision or credential")
        if not isinstance(game["containers"], dict) or not 1 <= len(game["containers"]) <= 16:
            raise ValueError("Invalid container scope")
        for name, item in game["containers"].items():
            if (not DNS.fullmatch(name) or set(item) != {"image", "managed_secrets", "protected"}
                    or not IMAGE.fullmatch(item["image"]) or not isinstance(item["managed_secrets"], list)
                    or not all(isinstance(s, str) and DNS.fullmatch(s) for s in item["managed_secrets"])
                    or not isinstance(item["protected"], dict)
                    or not all(NAME.fullmatch(k) and re.fullmatch(r"[0-9a-f]{64}", v) for k, v in item["protected"].items())):
                raise ValueError("Invalid container configuration")
    return config


def validate_desired(config, game, desired):
    if desired.get("challenge_id") != game["challenge_id"] or desired.get("target_id") != config["target_id"]:
        raise Fault("VM_UNAVAILABLE")
    if desired.get("source_revision") != game["source_revision"]:
        raise Fault("SOURCE_CHANGED")
    canonical_uuid(desired.get("application_id")); canonical_uuid(desired.get("version_id"))
    settings = desired.get("settings")
    if (not isinstance(settings, dict) or set(settings) != {"containers"}
            or not isinstance(settings["containers"], list)
            or len(settings["containers"]) != len(game["containers"])):
        raise Fault("ENVIRONMENT_MISMATCH")
    names = set()
    for item in settings["containers"]:
        name = item.get("name")
        fixed = game["containers"].get(name)
        if name in names or not fixed or item.get("image") != fixed["image"]:
            raise Fault("IMAGE_MISMATCH")
        names.add(name)
        entries = item.get("entries")
        if not isinstance(entries, dict) or len(entries) > 128:
            raise Fault("ENVIRONMENT_MISMATCH")
        total = 0
        for key, entry in entries.items():
            if not NAME.fullmatch(key) or not isinstance(entry, dict):
                raise Fault("ENVIRONMENT_MISMATCH")
            value = entry.get("value")
            if (value is not None and (not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > 4096)
                    or value is None and (entry.get("required") or entry.get("locked"))):
                raise Fault("ENVIRONMENT_MISMATCH")
            total += len(key.encode()) + (len(value.encode("utf-8")) if value is not None else 0)
        if total > 16384:
            raise Fault("ENVIRONMENT_MISMATCH")
        for key, expected in fixed["protected"].items():
            entry = entries.get(key, {})
            value = entry.get("value")
            if (not isinstance(value, str) or not entry.get("locked")
                    or not hmac.compare_digest(hmac.new(game["token"].encode(), value.encode(), hashlib.sha256).hexdigest(), expected)):
                raise Fault("ENVIRONMENT_MISMATCH")
    return settings


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Backend:
    def __init__(self, config, game):
        self.url = config["base_url"].rstrip("/") + "/" + game["challenge_id"]
        self.token = game["token"]
        # Never forward scoped credentials through environment-configured proxies or redirects.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, suffix="", body=None):
        request = urllib.request.Request(self.url + suffix,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=12) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise NetworkUnavailable()
                result = json.loads(raw)
                if result.get("code") != "SUCCESS" or not isinstance(result.get("data"), dict):
                    raise NetworkUnavailable()
                return result["data"]
        except urllib.error.HTTPError as error:
            if error.code == 409:
                raise Superseded() from None
            raise NetworkUnavailable() from None
        except (OSError, ValueError):
            raise NetworkUnavailable() from None

    def get(self, known=None):
        return self.call("?known_application_id=" + canonical_uuid(known) if known else "")

    def status(self, desired, state, error_code=None):
        body = {"application_id": desired["application_id"], "version_id": desired["version_id"], "state": state}
        if error_code:
            body["error_code"] = error_code
        return self.call("/status", body)


class Journal:
    def __init__(self, directory, challenge_id):
        self.path = Path(directory) / (canonical_uuid(challenge_id) + ".json")

    def read(self):
        return secure_read(self.path) if self.path.exists() else {}

    def write(self, value):
        temporary = self.path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, self.path)
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class Kubernetes:
    def __init__(self, game):
        self.game = game
        self.command = ["/usr/local/bin/k3s", "kubectl", "-n", game["namespace"]]

    def run(self, args, body=None, timeout=20, raw=False):
        try:
            result = subprocess.run(self.command + args, input=None if body is None else json.dumps(body).encode(),
                                    capture_output=True, timeout=timeout, check=False)
            if result.returncode:
                raise Fault("VM_UNAVAILABLE")
            return result.stdout if raw else json.loads(result.stdout or b"null")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            raise Fault("VM_UNAVAILABLE") from None

    def deployment(self):
        row = self.run(["get", "deployment", self.game["deployment"], "-o", "json"])
        containers = row["spec"]["template"]["spec"]["containers"]
        if (row["spec"].get("replicas", 1) != 1 or len(containers) != len(self.game["containers"])
                or {c["name"]: c["image"] for c in containers} != {k: v["image"] for k, v in self.game["containers"].items()}):
            raise Fault("IMAGE_MISMATCH")
        return row

    def values_match(self, desired):
        deployment = self.deployment()
        if deployment.get("status", {}).get("observedGeneration", 0) < deployment["metadata"]["generation"]:
            return False
        if deployment.get("status", {}).get("updatedReplicas", 0) != 1 or deployment.get("status", {}).get("readyReplicas", 0) != 1:
            return False
        selector = ",".join(k + "=" + v for k, v in sorted(deployment["spec"]["selector"]["matchLabels"].items()))
        pods = self.run(["get", "pods", "-l", selector, "-o", "json"])["items"]
        pods = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
        if len(pods) != 1 or not any(c["type"] == "Ready" and c["status"] == "True" for c in pods[0].get("status", {}).get("conditions", [])):
            return False
        for container in desired["settings"]["containers"]:
            configured = {key: entry["value"] for key, entry in container["entries"].items() if entry["value"] is not None}
            current = next(c for c in deployment["spec"]["template"]["spec"]["containers"] if c["name"] == container["name"])
            injected = {}
            for source in current.get("envFrom", []):
                name = source.get("secretRef", {}).get("name")
                if not name or source.get("prefix"):
                    raise Fault("ENVIRONMENT_MISMATCH")
                fixed = self.game["containers"][container["name"]]["managed_secrets"]
                managed = bool(re.fullmatch(r"koth-env-[0-9a-f]{32}-[0-9a-f]{8}", name))
                if name not in fixed and not managed:
                    raise Fault("ENVIRONMENT_MISMATCH")
                secret = self.run(["get", "secret", name, "--ignore-not-found", "-o", "json"])
                if secret is None:
                    return False
                if managed and secret.get("metadata", {}).get("labels", {}).get(OWNER) != self.game["challenge_id"]:
                    raise Fault("SECRET_CONFLICT")
                try:
                    injected.update({key: base64.b64decode(value, validate=True).decode("utf-8") for key, value in secret.get("data", {}).items()})
                except (ValueError, UnicodeError):
                    raise Fault("ENVIRONMENT_MISMATCH") from None
            for entry in current.get("env", []):
                if entry["name"] in configured and "value" in entry:
                    injected[entry["name"]] = entry["value"]
            # A subset comparison would falsely adopt an old version while removed
            # variables remain injected. Image-provided defaults are checked separately.
            if injected != configured:
                return False
            raw = self.run(["exec", pods[0]["metadata"]["name"], "-c", container["name"], "--", "env", "-0"], raw=True)
            actual = dict(part.decode("utf-8").split("=", 1) for part in raw.split(b"\0") if b"=" in part)
            for key, entry in container["entries"].items():
                value = entry["value"]
                if value is None:
                    if key in actual:
                        return False
                elif key not in actual or not hmac.compare_digest(value.encode(), actual[key].encode()):
                    return False
        return True

    def secret_name(self, desired, name):
        return "koth-env-" + desired["application_id"].replace("-", "") + "-" + hashlib.sha256(name.encode()).hexdigest()[:8]

    def ensure_secrets(self, desired):
        for item in desired["settings"]["containers"]:
            name = self.secret_name(desired, item["name"])
            labels = {OWNER: self.game["challenge_id"], APPLICATION: desired["application_id"]}
            data = {key: base64.b64encode(entry["value"].encode()).decode()
                    for key, entry in item["entries"].items() if entry["value"] is not None}
            secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": self.game["namespace"], "labels": labels},
                      "type": "Opaque", "immutable": True, "data": data}
            existing = self.run(["get", "secret", name, "--ignore-not-found", "-o", "json"])
            if existing is not None:
                if (existing.get("data", {}) != data or not existing.get("immutable")
                        or any(existing["metadata"].get("labels", {}).get(k) != v for k, v in labels.items())):
                    raise Fault("SECRET_CONFLICT")
            else:
                self.run(["create", "-f", "-", "-o", "json"], secret)

    def template(self, original, desired):
        changed = copy.deepcopy(original)
        annotations = changed.setdefault("metadata", {}).setdefault("annotations", {})
        annotations.update({OWNER: self.game["challenge_id"], APPLICATION: desired["application_id"], VERSION: desired["version_id"]})
        by_name = {c["name"]: c for c in desired["settings"]["containers"]}
        for container in changed["spec"]["containers"]:
            name = container["name"]
            refs = container.get("envFrom", [])
            baseline = self.game["containers"][name]["managed_secrets"]
            for ref in refs:
                secret = ref.get("secretRef", {}).get("name", "")
                if not secret or ref.get("prefix") or secret not in baseline and not re.fullmatch(r"koth-env-[0-9a-f]{32}-[0-9a-f]{8}", secret):
                    raise Fault("ENVIRONMENT_MISMATCH")
            container["envFrom"] = [{"secretRef": {"name": self.secret_name(desired, name)}}]
            direct = [e for e in container.get("env", []) if e["name"] not in by_name[name]["entries"]]
            if direct:
                container["env"] = direct
            else:
                container.pop("env", None)
        return changed

    def patch(self, before, after):
        try:
            self.run(["patch", "deployment", self.game["deployment"], "--type=json", "--patch-file=/dev/stdin", "-o", "json"],
                     [{"op": "test", "path": "/spec/template", "value": before},
                      {"op": "replace", "path": "/spec/template", "value": after}])
        except Fault:
            # A failed response may follow a committed patch. Inspect before deciding to retry.
            if self.deployment()["spec"]["template"] != after:
                raise Fault("ROLLBACK_CONFLICT") from None

    def ready(self):
        self.run(["rollout", "status", "deployment/" + self.game["deployment"], "--timeout=90s"], timeout=95, raw=True)

    def collect_unused_secrets(self):
        # Keep every Secret referenced by a live Pod or retained ReplicaSet for safe rollback.
        referenced = set()
        deployment = self.deployment()
        templates = [deployment["spec"]["template"]]
        for row in self.run(["get", "replicasets", "-o", "json"])["items"]:
            templates.append(row["spec"]["template"])
        for row in self.run(["get", "pods", "-o", "json"])["items"]:
            templates.append({"spec": row["spec"]})
        for template in templates:
            spec = template["spec"]
            for item in spec.get("containers", []) + spec.get("initContainers", []):
                referenced.update(ref.get("secretRef", {}).get("name") for ref in item.get("envFrom", []))
                referenced.update(e.get("valueFrom", {}).get("secretKeyRef", {}).get("name") for e in item.get("env", []))
            for volume in spec.get("volumes", []):
                referenced.add(volume.get("secret", {}).get("secretName"))
                referenced.update(s.get("secret", {}).get("name") for s in volume.get("projected", {}).get("sources", []))
        rows = self.run(["get", "secrets", "-l", OWNER + "=" + self.game["challenge_id"], "-o", "json"])["items"]
        for row in rows:
            name = row["metadata"]["name"]
            if name in referenced or not re.fullmatch(r"koth-env-[0-9a-f]{32}-[0-9a-f]{8}", name):
                continue
            # UID precondition prevents deleting a replacement created after this read.
            self.run(["delete", "--raw", "/api/v1/namespaces/" + self.game["namespace"] + "/secrets/" + name, "-f", "-"],
                     {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": row["metadata"]["uid"]}})


class Agent:
    def __init__(self, config, game, journal, api=None, kube=None):
        self.config, self.game, self.journal = config, game, journal
        self.api = api or Backend(config, game)
        self.kube = kube or Kubernetes(game)
        self.last_maintenance = 0

    def persist(self, state, phase, **extra):
        state.update(phase=phase, **extra); self.journal.write(state)

    def acknowledge(self, desired, state):
        if state["phase"] == "healthy":
            # A lost APPLIED response is retried without rolling back or starting another rollout.
            self.api.status(desired, "APPLIED")
            self.persist(state, "complete")
        elif state["phase"] == "failed":
            self.api.status(desired, "FAILED", state["error_code"])
            self.persist(state, "rejected")

    def tick(self):
        previous = self.journal.read()
        known = previous.get("application_id") if previous.get("phase") in ("complete", "rejected") else None
        desired = self.api.get(known)
        if not desired.get("changed"):
            if time.monotonic() - self.last_maintenance > 600:
                self.last_maintenance = time.monotonic()
                try:
                    self.kube.collect_unused_secrets()
                except Fault:
                    pass
            return "unchanged"
        try:
            validate_desired(self.config, self.game, desired)
        except (Fault, ValueError) as error:
            code = error.code if isinstance(error, Fault) else "ENVIRONMENT_MISMATCH"
            self.api.status(desired, "FAILED", code)
            return "rejected"
        state = previous if previous.get("application_id") == desired["application_id"] else {
            "application_id": desired["application_id"], "version_id": desired["version_id"], "phase": "new"}
        if state["phase"] in ("failed", "healthy"):
            if state["phase"] == "healthy" and not self.kube.values_match(desired):
                self.persist(state, "failed", error_code="ENVIRONMENT_MISMATCH")
            self.acknowledge(desired, state)
            return state["phase"]
        if state["phase"] in ("complete", "rejected"):
            return "unchanged"
        try:
            if state["phase"] == "rollback":
                self.rollback(state)
                self.acknowledge(desired, state)
                return state["phase"]
            if self.kube.values_match(desired):
                self.persist(state, "healthy")
            else:
                if not desired.get("can_apply"):
                    raise Fault("GAME_ACTIVE")
                self.api.status(desired, "APPLYING")
                current = self.kube.deployment()["spec"]["template"]
                if state["phase"] == "new":
                    changed = self.kube.template(current, desired)
                    self.persist(state, "prepared", before=current, after=changed)
                elif current not in (state["before"], state["after"]):
                    raise Fault("ROLLBACK_CONFLICT")
                self.kube.ensure_secrets(desired)
                check = self.api.get()
                if check["application_id"] != desired["application_id"]:
                    raise Superseded()
                validate_desired(self.config, self.game, check)
                if not check.get("can_apply"):
                    raise Fault("GAME_ACTIVE")
                current = self.kube.deployment()["spec"]["template"]
                if current == state["before"]:
                    self.kube.patch(state["before"], state["after"])
                elif current != state["after"]:
                    raise Fault("ROLLBACK_CONFLICT")
                self.persist(state, "patched")
                self.kube.ready()
                if not self.kube.values_match(desired):
                    raise Fault("ENVIRONMENT_MISMATCH")
                self.persist(state, "healthy")
        except Fault as error:
            if state.get("after"):
                self.persist(state, "rollback", error_code=error.code)
                self.rollback(state)
            else:
                self.persist(state, "failed", error_code=error.code)
        # Network failures and superseded replies deliberately bypass rollout rollback.
        self.acknowledge(desired, state)
        return state["phase"]

    def rollback(self, state):
        try:
            current = self.kube.deployment()["spec"]["template"]
            if current == state["after"]:
                self.kube.patch(state["after"], state["before"])
            elif current != state["before"]:
                raise Fault("ROLLBACK_CONFLICT")
            self.kube.ready()
            self.persist(state, "failed", error_code="ROLLOUT_FAILED" if state["error_code"] == "VM_UNAVAILABLE" else state["error_code"])
        except Fault:
            self.persist(state, "failed", error_code="ROLLBACK_CONFLICT")


def main():
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/msgctf-koth-environment/agent.json")
    parser.add_argument("--state-dir", default="/var/lib/msgctf-koth-environment")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = validate_config(secure_read(args.config))
    directory = Path(args.state_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("Root-only state directory required")
    with open(directory / "agent.lock", "a", encoding="ascii") as lock:
        os.chmod(directory / "agent.lock", 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        agents = [Agent(config, game, Journal(directory, game["challenge_id"])) for game in config["games"]]
        last = {}
        while True:
            for agent in agents:
                try:
                    status = agent.tick()
                except Superseded:
                    status = "superseded"
                except (NetworkUnavailable, Fault, ValueError, KeyError, TypeError, OSError):
                    status = "unavailable"
                key = agent.game["challenge_id"]
                if status != last.get(key):
                    print(json.dumps({"challenge_id": key, "state": status}), flush=True)
                    last[key] = status
            if args.once:
                break
            time.sleep(15)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError):
        print("KOTH environment agent configuration is unavailable", file=sys.stderr)
        sys.exit(1)
