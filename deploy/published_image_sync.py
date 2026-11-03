#!/usr/bin/env python3
"""Promote successful main publications into existing operator-owned image profiles.

Only immutable image identities change. UID, mounts, FLAG requirements, network
edges, probes and startup/shutdown controls remain the reviewed operator values.
"""
import argparse
import copy
import datetime
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

IMAGE = re.compile(r"ghcr\.io/msg-ctf/challenges/([a-z0-9][a-z0-9-]*)/([a-z0-9][a-z0-9-]*)@sha256:[a-f0-9]{64}\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
MAX_JSON = 2 * 1024 * 1024
MAX_ARCHIVE = 8 * 1024 * 1024


class SyncError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code="INVALID_PUBLICATION"):
    if not condition:
        raise SyncError(code)


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    try:
        require(len(raw) <= MAX_JSON)
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError, TypeError):
        raise SyncError("INVALID_JSON") from None


def read_private(path):
    path = Path(path)
    metadata = path.lstat()
    require(path.is_absolute() and stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), "UNSAFE_FILE")
    require(metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) & 0o077 == 0, "UNSAFE_FILE")
    require(metadata.st_size <= MAX_JSON, "UNSAFE_FILE")
    return path.read_bytes()


def atomic_json(path, value):
    path = Path(path)
    require(not path.is_symlink(), "UNSAFE_FILE")
    fd, name = tempfile.mkstemp(prefix=".publication-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
        parent = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self, repository, token):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "INVALID_CONFIG")
        self.repository = repository
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, suffix, archive=False):
        require(suffix.startswith("/actions/"), "INVALID_API_PATH")
        url = "https://api.github.com/repos/" + self.repository + suffix
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json", "User-Agent": "msgctf-publication-sync"})
        limit = MAX_ARCHIVE if archive else MAX_JSON
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            if not archive or error.code not in {301, 302, 303, 307, 308}:
                error.close()
                raise SyncError("GITHUB_UNAVAILABLE") from None
            location = error.headers.get("Location", "")
            error.close()
            parsed = urllib.parse.urlsplit(location)
            host = parsed.hostname or ""
            require(parsed.scheme == "https" and not parsed.username and not parsed.password
                    and (host.endswith(".blob.core.windows.net") or host.endswith(".actions.githubusercontent.com")
                         or host.endswith(".amazonaws.com")), "UNTRUSTED_ARTIFACT_REDIRECT")
            # Use a new request without the GitHub credential on signed storage URLs.
            response = self.opener.open(urllib.request.Request(location), timeout=30)
        with response:
            require(response.status == 200, "GITHUB_UNAVAILABLE")
            raw = response.read(limit + 1)
        require(len(raw) <= limit, "ARTIFACT_TOO_LARGE")
        return raw if archive else decode(raw)


def verified_bundle(api, artifact, *, repository, branch, workflow):
    require(type(artifact.get("id")) is int and artifact["id"] > 0 and artifact.get("expired") is False)
    run_id = (artifact.get("workflow_run") or {}).get("id")
    require(type(run_id) is int and run_id > 0)
    run = api.request("/actions/runs/" + str(run_id))
    require(run.get("id") == run_id and run.get("status") == "completed" and run.get("conclusion") == "success", "CI_NOT_SUCCESSFUL")
    require(run.get("event") in {"push", "workflow_dispatch"} and run.get("head_branch") == branch, "UNTRUSTED_SOURCE")
    require(run.get("repository", {}).get("full_name", "").lower() == repository.lower(), "UNTRUSTED_REPOSITORY")
    require(run.get("head_repository", {}).get("full_name", repository).lower() == repository.lower(), "UNTRUSTED_REPOSITORY")
    require(run.get("path", "").split("@", 1)[0] == workflow, "UNTRUSTED_WORKFLOW")
    sha = run.get("head_sha", "")
    require(bool(SHA.fullmatch(sha)))
    identity = artifact.get("workflow_run") or {}
    require(identity.get("head_sha", sha) == sha and identity.get("head_branch", branch) == branch)
    name = artifact.get("name", "")
    match = re.fullmatch(r"([a-z0-9]+(?:-[a-z0-9]+)*)-" + str(run_id) + "-" + str(run.get("run_attempt")) + r"-[a-f0-9]{28,64}-publish-bundle", name)
    require(match is not None, "ARTIFACT_IDENTITY_MISMATCH")
    raw = api.request("/actions/artifacts/" + str(artifact["id"]) + "/zip", archive=True)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = [entry for entry in archive.infolist() if entry.filename == "artifact-v2.json"]
            require(len(members) == 1 and members[0].file_size <= MAX_JSON and len(archive.infolist()) <= 100)
            document = decode(archive.read(members[0]))
    except (zipfile.BadZipFile, OSError):
        raise SyncError("INVALID_ARCHIVE") from None
    require(document.get("schema_version") == "2.0" and document.get("challenge_slug") == match[1])
    require(document.get("source_sha") == sha and document.get("source_ref") == "refs/heads/" + branch)
    require(document.get("registry_revision") == run.get("run_number") and document.get("scan_result") == "PASS")
    require(document.get("architecture") == "AMD64" and document.get("runtime_type") == "KUBERNETES", "UNSUPPORTED_RUNTIME")
    containers = document.get("workload", {}).get("containers")
    require(isinstance(containers, list) and 1 <= len(containers) <= 32)
    seen = set()
    for container in containers:
        require(isinstance(container, dict) and container.get("name") not in seen)
        seen.add(container["name"])
        image = container.get("image", "")
        reference = IMAGE.fullmatch(image)
        require(reference is not None and reference[1] == document["challenge_slug"])
        ports = container.get("ports")
        require(isinstance(ports, list) and bool(ports))
        require(all(isinstance(p, dict) and type(p.get("port")) is int and 1 <= p["port"] <= 65535 for p in ports))
        require(len({p["port"] for p in ports}) == len(ports))
    return document


def extend_policy(policy, document):
    """Clone matching operator profiles, including the whole reviewed network set."""
    candidate = copy.deepcopy(policy)
    existing = {entry["image"]: entry for entry in policy["images"]}
    requested = {c["name"]: c for c in document["workload"]["containers"]}
    managed = set(policy["managed_repositories"])
    reserved = set(policy.get("vm_required_repositories", []))
    replacements = {}
    added = []
    for name, container in requested.items():
        image = container["image"]
        repo = image.split("@", 1)[0]
        require(repo in managed and repo not in reserved, "UNREVIEWED_EXECUTION_PROFILE")
        ports = sorted(p["port"] for p in container["ports"])
        profiles = [p for p in policy["images"] if p["image"].split("@", 1)[0] == repo and p["status"] == "create_enabled"
                    and p["container"] == name and p["isolation_profile"] == document["isolation_profile"] and sorted(p["ports"]) == ports]
        require(bool(profiles), "EXECUTION_PROFILE_CHANGED")
        # A digest must not choose between conflicting operator requirements.
        forms = {json.dumps({k: v for k, v in p.items() if k != "image"}, sort_keys=True) for p in profiles}
        require(len(forms) == 1, "AMBIGUOUS_EXECUTION_PROFILE")
        chosen = profiles[-1]
        replacements[repo] = image
        if image in existing:
            require(existing[image]["status"] == "create_enabled", "IMAGE_BLOCKED")
            continue
        clone = copy.deepcopy(chosen)
        clone["image"] = image
        candidate["images"].append(clone)
        existing[image] = clone
        added.append(image)
        protocols = [p for p in policy.get("endpoint_protocols", []) if p["image"] == chosen["image"]]
        for entry in protocols:
            clone = copy.deepcopy(entry)
            clone["image"] = image
            candidate.setdefault("endpoint_protocols", []).append(clone)
    graph_repos = set(policy.get("network_required_repositories", []))
    if graph_repos.intersection(replacements):
        matches = []
        for graph in policy.get("workload_networks", []):
            identities = {c["name"]: c for c in graph["containers"]}
            if set(identities) != set(requested) or graph["isolation_profile"] != document["isolation_profile"]:
                continue
            if all(identities[name]["image"].split("@", 1)[0] == c["image"].split("@", 1)[0]
                   and sorted(identities[name]["ports"]) == sorted(p["port"] for p in c["ports"]) for name, c in requested.items()):
                matches.append(graph)
        require(bool(matches), "WORKLOAD_NETWORK_CHANGED")
        def shape(graph):
            value = copy.deepcopy(graph)
            value.pop("id", None)
            for c in value["containers"]:
                c["image"] = c["image"].split("@", 1)[0]
            return json.dumps(value, sort_keys=True)
        require(len({shape(g) for g in matches}) == 1, "AMBIGUOUS_WORKLOAD_NETWORK")
        graph = copy.deepcopy(matches[-1])
        for c in graph["containers"]:
            c["image"] = requested[c["name"]]["image"]
        graph["id"] = "publication-" + hashlib.sha256(json.dumps(graph, sort_keys=True).encode()).hexdigest()[:40]
        if not any({c["image"] for c in g["containers"]} == {c["image"] for c in graph["containers"]} for g in candidate.get("workload_networks", [])):
            candidate.setdefault("workload_networks", []).append(graph)
    return candidate, added


def discover(api, policy, max_pages=10):
    slugs = set()
    for repository in policy["managed_repositories"]:
        match = re.fullmatch(r"ghcr\.io/msg-ctf/challenges/([a-z0-9-]+)/[a-z0-9-]+", repository)
        if match and not match[1].startswith("koth-"):
            slugs.add(match[1])
    latest = {}
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=48)
    for page in range(1, max_pages + 1):
        result = api.request("/actions/artifacts?per_page=100&page=" + str(page))
        rows = result.get("artifacts")
        require(isinstance(rows, list), "INVALID_ARTIFACT_LIST")
        for row in rows:
            match = re.match(r"([a-z0-9]+(?:-[a-z0-9]+)*)-[0-9]+-[0-9]+-[a-f0-9]+-publish-bundle$", row.get("name", ""))
            if match and match[1] in slugs and not row.get("expired"):
                if match[1] not in latest or row["id"] > latest[match[1]]["id"]:
                    latest[match[1]] = row
        dates = [datetime.datetime.fromisoformat(r["created_at"].replace("Z", "+00:00")) for r in rows if r.get("created_at")]
        if not rows or page * 100 >= result.get("total_count", page * 100 + 1) or dates and max(dates) < cutoff:
            break
    return sorted(latest.values(), key=lambda row: row["id"])


def synchronize(config, api, state, reload_policy, *, plan_only=False):
    policy_path = Path(config["policy_file"])
    require(not policy_path.is_symlink(), "UNSAFE_FILE")
    original = policy_path.read_bytes()
    policy = decode(original)
    candidate = copy.deepcopy(policy)
    records = state.setdefault("artifacts", {})
    outcomes = []
    successful = []
    for artifact in discover(api, policy, config.get("max_pages", 10)):
        key = str(artifact["id"])
        if records.get(key, {}).get("status") == "APPLIED":
            continue
        if records.get(key, {}).get("next_check_at", 0) > time.time():
            continue
        try:
            document = verified_bundle(api, artifact, repository=config["repository"], branch=config["branch"], workflow=config["workflow"])
            candidate, images = extend_policy(candidate, document)
            successful.append((key, {"source_sha": document["source_sha"], "revision": document["registry_revision"],
                                     "run_id": artifact["workflow_run"]["id"], "images": images}))
            outcomes.append({"artifact_id": artifact["id"], "slug": document["challenge_slug"], "status": "VERIFIED", "new_images": len(images)})
        except (SyncError, OSError, ValueError, KeyError, urllib.error.URLError) as error:
            code = error.code if isinstance(error, SyncError) else "GITHUB_UNAVAILABLE"
            slug = re.sub(r"-[0-9]+-[0-9]+-[a-f0-9]+-publish-bundle$", "", artifact.get("name", ""))[:100]
            records[key] = {"status": "WAITING", "error_code": code, "next_check_at": time.time() + (30 if code == "CI_NOT_SUCCESSFUL" else 300)}
            outcomes.append({"artifact_id": artifact["id"], "slug": slug, "status": "WAITING", "error_code": code})
    data = (json.dumps(candidate, ensure_ascii=False, indent=2) + "\n").encode()
    changed = candidate != policy
    pending = state.get("pending_policy_sha256")
    recovered = pending == hashlib.sha256(original).hexdigest()
    require(len(data) <= 1 << 20, "POLICY_TOO_LARGE")
    if plan_only:
        return {"changed": changed, "outcomes": outcomes, "plan_only": True}
    if changed or recovered:
        state["pending_policy_sha256"] = hashlib.sha256(data if changed else original).hexdigest()
        atomic_json(config["state_file"], state)
        result = reload_policy(data if changed else original, hashlib.sha256(original).hexdigest())
        require(isinstance(result, dict) and result.get("status") == "verified", "RELOAD_NOT_VERIFIED")
        state.pop("pending_policy_sha256", None)
    for key, value in successful:
        records[key] = {**value, "status": "APPLIED"}
    # The marker is recovery data, not an unbounded copy of GitHub history.
    state["artifacts"] = dict(sorted(records.items(), key=lambda item: int(item[0]))[-2048:])
    state["last_checked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    state["outcomes"] = outcomes
    atomic_json(config["state_file"], state)
    return {"changed": changed, "recovered_pending_reload": recovered, "outcomes": outcomes}


def load_config(path):
    config = decode(read_private(path))
    require(set(config) == {"repository", "branch", "workflow", "token_file", "policy_file", "state_file", "max_pages"}, "INVALID_CONFIG")
    require(config["repository"] == "MSG-CTF/2026_MSG_CTF" and config["branch"] == "main", "INVALID_CONFIG")
    require(re.fullmatch(r"\.github/workflows/[-a-zA-Z0-9_.]+\.ya?ml", config["workflow"]) is not None, "INVALID_CONFIG")
    require(config["policy_file"] == "/etc/secure-provisioner/image-policies.json", "INVALID_CONFIG")
    require(config["state_file"] == "/var/lib/secure-provisioner-publications/state.json", "INVALID_CONFIG")
    require(type(config["max_pages"]) is int and 1 <= config["max_pages"] <= 20, "INVALID_CONFIG")
    return config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/secure-provisioner-publications/config.json")
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    config = load_config(args.config)
    directory = Path(config["state_file"]).parent
    require(not directory.is_symlink(), "UNSAFE_FILE")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(directory.stat().st_uid == 0 and stat.S_IMODE(directory.stat().st_mode) & 0o077 == 0, "UNSAFE_FILE")
    with (directory / "sync.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"status": "ALREADY_RUNNING"}))
            return
        token = read_private(config["token_file"]).decode().strip()
        require(16 <= len(token) <= 4096 and not any(c.isspace() for c in token), "INVALID_CREDENTIAL")
        state_path = Path(config["state_file"])
        state = decode(read_private(state_path)) if state_path.exists() else {}
        helper = Path("/usr/local/lib/msgctf-deploy/release.py")
        require(helper.is_file() and not helper.is_symlink() and helper.stat().st_uid == 0
                and not stat.S_IMODE(helper.stat().st_mode) & 0o022, "UNSAFE_RELOAD_HELPER")
        spec = importlib.util.spec_from_file_location("trusted_release", helper)
        release = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(release)
        result = synchronize(config, GitHub(config["repository"], token), state, release.reload_image_policies, plan_only=args.plan)
        print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"status": "RETRY", "error_code": error.code if isinstance(error, SyncError) else type(error).__name__}))
        raise SystemExit(1) from None
