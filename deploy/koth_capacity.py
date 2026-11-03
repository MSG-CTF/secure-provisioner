#!/usr/bin/env python3
"""Apply reviewed KOTH capacity settings without replacing game code or images."""
import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

PROFILE = "msgctf.io/capacity-profile"
INIT_NAME = "prepare-jenga-sqlite"
DATABASE = "/data/jenga.db"
SQLITE_INIT = """import sqlite3
from contextlib import closing
with closing(sqlite3.connect('/data/jenga.db', timeout=30)) as db:
    mode = db.execute('PRAGMA journal_mode=WAL').fetchone()[0]
    if mode != 'wal':
        raise RuntimeError('SQLite WAL initialization failed')
"""


def jenga_template(template):
    changed = copy.deepcopy(template)
    spec = changed["spec"]
    containers = spec["containers"]
    if len(containers) != 1 or containers[0]["name"] != "jenga":
        raise ValueError("Unexpected Jenga container layout")
    game = containers[0]
    if not re.fullmatch(r"ghcr\.io/msg-ctf/challenges/koth-jenga/jenga@sha256:[0-9a-f]{64}", game["image"]):
        raise ValueError("Jenga must use its approved immutable image")
    mounts = [m for m in game.get("volumeMounts", []) if m["mountPath"] == "/data"]
    if len(mounts) != 1 or mounts[0].get("readOnly") or mounts[0].get("subPathExpr"):
        raise ValueError("Jenga needs its existing writable /data volume")
    volume = next((v for v in spec.get("volumes", []) if v["name"] == mounts[0]["name"]), {})
    if "persistentVolumeClaim" not in volume:
        raise ValueError("SQLite state must remain on the existing PVC")
    resources = game.setdefault("resources", {})
    resources.setdefault("limits", {}).update(cpu="1", memory="512Mi")
    # Keep existing requests, disk limits, and all pod security/network settings.
    old = spec.get("initContainers", [])
    annotations = changed.setdefault("metadata", {}).setdefault("annotations", {})
    if any(c["name"] == INIT_NAME for c in old) and annotations.get(PROFILE) != "jenga-v1":
        raise ValueError("An unrecognized SQLite init container already exists")
    init = copy.deepcopy(next((c for c in old if c["name"] == INIT_NAME), {}))
    if init.get("env") or init.get("envFrom"):
        raise ValueError("SQLite init must not inherit game secrets")
    init.update({
        "name": INIT_NAME, "image": game["image"], "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-c", SQLITE_INIT],
        "volumeMounts": [copy.deepcopy(mounts[0])],
        "resources": {"requests": {"cpu": "50m", "memory": "32Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi", "ephemeral-storage": "64Mi"}},
        "securityContext": copy.deepcopy(game.get("securityContext", {})),
    })
    spec["initContainers"] = [c for c in old if c["name"] != INIT_NAME] + [init]
    annotations[PROFILE] = "jenga-v1"
    return changed


def swanopoly_template(template):
    changed = copy.deepcopy(template)
    by_name = {c["name"]: c for c in changed["spec"]["containers"]}
    if not {"test", "submit"} <= set(by_name):
        raise ValueError("Swanopoly requires separate test and submit runners")
    for name in ("test", "submit"):
        container = by_name[name]
        if not re.fullmatch(r"ghcr\.io/msg-ctf/challenges/koth-swanopoly/" + name + r"@sha256:[0-9a-f]{64}", container["image"]):
            raise ValueError("Swanopoly must use its approved immutable runner images")
        container["env"] = [e for e in container.get("env", []) if e["name"] != "RUNNER_MAX_WAIT_QUEUE"]
        container["env"].append({"name": "RUNNER_MAX_WAIT_QUEUE", "value": "128"})
    changed.setdefault("metadata", {}).setdefault("annotations", {})[PROFILE] = "swanopoly-v1"
    return changed


def capacity_template(game, deployment):
    namespace = "koth-" + game
    if (deployment["kind"] != "Deployment" or deployment["metadata"].get("namespace") != namespace
            or deployment["metadata"]["name"] != "game" or deployment["spec"].get("replicas", 1) != 1):
        raise ValueError("Capacity profile requires the reviewed single-replica game Deployment")
    builder = {"jenga": jenga_template, "swanopoly": swanopoly_template}[game]
    return builder(deployment["spec"]["template"])


def jenga_gateway(text, upstream):
    """Bound Python/SQLite concurrency; retain every existing gateway boundary."""
    lines = text.splitlines(keepends=True)
    def block_end(start):
        depth = 1
        for position in range(start + 1, len(lines)):
            token = lines[position].strip()
            if token == "}":
                depth -= 1
                if depth == 0:
                    return position
            elif token.endswith("{"):
                depth += 1
        raise ValueError("Unexpected gateway block")
    found = 0
    for index in reversed(range(len(lines))):
        match = re.fullmatch(r"([ \t]*)reverse_proxy " + re.escape(upstream) + r" \{\s*\n?", lines[index])
        if not match:
            continue
        indent = match[1]
        end = block_end(index)
        transport = next((i for i in range(index + 1, end) if lines[i].strip() == "transport http {"), None)
        if transport is None:
            lines[index + 1:index + 1] = [indent + "\ttransport http {\n", indent + "\t\tmax_conns_per_host 8\n", indent + "\t}\n"]
        else:
            prefix = re.match(r"[ \t]*", lines[transport])[0]
            close = block_end(transport)
            if close >= end:
                raise ValueError("Unexpected HTTP transport block")
            old = [i for i in range(transport + 1, close) if lines[i].strip().startswith("max_conns_per_host ")]
            if old:
                if len(old) != 1 or lines[old[0]].strip() != "max_conns_per_host 8":
                    raise ValueError("Existing connection limit needs operator review")
            else:
                lines.insert(transport + 1, prefix + "\tmax_conns_per_host 8\n")
        found += 1
    if not 1 <= found <= 8:
        raise ValueError("Expected the reviewed game upstream in the gateway")
    return "".join(lines)


def tune_jenga_gateway(state_dir, upstream):
    target = Path("/etc/msgctf-koth/Caddyfile")
    original = target.read_text(encoding="utf-8")
    candidate = jenga_gateway(original, upstream)
    digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt = state_dir / "jenga-gateway-applied-sha256"
    def reload_gateway():
        result = subprocess.run(["systemctl", "show", "msg-koth-gateway", "--property=CanReload", "--value"],
                                capture_output=True, text=True, check=True, timeout=10)
        operation = "reload" if result.stdout.strip() == "yes" else "restart"
        subprocess.run(["systemctl", operation, "msg-koth-gateway"], check=True, capture_output=True, timeout=25)
        receipt.write_text(digest(candidate)); receipt.chmod(0o600)
    if candidate == original:
        if not receipt.exists() or receipt.read_text() != digest(candidate):
            # Recover if config replacement succeeded but the service update failed.
            subprocess.run(["/usr/local/bin/caddy", "validate", "--config", str(target), "--adapter", "caddyfile"],
                           check=True, capture_output=True, timeout=20)
            reload_gateway()
            return True
        return False
    restores = []
    for path in target.parent.glob("rehearsal-*/state.json"):
        state = json.loads(path.read_text())
        if state.get("candidate_hash") == digest(original):
            restore_file = path.parent / "original.Caddyfile"
            restore_original = restore_file.read_text()
            if state.get("original_hash") != digest(restore_original):
                raise ValueError("Scheduled gateway restore changed; do not overwrite")
            restores.append((path, state, restore_file, jenga_gateway(restore_original, upstream)))
    if len(restores) > 1:
        raise ValueError("More than one active gateway restore")
    for name, text in [("jenga-gateway", candidate)] + [("jenga-event-gateway", row[3]) for row in restores]:
        check = state_dir / (name + ".candidate")
        check.write_text(text)
        check.chmod(0o600)
        result = subprocess.run(["/usr/local/bin/caddy", "validate", "--config", str(check), "--adapter", "caddyfile"], capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError("Caddy rejected the capacity settings")
    def replace(path, text):
        meta = path.stat()
        temporary = state_dir / (path.name + ".install")
        temporary.write_text(text)
        temporary.chmod(meta.st_mode & 0o777)
        os.chown(temporary, meta.st_uid, meta.st_gid)
        os.replace(temporary, path)
    # Preserve both QA and event schedules; the existing close job checks these hashes.
    for path, state, restore_file, restored in restores:
        backup = state_dir / "jenga-rehearsal-state-before.json"
        if not backup.exists():
            backup.write_text(json.dumps(state)); backup.chmod(0o600)
        replace(restore_file, restored)
        state.update(candidate_hash=digest(candidate), original_hash=digest(restored))
        replace(path, json.dumps(state))
    backup = state_dir / "jenga-Caddyfile-before"
    if not backup.exists():
        backup.write_text(original); backup.chmod(0o600)
    if target.read_text() != original:
        raise ValueError("Gateway changed during capacity validation")
    replace(target, candidate)
    reload_gateway()
    return True


def kubectl(args, body=None):
    result = subprocess.run(["/usr/local/bin/k3s", "kubectl", *args],
        input=json.dumps(body).encode() if body is not None else None, capture_output=True, timeout=210)
    if result.returncode:
        raise RuntimeError("Scoped Kubernetes operation failed")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("game", choices=("jenga", "swanopoly"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/msgctf-koth-capacity"))
    args = parser.parse_args()
    scoped = ["-n", "koth-" + args.game]
    deployment = json.loads(kubectl(scoped + ["get", "deployment", "game", "-o", "json"]))
    template = capacity_template(args.game, deployment)
    changed = template != deployment["spec"]["template"]
    gateway_changed = False
    if args.apply and args.game == "jenga":
        service = json.loads(kubectl(scoped + ["get", "service", "game", "-o", "json"]))
        upstream = service["spec"]["clusterIP"] + ":8080"
        gateway_changed = tune_jenga_gateway(args.state_dir, upstream)
    if args.apply and changed:
        if args.game == "jenga":
            actual = kubectl(scoped + ["exec", "deployment/game", "-c", "jenga", "--", "python", "-c",
                "import os;print(os.environ.get('JENGA_DB','/data/jenga.db'))"]).decode().strip()
            if actual != DATABASE:
                raise ValueError("Reviewed Jenga database path does not match the running game")
        args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup = args.state_dir / (args.game + "-before.json")
        if not backup.exists():
            with backup.open("x", encoding="utf-8") as stream:
                json.dump(deployment, stream)
            backup.chmod(0o600)
        patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": deployment["metadata"]["resourceVersion"]},
                 {"op": "replace", "path": "/spec/template", "value": template}]
        kubectl(scoped + ["patch", "deployment", "game", "--type=json", "--patch-file=/dev/stdin"], patch)
        kubectl(scoped + ["rollout", "status", "deployment/game", "--timeout=180s"])
    print(json.dumps({"game": args.game, "changes_needed": changed, "applied": bool(args.apply and changed),
                      "gateway_updated": gateway_changed, "game_images_changed": False, "game_source_changed": False}))


if __name__ == "__main__":
    main()
