#!/usr/bin/env python3
"""Apply reviewed KOTH capacity settings without replacing game code or images."""
import argparse
import copy
import json
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
    init = {
        "name": INIT_NAME, "image": game["image"], "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-c", SQLITE_INIT],
        "volumeMounts": [copy.deepcopy(mounts[0])],
        "resources": {"requests": {"cpu": "50m", "memory": "32Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi", "ephemeral-storage": "64Mi"}},
        "securityContext": copy.deepcopy(game.get("securityContext", {})),
    }
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
                      "game_images_changed": False, "game_source_changed": False}))


if __name__ == "__main__":
    main()
