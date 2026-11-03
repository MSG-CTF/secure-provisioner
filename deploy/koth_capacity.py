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


def dependency_plan(backend, coordinator, node, agent):
    """Four fixed 1-CPU/640Mi runners fit the reviewed dedicated 4-CPU node."""
    if (backend["metadata"].get("namespace") != "dependency-hell" or backend["metadata"]["name"] != "backend"
            or coordinator["metadata"].get("namespace") != "dependency-hell-judge-control"
            or coordinator["metadata"]["name"] != "dependency-hell-coordinator"):
        raise ValueError("Unexpected Dependency Hell deployment")
    allocation = node["status"]["allocatable"]
    cpu = allocation["cpu"]
    millicpu = int(cpu[:-1]) if cpu.endswith("m") else int(cpu) * 1000
    memory = allocation["memory"]
    factor = {"Ki": 1, "Mi": 1024, "Gi": 1024 * 1024}
    memory_kib = next((int(memory[:-2]) * size for suffix, size in factor.items() if memory.endswith(suffix)), 0)
    if millicpu < 4000 or memory_kib < 3584 * 1024:
        raise ValueError("Four runners need the dedicated 4-CPU, 4-GB node")
    conditions = {c["type"]: c["status"] for c in node["status"]["conditions"]}
    if conditions.get("Ready") != "True" or any(conditions.get(k) == "True" for k in ("MemoryPressure", "DiskPressure", "PIDPressure")):
        raise ValueError("Runner node is not healthy")
    games = [g for g in agent["games"] if g["challenge_id"] == "323a66d7-c0e1-5263-965e-58319cb3a7f4"]
    if len(games) != 1 or games[0].get("workloads", {}).get("backend", {}).get("max_replicas", 0) < 4:
        raise ValueError("Environment agent must approve four backend replicas")
    for deployment in (backend, coordinator):
        for c in deployment["spec"]["template"]["spec"]["containers"]:
            if not re.fullmatch(r"ghcr\.io/msg-ctf/challenges/koth-dependency-hell/[a-z0-9_-]+@sha256:[0-9a-f]{64}", c["image"]):
                raise ValueError("Dependency Hell needs its approved immutable images")
    template = copy.deepcopy(coordinator["spec"]["template"])
    containers = template["spec"]["containers"]
    if len(containers) != 1 or containers[0]["name"] != "judge-coordinator":
        raise ValueError("Unexpected coordinator container layout")
    c = containers[0]
    c["env"] = [e for e in c.get("env", []) if e["name"] != "MAX_ACTIVE_EVALUATIONS"]
    c["env"].append({"name": "MAX_ACTIVE_EVALUATIONS", "value": "4"})
    if not 1 <= backend["spec"].get("replicas", 1) <= 4:
        raise ValueError("Review the existing backend replica count")
    return template


def tune_dependency(state_dir, apply):
    backend = json.loads(kubectl(["-n", "dependency-hell", "get", "deployment", "backend", "-o", "json"]))
    coordinator = json.loads(kubectl(["-n", "dependency-hell-judge-control", "get", "deployment", "dependency-hell-coordinator", "-o", "json"]))
    node = json.loads(kubectl(["get", "node", "msg-koth-dependency-hell-runner", "-o", "json"]))
    agent = json.loads(Path("/etc/msgctf-koth-environment/agent.json").read_text())
    template = dependency_plan(backend, coordinator, node, agent)
    changed = template != coordinator["spec"]["template"] or backend["spec"].get("replicas", 1) != 4
    if apply and changed:
        jobs = json.loads(kubectl(["-n", "dependency-hell-judge-runners", "get", "jobs", "-o", "json"]))
        if jobs["items"]:
            raise ValueError("Wait for active runner jobs to be cleaned before capacity changes")
        resident = json.loads(kubectl(["get", "pods", "-A", "--field-selector", "spec.nodeName=msg-koth-dependency-hell-runner", "-o", "json"]))
        if any(p["status"]["phase"] not in ("Succeeded", "Failed") for p in resident["items"]):
            raise ValueError("The four reserved CPU slots must be free on the dedicated runner node")
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup = state_dir / "dependency-before.json"
        if not backup.exists():
            backup.write_text(json.dumps({"backend": backend, "coordinator": coordinator})); backup.chmod(0o600)
        changes = [(coordinator, "/spec/template", template), (backend, "/spec/replicas", 4)]
        for deployment, path, value in changes:
            original = deployment["spec"]["template"] if path.endswith("template") else deployment["spec"].get("replicas", 1)
            if original == value:
                continue
            meta = deployment["metadata"]
            scoped = ["-n", meta["namespace"]]
            kubectl(scoped + ["patch", "deployment", meta["name"], "--type=json", "--patch-file=/dev/stdin"],
                [{"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
                 {"op": "replace", "path": path, "value": value}])
            kubectl(scoped + ["rollout", "status", "deployment/" + meta["name"], "--timeout=180s"])
    return {"game": "dependency-hell", "changes_needed": changed, "applied": bool(apply and changed),
            "backend_replicas": 4, "coordinator_slots": 4, "runner_limits_unchanged": True,
            "game_images_changed": False, "game_source_changed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("game", choices=("jenga", "swanopoly", "dependency-hell"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/msgctf-koth-capacity"))
    args = parser.parse_args()
    if args.game == "dependency-hell":
        print(json.dumps(tune_dependency(args.state_dir, args.apply)))
        return
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
