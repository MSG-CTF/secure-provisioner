import copy
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from koth_capacity import capacity_template, SQLITE_INIT, jenga_gateway


def deployment(game):
    names = ["jenga"] if game == "jenga" else ["service", "backend", "test", "submit"]
    return {"kind": "Deployment", "metadata": {"name": "game", "namespace": "koth-" + game},
        "spec": {"replicas": 1, "template": {"metadata": {}, "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001},
            "volumes": [{"name": "state", "persistentVolumeClaim": {"claimName": "game-state"}}],
            "containers": [{"name": n, "image": f"ghcr.io/msg-ctf/challenges/koth-{game}/{n}@sha256:" + "a" * 64,
                "command": ["original-command"], "envFrom": [{"secretRef": {"name": n + "-env"}}],
                "env": [{"name": "KEPT", "value": "ordinary-setting"}],
                "volumeMounts": [{"name": "state", "mountPath": "/data"}],
                "securityContext": {"readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "300m", "memory": "256Mi"},
                    "limits": {"cpu": "300m", "memory": "256Mi", "ephemeral-storage": "1Gi"}}} for n in names]}}}}


class CapacityProfiles(unittest.TestCase):
    def test_gateway_bounds_game_upstream_and_preserves_auth_and_release_routes(self):
        original='''game.example {
 @released expression `approved-time-window`
 reverse_proxy 10.0.0.1:8080 {
  header_up Cookie protected
  transport http {
   response_header_timeout 160s
  }
 }
 reverse_proxy https://msgctf.kr {
  transport http {
   response_header_timeout 3s
  }
 }
}
'''
        changed=jenga_gateway(original,'10.0.0.1:8080')
        self.assertEqual(changed.count('max_conns_per_host 8'),1)
        self.assertEqual(changed.replace('  \tmax_conns_per_host 8\n',''),original)
        self.assertEqual(jenga_gateway(changed,'10.0.0.1:8080'),changed)
        unindented='\n'.join(line.lstrip() for line in original.splitlines())+'\n'
        self.assertEqual(jenga_gateway(unindented,'10.0.0.1:8080').count('max_conns_per_host 8'),1)
        with self.assertRaises(ValueError):jenga_gateway(original,'another-upstream:8080')

    def test_jenga_preserves_author_command_image_pvc_and_security(self):
        original = deployment("jenga")
        snapshot = copy.deepcopy(original)
        after = capacity_template("jenga", original)
        self.assertEqual(original, snapshot)
        before_game = original["spec"]["template"]["spec"]["containers"][0]
        after_game = after["spec"]["containers"][0]
        for field in ("command", "image", "env", "envFrom", "volumeMounts", "securityContext"):
            self.assertEqual(after_game[field], before_game[field])
        self.assertEqual(after_game["resources"]["limits"]["ephemeral-storage"], "1Gi")
        self.assertEqual(after_game["resources"]["requests"], before_game["resources"]["requests"])
        self.assertFalse(after["spec"]["automountServiceAccountToken"])
        self.assertNotIn("envFrom", after["spec"]["initContainers"][0])
        original["spec"]["template"] = after
        self.assertEqual(after, capacity_template("jenga", original))

    def test_rejects_shared_sqlite_replicas_and_wrong_game_or_storage(self):
        for change in (lambda d: d["spec"].update(replicas=2),
                       lambda d: d["metadata"].update(namespace="another-game"),
                       lambda d: d["spec"]["template"]["spec"].update(volumes=[])):
            row = deployment("jenga")
            change(row)
            with self.assertRaises(ValueError):
                capacity_template("jenga", row)

    def test_swanopoly_keeps_runner_isolation_and_existing_environment(self):
        original = deployment("swanopoly")
        after = capacity_template("swanopoly", original)
        for before, current in zip(original["spec"]["template"]["spec"]["containers"], after["spec"]["containers"]):
            self.assertEqual(before["resources"], current["resources"])
            self.assertEqual(before["image"], current["image"])
            self.assertEqual(before["command"], current["command"])
            if before["name"] in ("test", "submit"):
                self.assertEqual(current["env"][-1], {"name": "RUNNER_MAX_WAIT_QUEUE", "value": "128"})
            else:
                self.assertEqual(before, current)

    def test_sqlite_init_is_repeatable_and_75_real_writers_keep_all_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "jenga.db"
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("CREATE TABLE teams (team_id INTEGER PRIMARY KEY, height INTEGER)")
                db.execute("INSERT INTO teams VALUES (-1, 7)")
            init = SQLITE_INIT.replace("/data/jenga.db", str(path).replace("\\", "/"))
            exec(compile(init, "<sqlite init>", "exec"), {})
            exec(compile(init, "<sqlite init>", "exec"), {})
            def write(index):
                with closing(sqlite3.connect(path, timeout=5)) as db, db:
                    db.execute("INSERT INTO teams VALUES (?, ?)", (index, 5))
                    return db.execute("SELECT height FROM teams WHERE team_id=-1").fetchone()[0]
            with ThreadPoolExecutor(max_workers=75) as pool:
                self.assertEqual(list(pool.map(write, range(75))), [7] * 75)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                self.assertEqual(db.execute("SELECT COUNT(*), SUM(height) FROM teams").fetchone(), (76, 382))


if __name__ == "__main__":
    unittest.main()
