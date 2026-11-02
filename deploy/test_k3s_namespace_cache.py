import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("k3s_namespace_cache", Path(__file__).with_name("k3s_namespace_cache.py"))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
UID = "0f395a01-f9b1-4863-8278-391a67f87d55"


class FakeSystem:
    def __init__(self):
        self.node_uid = UID
        self.namespaces = []
        self.budget = dict(tool.BASE)
        self.restarts = 0
        self.fail_tuned_wait = False
        self.custom_cli = False

    def check_config_source(self):
        if self.custom_cli:
            raise tool.Refused("custom CLI")

    def snapshot(self, expected):
        tool.validate_node([{"metadata": {"uid": self.node_uid}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}], self.namespaces, expected)
        return self.budget

    def restart(self):
        self.restarts += 1

    def wait(self, expected, budget):
        if self.fail_tuned_wait and budget == tool.TUNED:
            raise tool.Refused("synthetic restart failure")
        self.snapshot(expected)
        self.budget = dict(budget)


class NamespaceCacheProfileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "k3s"
        self.config.mkdir()
        self.original = b"write-kubeconfig-mode: '0600'\nkube-controller-manager-arg:\n  - node-cidr-mask-size-ipv4=24\n"
        (self.config / "config.yaml").write_bytes(self.original)
        self.system = FakeSystem()
        self.tuning = tool.Tuning(UID, self.config, self.root / "state", self.system)

    def test_plan_is_read_only_and_uses_append_dropin(self):
        plan = self.tuning.plan()
        self.assertEqual(plan["baseline"], tool.BASE)
        self.assertFalse(self.tuning.path.exists())
        self.assertFalse(self.tuning.state_path.exists())
        self.assertEqual(self.system.restarts, 0)
        self.assertIn(b"kube-apiserver-arg+:", tool.DROPIN)
        self.assertEqual((self.config / "config.yaml").read_bytes(), self.original)

    def test_apply_restore_preserve_every_existing_argument(self):
        self.assertEqual(self.tuning.apply()["phase"], "applied_verified")
        self.assertEqual(self.system.budget, tool.TUNED)
        self.assertEqual(self.tuning.path.read_bytes(), tool.DROPIN)
        self.assertEqual(self.tuning.restore()["phase"], "restored_verified")
        self.assertFalse(self.tuning.path.exists())
        self.assertEqual(self.system.budget, tool.BASE)
        self.assertEqual(self.system.restarts, 2)
        self.assertEqual((self.config / "config.yaml").read_bytes(), self.original)

    def test_active_and_terminating_namespaces_block_restarts(self):
        for suffix in [None, "2026-11-02T00:00:00Z"]:
            with self.subTest(deletion_timestamp=suffix):
                self.system.namespaces = [{"metadata": {"name": "ctf-owned", "deletionTimestamp": suffix}}]
                with self.assertRaises(tool.Refused):
                    self.tuning.apply()
                self.assertFalse(self.tuning.path.exists())
                self.assertEqual(self.system.restarts, 0)

    def test_wrong_node_is_never_modified(self):
        self.system.node_uid = "another-node"
        with self.assertRaises(tool.Refused):
            self.tuning.apply()
        self.assertFalse(self.tuning.state_path.exists())
        self.assertEqual(self.system.restarts, 0)

    def test_existing_cache_override_is_not_replaced(self):
        (self.config / "config.yaml").write_bytes(b"kube-controller-manager-arg:\n - watch-cache=true\n")
        with self.assertRaises(tool.Refused):
            self.tuning.apply()
        self.assertEqual(self.system.restarts, 0)

    def test_cli_override_is_refused(self):
        self.system.custom_cli = True
        with self.assertRaises(tool.Refused):
            self.tuning.apply()
        self.assertFalse(self.tuning.state_path.exists())

    def test_failed_verification_automatically_restores_baseline(self):
        self.system.fail_tuned_wait = True
        with self.assertRaises(tool.Refused):
            self.tuning.apply()
        self.assertFalse(self.tuning.path.exists())
        self.assertEqual(self.system.budget, tool.BASE)
        self.assertEqual(self.system.restarts, 2)
        self.assertEqual((self.config / "config.yaml").read_bytes(), self.original)

    def test_other_config_change_prevents_restore(self):
        self.tuning.apply()
        (self.config / "config.yaml").write_bytes(self.original + b"disable: traefik\n")
        with self.assertRaises(tool.Refused):
            self.tuning.restore()
        self.assertTrue(self.tuning.path.exists())
        self.assertEqual(self.system.restarts, 1)

    def test_changed_owned_file_prevents_restore(self):
        self.tuning.apply()
        self.tuning.path.write_bytes(tool.DROPIN + b"# changed by operator\n")
        with self.assertRaises(tool.Refused):
            self.tuning.restore()
        self.assertEqual(self.system.restarts, 1)

    def test_namespace_arriving_after_plan_prevents_restart(self):
        original = self.system.snapshot
        calls = 0
        def snapshot(expected):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.system.namespaces = [{"metadata": {"name": "ctf-arrived"}}]
            return original(expected)
        with patch.object(self.system, "snapshot", side_effect=snapshot):
            with self.assertRaises(tool.Refused):
                self.tuning.apply()
        self.assertFalse(self.tuning.path.exists())
        # A last-moment workload prevents both the initial restart and rollback restart
        self.assertEqual(self.system.restarts, 0)

    def test_actual_startup_log_parses_quoted_false_and_default(self):
        self.assertEqual(tool.cache_profile('msg="Running kube-apiserver --watch-cache=false"'), tool.TUNED)
        self.assertEqual(tool.cache_profile('msg="Running kube-apiserver --secure-port=6443"'), tool.BASE)
        for log in ['', 'Running kube-apiserver --watch-cache=unknown', 'Running kube-apiserver --watch-cache=false --watch-cache=true']:
            with self.subTest(log=log), self.assertRaises(tool.Refused):
                tool.cache_profile(log)

    def test_namespace_arriving_during_failed_verification_blocks_rollback_restart(self):
        def wait(expected, budget):
            self.system.namespaces = [{"metadata": {"name": "ctf-arrived"}}]
            raise tool.Refused("verification failed")
        with patch.object(self.system, "wait", side_effect=wait):
            with self.assertRaises(tool.Refused):
                self.tuning.apply()
        self.assertEqual(self.system.restarts, 1)
        self.assertTrue(self.tuning.path.exists())



if __name__ == "__main__":
    unittest.main()
