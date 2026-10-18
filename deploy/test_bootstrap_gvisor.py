import tempfile
import unittest
from pathlib import Path

from bootstrap_gvisor import check_idle, write_reviewed_file


class GVisorBootstrapTests(unittest.TestCase):
    def test_restart_rejects_live_challenge_pods(self):
        check_idle([{"metadata": {"namespace": "kube-system"}}])
        with self.assertRaises(RuntimeError):
            check_idle([{"metadata": {"namespace": "ctf-abc"}}])

    def test_existing_configuration_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "runtime.toml"
            self.assertTrue(write_reviewed_file(target, b"approved", 0o644))
            self.assertFalse(write_reviewed_file(target, b"approved", 0o644))
            with self.assertRaises(RuntimeError):
                write_reviewed_file(target, b"unreviewed", 0o644)
            self.assertEqual(target.read_bytes(), b"approved")

    def test_configuration_cannot_follow_a_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = root / "original"
            original.write_bytes(b"keep")
            link = root / "link"
            link.symlink_to(original)
            with self.assertRaises(RuntimeError):
                write_reviewed_file(link, b"replacement", 0o644)
            self.assertEqual(original.read_bytes(), b"keep")
