"""Native regression: run as root in a private Linux mount namespace.

unshare --mount --propagation private --fork env \
  RUNTIME_TEST_NATIVE_SOCKET_RECOVERY=1 python3 deploy/test_image_agent_socket_recovery.py
"""
import errno
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0
    and os.environ.get("RUNTIME_TEST_NATIVE_SOCKET_RECOVERY") == "1",
    "requires explicit opt-in inside a private Linux mount namespace",
)
class SocketRecoveryTest(unittest.TestCase):
    def test_directory_mount_tracks_replaced_runtime_socket(self):
        # Never modify the caller's mount namespace, even with accidental opt-in.
        self.assertNotEqual(os.readlink("/proc/self/ns/mnt"), os.readlink("/proc/1/ns/mnt"))
        with tempfile.TemporaryDirectory(prefix="image-agent-socket-recovery-") as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            endpoint = source / "containerd.sock"
            file_mount = root / "old-socket"
            file_mount.touch()
            directory_mount = root / "directory"
            directory_mount.mkdir()
            bound = []
            listeners = []

            def listen(value):
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(endpoint))
                listener.listen(4)
                listener.settimeout(0.1)
                stopped = threading.Event()

                def serve():
                    while not stopped.is_set():
                        try:
                            connection, _ = listener.accept()
                        except socket.timeout:
                            continue
                        except OSError:
                            break
                        with connection:
                            connection.sendall(value)

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                item = listener, stopped, thread
                listeners.append(item)
                return item

            def close(item):
                listener, stopped, thread = item
                stopped.set()
                listener.close()
                thread.join(2)
                self.assertFalse(thread.is_alive())

            def request(path):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(2)
                    client.connect(str(path))
                    return client.recv(16)

            try:
                first = listen(b"before")
                for original, target in ((endpoint, file_mount), (source, directory_mount)):
                    subprocess.run(["mount", "--bind", str(original), str(target)], check=True, capture_output=True)
                    bound.append(target)
                self.assertEqual(request(file_mount), b"before")
                self.assertEqual(request(directory_mount / endpoint.name), b"before")
                close(first)
                listeners.remove(first)
                endpoint.unlink()
                listen(b"recovered")
                self.assertNotEqual(os.stat(file_mount).st_ino, os.stat(endpoint).st_ino)
                self.assertEqual(os.stat(directory_mount / endpoint.name).st_ino, os.stat(endpoint).st_ino)
                with self.assertRaises(OSError) as error:
                    request(file_mount)
                self.assertEqual(error.exception.errno, errno.ECONNREFUSED)
                self.assertEqual(request(directory_mount / endpoint.name), b"recovered")
            finally:
                for item in listeners:
                    close(item)
                for target in reversed(bound):
                    subprocess.run(["umount", str(target)], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
