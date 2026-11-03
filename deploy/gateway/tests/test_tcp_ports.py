import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

from gateway import controller as c


class TCPPortTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        reservation = Path(temporary.name) / 'reserved'
        reservation.write_text('42817')
        p = patch.object(c, 'RESERVED_PORTS', reservation)
        p.start()
        self.addCleanup(p.stop)

    def test_listener_must_actually_belong_to_nginx_on_both_address_families(self):
        for output in ('', 'LISTEN 0 128 0.0.0.0:42817 0.0.0.0:* users:(("other",pid=1,fd=1))\nLISTEN 0 128 [::]:42817 [::]:* users:(("other",pid=1,fd=2))\n'):
            with self.subTest(output=output), patch.object(c, 'socket_status', return_value=output), patch.object(c.time, 'monotonic', side_effect=[0, 6]):
                with self.assertRaises(c.ControllerError) as caught:
                    c.confirm_tcp_listeners({42817}, set())
                self.assertEqual(caught.exception.code, 'ROUTE_CLEANUP_PENDING')

    def test_failed_or_unsupported_socket_destruction_cannot_confirm_cleanup(self):
        active = 'ESTAB 0 0 127.0.0.1:42817 127.0.0.1:50000\n'
        with patch.object(c, 'socket_status', side_effect=[active, '', active]):
            with self.assertRaises(c.ControllerError) as caught:
                c.retire_tcp_connections({42817})
        self.assertEqual(caught.exception.code, 'ROUTE_CLEANUP_PENDING')
