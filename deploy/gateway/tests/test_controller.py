import json
import multiprocessing
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from gateway import controller as c


def concurrent_put(number):
    for _ in range(200):
        try:
            return c.dispatch({'operation': 'put', 'instance_id': f'parallel-{number}', 'target_ip': '8.8.8.8', 'target_port': 32000 + number, 'protocol': 'tcp'})[1]['port']
        except c.ControllerError as error:
            if error.code != 'GATEWAY_BUSY':
                raise
            time.sleep(.005)
    raise AssertionError('Registry lock did not become available')


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        for name, value in {'CONFIG': root / 'config.json', 'REGISTRY': root / 'routes.conf', 'STATE': root, 'JOURNAL': root / 'pending.json'}.items():
            p = patch.object(c, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.config = {'base_domain': 'gate.msgctf.kr', 'gateway_public_ip': '8.8.4.4'}
        self.write_config()
        p = patch.object(c, 'reload_nginx')
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(c, 'RESERVED_PORTS', root / 'reserved-ports', create=True)
        p.start()
        self.addCleanup(p.stop)
        c.RESERVED_PORTS.write_text('1024-65535')
        p = patch.object(c, 'confirm_tcp_listeners', create=True)
        p.start()
        self.addCleanup(p.stop)

    def write_config(self):
        c.CONFIG.write_text(json.dumps(self.config))

    def enable_pool(self, start=42817, end=42818):
        self.config['tcp_public_ports'] = {'start': start, 'end': end}
        self.write_config()

    def put(self, instance='sample-1', protocol='tcp', target_port=31042):
        return c.dispatch({'operation': 'put', 'instance_id': instance, 'target_ip': '8.8.8.8', 'target_port': target_port, 'protocol': protocol})

    def test_existing_http_and_default_tcp_contract(self):
        for index, protocol in enumerate(('http', 'tcp')):
            with self.subTest(protocol=protocol):
                status, route = self.put(protocol, protocol, 31042 + index)
                self.assertEqual(status, 201)
                self.assertEqual(route['port'], 443)
                self.assertIs(route['tls'], True)
                self.assertEqual(route['url'], 'https://' + route['hostname'] if protocol == 'http' else None)
                self.assertEqual(self.put(protocol, protocol, 31042 + index), (200, route))

    def test_retry_uses_only_same_approved_target_and_reads_legacy_registry(self):
        self.put('retained', 'http')
        routes, deleted = c.parse_registry(c.REGISTRY.read_text(), 'gate.msgctf.kr', '8.8.4.4')
        deleted.add('retired-id')
        legacy = c.render_legacy(routes, deleted)
        self.assertEqual(c.parse_registry(legacy, 'gate.msgctf.kr', '8.8.4.4'), (routes, deleted))
        rendered = c.render(routes, deleted)
        self.assertEqual(c.parse_registry(rendered, 'gate.msgctf.kr', '8.8.4.4'), (routes, deleted))
        self.assertEqual(rendered.count('    server 8.8.8.8:31042 max_fails=0'), 2)
        self.assertIn('proxy_next_upstream_tries 2;', rendered)
        self.assertIn('proxy_next_upstream_timeout 4s;', rendered)
        self.assertIn('proxy_connect_timeout 2s;', rendered)
        tampered = rendered.replace('server 8.8.8.8:31042 max_fails=0 backup;',
                                    'server 1.1.1.1:31042 max_fails=0 backup;')
        with self.assertRaises(ValueError):
            c.parse_registry(tampered, 'gate.msgctf.kr', '8.8.4.4')

    def test_tcp_pool_returns_persistent_plaintext_port_and_http_stays_https(self):
        self.enable_pool()
        _, web = self.put('web', 'http')
        self.assertEqual((web['port'], web['tls']), (443, True))
        _, tcp = self.put('tcp', 'tcp', 31043)
        self.assertIn(tcp['port'], (42817, 42818))
        self.assertIs(tcp['tls'], False)
        self.assertIsNone(tcp['url'])
        rendered = c.REGISTRY.read_text()
        self.assertIn(f"listen {tcp['port']};", rendered)
        self.assertNotIn(f"listen {tcp['port']} ssl;", rendered)
        self.assertEqual(c.dispatch({'operation': 'get', 'instance_id': 'tcp'}), (200, tcp))
        self.config.pop('tcp_public_ports')
        self.write_config()
        self.assertEqual(self.put('tcp', 'tcp', 31043), (200, tcp))

    def test_existing_tls_tcp_not_migrated_when_pool_is_enabled(self):
        _, legacy = self.put('legacy')
        original = c.REGISTRY.read_text()
        self.enable_pool()
        self.assertEqual(self.put('legacy'), (200, legacy))
        self.assertEqual(c.REGISTRY.read_text(), original)

    def test_pool_exhaustion_does_not_modify_registry(self):
        self.enable_pool(42817, 42817)
        _, first = self.put('first')
        previous = c.REGISTRY.read_text()
        with self.assertRaises(c.ControllerError) as caught:
            self.put('second', target_port=31043)
        self.assertEqual((caught.exception.status, caught.exception.code), (503, 'PORT_POOL_EXHAUSTED'))
        self.assertEqual(c.REGISTRY.read_text(), previous)
        self.assertEqual(c.dispatch({'operation': 'get', 'instance_id': 'first'}), (200, first))

    def test_allocator_skips_an_occupied_host_port(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            port = occupied.getsockname()[1]
            self.enable_pool(port, port)
            with self.assertRaises(c.ControllerError) as caught:
                self.put()
            self.assertEqual(caught.exception.code, 'PORT_POOL_EXHAUSTED')
            self.assertFalse(c.REGISTRY.exists())

    def test_deleted_port_reusable_but_deleted_instance_id_stays_tombstoned(self):
        self.enable_pool(42817, 42817)
        _, first = self.put('first')
        self.assertEqual(c.dispatch({'operation': 'delete', 'instance_id': 'first'}), (204, None))
        _, second = self.put('second', target_port=31043)
        self.assertEqual(second['port'], first['port'])
        with self.assertRaises(c.ControllerError) as caught:
            self.put('first')
        self.assertEqual(caught.exception.code, 'INSTANCE_DELETED')

    def test_invalid_pool_fails_new_tcp_without_modifying_existing_web(self):
        self.put('web', 'http')
        original = c.REGISTRY.read_text()
        for pool in ({'start': 22, 'end': 23}, {'start': True, 'end': 40001}, {'start': 50000, 'end': 40000}, {'start': 40000, 'end': 65536}, {'start': 40000}, []):
            with self.subTest(pool=pool):
                self.config['tcp_public_ports'] = pool
                self.write_config()
                with self.assertRaises(c.ControllerError) as caught:
                    self.put('bad', target_port=31043)
                self.assertEqual(caught.exception.code, 'GATEWAY_NOT_CONFIGURED')
                self.assertEqual(c.REGISTRY.read_text(), original)

    def test_duplicate_and_invalid_public_ports_are_rejected_on_recovery(self):
        routes = {
            'a': {'instance_id': 'a', 'hostname': 'a' * 32 + '.gate.msgctf.kr', 'target_ip': '8.8.8.8', 'target_port': 31042, 'protocol': 'tcp', 'created_at': '2026-10-27T00:00:00+00:00', 'public_port': 42817},
            'b': {'instance_id': 'b', 'hostname': 'b' * 32 + '.gate.msgctf.kr', 'target_ip': '8.8.8.8', 'target_port': 31043, 'protocol': 'tcp', 'created_at': '2026-10-27T00:00:00+00:00', 'public_port': 42817},
        }
        for invalid in (routes, {'a': {**routes['a'], 'public_port': True}}, {'a': {**routes['a'], 'public_port': 443}}, {'a': {**routes['a'], 'protocol': 'http'}}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    c.parse_registry(c.render(invalid, set()), 'gate.msgctf.kr', '8.8.4.4')

    def test_failed_reload_preserves_port_for_retry(self):
        self.enable_pool(42817, 42817)
        _, original = self.put('first')
        with patch.object(c, 'reload_nginx', side_effect=[c.ControllerError(502, 'NGINX_APPLY_FAILED', 'test'), None]):
            with self.assertRaises(c.ControllerError):
                c.dispatch({'operation': 'delete', 'instance_id': 'first'})
        self.assertEqual(c.dispatch({'operation': 'get', 'instance_id': 'first'}), (200, original))
        with self.assertRaises(c.ControllerError) as caught:
            self.put('second', target_port=31043)
        self.assertEqual(caught.exception.code, 'PORT_POOL_EXHAUSTED')

    def test_unconfirmed_listener_change_is_not_published(self):
        self.enable_pool(42817, 42817)
        with patch.object(c, 'confirm_tcp_listeners', side_effect=[c.ControllerError(503, 'ROUTE_CLEANUP_PENDING', 'synthetic failure'), None]):
            with self.assertRaises(c.ControllerError):
                self.put('unconfirmed')
        self.assertFalse(c.REGISTRY.exists())
        self.assertFalse(c.JOURNAL.exists())

    def test_failed_socket_cleanup_retains_route_and_its_public_port(self):
        self.enable_pool(42817, 42817)
        _, route = self.put('first')
        with patch.object(c, 'retire_tcp_connections', create=True, side_effect=[c.ControllerError(503, 'ROUTE_CLEANUP_PENDING', 'synthetic failure'), None]):
            with self.assertRaises(c.ControllerError) as caught:
                c.dispatch({'operation': 'delete', 'instance_id': 'first'})
        self.assertEqual(caught.exception.code, 'ROUTE_CLEANUP_PENDING')
        self.assertEqual(c.dispatch({'operation': 'get', 'instance_id': 'first'}), (200, route))
        with self.assertRaises(c.ControllerError):
            self.put('second', target_port=31043)

    def test_valid_plaintext_registry_roundtrip_is_supported(self):
        route = {'instance_id': 'a', 'hostname': 'a' * 32 + '.gate.msgctf.kr', 'target_ip': '8.8.8.8', 'target_port': 31042, 'protocol': 'tcp', 'created_at': '2026-10-27T00:00:00+00:00', 'public_port': 42817}
        self.assertEqual(c.parse_registry(c.render({'a': route}, set()), 'gate.msgctf.kr', '8.8.4.4'), ({'a': route}, set()))

    def test_pool_must_be_reserved_from_ephemeral_connections(self):
        self.enable_pool(42817, 42818)
        for reservation in ('', '42817', '42818-42820'):
            with self.subTest(reservation=reservation):
                c.RESERVED_PORTS.write_text(reservation)
                with self.assertRaises(c.ControllerError) as caught:
                    self.put()
                self.assertEqual(caught.exception.code, 'GATEWAY_NOT_CONFIGURED')
                self.assertFalse(c.REGISTRY.exists())
        c.RESERVED_PORTS.write_text('42817,42818-42820')
        self.assertIs(self.put()[1]['tls'], False)

    def test_concurrent_allocations_have_unique_persisted_ports(self):
        self.enable_pool(42817, 42832)
        with multiprocessing.get_context('fork').Pool(4) as workers:
            ports = workers.map(concurrent_put, range(12))
        self.assertEqual(len(set(ports)), 12)
        routes, _ = c.parse_registry(c.REGISTRY.read_text(), 'gate.msgctf.kr', '8.8.4.4')
        self.assertEqual({r['public_port'] for r in routes.values()}, set(ports))

    def test_reconcile_requires_persisted_tcp_listeners_ready(self):
        self.enable_pool(42817, 42817)
        _, route = self.put()
        with patch.object(c, 'confirm_tcp_listeners', side_effect=c.ControllerError(503, 'ROUTE_CLEANUP_PENDING', 'not active')):
            with self.assertRaises(c.ControllerError):
                c.dispatch({'operation': 'reconcile'})
        self.assertEqual(c.dispatch({'operation': 'get', 'instance_id': 'sample-1'}), (200, route))

    def test_crashed_delete_recovers_original_port_before_replay(self):
        self.enable_pool(42817, 42817)
        _, route = self.put()
        original = c.REGISTRY.read_text()
        c.JOURNAL.write_text(json.dumps({'previous': original}))
        c.REGISTRY.write_text(c.render({}, {'sample-1'}))
        self.assertEqual(c.dispatch({'operation': 'get', 'instance_id': 'sample-1'}), (200, route))
        self.assertFalse(c.JOURNAL.exists())

    def test_crashed_create_removes_unconfirmed_listener_before_reallocation(self):
        self.enable_pool(42817, 42817)
        self.put()
        c.JOURNAL.write_text(json.dumps({'previous': None}))
        with patch.object(c, 'retire_tcp_connections', side_effect=c.ControllerError(503, 'ROUTE_CLEANUP_PENDING', 'still active')):
            with self.assertRaises(c.ControllerError) as caught:
                c.dispatch({'operation': 'reconcile'})
        self.assertEqual(caught.exception.code, 'NGINX_RECOVERY_REQUIRED')
        self.assertTrue(c.JOURNAL.exists())

    def test_repeated_failed_rollback_keeps_pending_port_cleanup_durable(self):
        self.enable_pool(42817, 42817)
        self.put()
        c.JOURNAL.write_text(json.dumps({'previous': None}))

        def fail_while_port_is_active(ports):
            if 42817 in ports:
                raise c.ControllerError(503, 'ROUTE_CLEANUP_PENDING', 'still active')

        with patch.object(c, 'retire_tcp_connections', side_effect=fail_while_port_is_active):
            for attempt in range(3):
                with self.subTest(attempt=attempt):
                    with self.assertRaises(c.ControllerError) as caught:
                        c.dispatch({'operation': 'reconcile'})
                    self.assertEqual(caught.exception.code, 'NGINX_RECOVERY_REQUIRED')
                    self.assertTrue(c.JOURNAL.exists())
        self.assertEqual(c.dispatch({'operation': 'reconcile'}), (200, None))
        self.assertFalse(c.JOURNAL.exists())

    def test_crash_after_registry_restoration_does_not_forget_rollback_port(self):
        self.enable_pool(42817, 42817)
        c.JOURNAL.write_text(json.dumps({'previous': None, 'rollback_ports': [42817]}))

        def fail_while_port_is_active(ports):
            if ports:
                raise c.ControllerError(503, 'ROUTE_CLEANUP_PENDING', 'still active')

        with patch.object(c, 'retire_tcp_connections', side_effect=fail_while_port_is_active):
            with self.assertRaises(c.ControllerError) as caught:
                c.dispatch({'operation': 'reconcile'})
        self.assertEqual(caught.exception.code, 'NGINX_RECOVERY_REQUIRED')
        self.assertTrue(c.JOURNAL.exists())

    def test_malformed_cleanup_intent_is_not_discarded(self):
        for ports in (None, [443], [True], [42817, 42817], '42817'):
            with self.subTest(ports=ports):
                c.JOURNAL.write_text(json.dumps({'previous': None, 'rollback_ports': ports}))
                with self.assertRaises(c.ControllerError) as caught:
                    c.dispatch({'operation': 'reconcile'})
                self.assertEqual(caught.exception.code, 'NGINX_RECOVERY_REQUIRED')
                self.assertTrue(c.JOURNAL.exists())


if __name__ == '__main__':
    unittest.main()
