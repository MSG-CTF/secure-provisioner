import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from gateway import controller as c


NGINX = os.environ.get('GATEWAY_TEST_NGINX')


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(self.server.tag + data)


class Web(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '4')
        self.end_headers()
        self.wfile.write(b'web!')

    def log_message(self, *args):
        pass


@unittest.skipUnless(NGINX and os.geteuid() == 0, 'Set GATEWAY_TEST_NGINX and run as root in an isolated Linux test environment')
class NginxIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='gateway-nginx-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, value in {'CONFIG': self.root / 'config.json', 'REGISTRY': self.root / 'routes.conf', 'STATE': self.root, 'JOURNAL': self.root / 'pending.json', 'RESERVED_PORTS': self.root / 'reserved-ports'}.items():
            p = patch.object(c, name, value)
            p.start()
            self.addCleanup(p.stop)
        # Real public-IP admission is exercised in API/controller tests; only the
        # local integration backend is loopback so no external service is used.
        p = patch.object(c, 'public_ip', lambda value: value)
        p.start()
        self.addCleanup(p.stop)
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            self.port = available.getsockname()[1]
        c.RESERVED_PORTS.write_text(str(self.port))
        c.CONFIG.write_text(json.dumps({'base_domain': 'gate.msgctf.kr', 'gateway_public_ip': '127.0.0.2', 'tcp_public_ports': {'start': self.port, 'end': self.port}}))
        c.REGISTRY.write_text(c.HEADER)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(self.root / 'key.pem'), '-out', str(self.root / 'cert.pem'), '-days', '1', '-subj', '/CN=local-gateway-test'], check=True, capture_output=True)
        self.config = self.root / 'nginx.conf'
        version = subprocess.run([NGINX, '-V'], capture_output=True, text=True, check=True)
        module = 'load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n' if '--with-stream=dynamic' in version.stderr else ''
        self.config.write_text(module + f'''pid {self.root}/nginx.pid;
error_log {self.root}/error.log;
events {{ worker_connections 128; }}
http {{ access_log off; }}
stream {{
    server_names_hash_bucket_size 128;
    ssl_certificate {self.root}/cert.pem;
    ssl_certificate_key {self.root}/key.pem;
    proxy_connect_timeout 1s;
    proxy_timeout 30s;
    server {{ listen 443 ssl default_server; listen [::]:443 ssl default_server; ssl_reject_handshake on; }}
    include {c.REGISTRY};
}}
''')
        self.nginx_args = [NGINX, '-p', str(self.root), '-c', str(self.config)]
        startup = subprocess.run(self.nginx_args, capture_output=True, text=True)
        self.assertEqual(startup.returncode, 0, startup.stderr)
        self.addCleanup(self.stop_nginx)
        p = patch.object(c, 'reload_nginx', self.reload_nginx)
        p.start()
        self.addCleanup(p.stop)
        self.servers = []
        self.addCleanup(self.stop_backends)

    def reload_nginx(self):
        for extra in (['-t', '-q'], ['-s', 'reload']):
            result = subprocess.run(self.nginx_args + extra, capture_output=True)
            if result.returncode:
                raise c.ControllerError(502, 'NGINX_APPLY_FAILED', result.stderr.decode())

    def stop_nginx(self):
        subprocess.run(self.nginx_args + ['-s', 'stop'], capture_output=True)
        # Only this test's master/worker processes; no system NGINX service.
        deadline = time.monotonic() + 3
        while (self.root / 'nginx.pid').exists() and time.monotonic() < deadline:
            time.sleep(.02)

    def stop_backends(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()

    def backend(self, tag=None):
        if tag is None:
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Web)
        else:
            server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
            server.daemon_threads = True
            server.tag = tag
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server.server_address[1]

    def put(self, instance, port, protocol='tcp'):
        return c.dispatch({'operation': 'put', 'instance_id': instance, 'target_ip': '127.0.0.1', 'target_port': port, 'protocol': protocol})[1]

    def connect(self):
        deadline = time.monotonic() + 3
        while True:
            try:
                return socket.create_connection(('127.0.0.1', self.port), timeout=1)
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.02)

    def test_nc_delete_reuse_and_existing_web_connection(self):
        web = self.put('web', self.backend(), 'http')
        # Allow the baseline asynchronous NGINX reload to finish.
        time.sleep(.15)
        connection = http.client.HTTPSConnection(web['hostname'], 443, context=ssl._create_unverified_context(), timeout=3)
        connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection(('127.0.0.1', 443), timeout)
        self.addCleanup(connection.close)
        connection.request('GET', '/')
        self.assertEqual(connection.getresponse().read(), b'web!')
        web_socket = connection.sock
        first = self.put('first', self.backend(b'A:'))
        self.assertEqual((first['port'], first['tls']), (self.port, False))
        with self.connect() as active:
            active.sendall(b'unchanged\x00bytes')
            self.assertEqual(active.recv(4096), b'A:unchanged\x00bytes')
            result = subprocess.run(['nc', '-q', '1', '127.0.0.1', str(self.port)], input=b'nc-payload\x00', capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'A:nc-payload\x00')
            self.assertEqual(c.dispatch({'operation': 'delete', 'instance_id': 'first'}), (204, None))
            active.settimeout(1)
            try:
                self.assertEqual(active.recv(1), b'')
            except ConnectionResetError:
                pass
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(('127.0.0.1', self.port), timeout=1)
        second = self.put('second', self.backend(b'B:'))
        self.assertEqual(second['port'], first['port'])
        with self.connect() as active:
            active.sendall(b'new-owner')
            self.assertEqual(active.recv(4096), b'B:new-owner')
        connection.request('GET', '/')
        self.assertEqual(connection.getresponse().read(), b'web!')
        self.assertIs(connection.sock, web_socket, 'TCP deletion must not terminate unrelated web connections')

    def test_existing_tls_tcp_works_before_and_after_pool_activation(self):
        config = json.loads(c.CONFIG.read_text())
        pool = config.pop('tcp_public_ports')
        c.CONFIG.write_text(json.dumps(config))
        target = self.backend(b'TLS:')
        legacy = self.put('legacy', target)
        self.assertEqual((legacy['port'], legacy['tls']), (443, True))
        time.sleep(.15)
        context = ssl._create_unverified_context()
        with context.wrap_socket(socket.create_connection(('127.0.0.1', 443), timeout=3), server_hostname=legacy['hostname']) as existing:
            existing.sendall(b'before')
            self.assertEqual(existing.recv(4096), b'TLS:before')
            config['tcp_public_ports'] = pool
            c.CONFIG.write_text(json.dumps(config))
            self.put('plain', self.backend(b'plain:'))
            self.assertEqual(self.put('legacy', target), legacy)
            existing.sendall(b'after')
            self.assertEqual(existing.recv(4096), b'TLS:after')
            with context.wrap_socket(socket.create_connection(('127.0.0.1', 443), timeout=3), server_hostname=legacy['hostname']) as fresh:
                fresh.sendall(b'fresh')
                self.assertEqual(fresh.recv(4096), b'TLS:fresh')

    def test_asynchronous_nginx_bind_failure_never_publishes_new_route(self):
        target = self.backend(b'echo:')
        with socket.socket() as collision:
            first_reload = True

            def reload_with_bind_race():
                nonlocal first_reload
                if first_reload:
                    first_reload = False
                    # Occupy the chosen port after allocator preflight, before
                    # master reload. nginx -t/reload commands still return zero.
                    collision.bind(('127.0.0.1', self.port))
                    collision.listen()
                self.reload_nginx()

            with patch.object(c, 'reload_nginx', reload_with_bind_race):
                with self.assertRaises(c.ControllerError) as caught:
                    self.put('racing', target)
            self.assertEqual(caught.exception.code, 'NGINX_RECOVERY_REQUIRED')
            self.assertTrue(c.JOURNAL.exists())
            self.assertEqual(c.parse_registry(c.REGISTRY.read_text(), 'gate.msgctf.kr', '127.0.0.2'), ({}, set()))
        self.assertEqual(c.dispatch({'operation': 'reconcile'}), (200, None))
        self.assertFalse(c.JOURNAL.exists())
        route = self.put('racing', target)
        self.assertEqual(route['port'], self.port)
        with self.connect() as connection:
            connection.sendall(b'recovered')
            self.assertEqual(connection.recv(4096), b'echo:recovered')
