import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import koth_core_gateway as gateway

BASE = '''    location = /internal/v1/runtime-secrets/resolve { return 418; }
    location @callback_denied { return 404; }
    location = /internal { return 404; }
    location /internal/ { return 404; }
    location / { return 204; }
'''


class GatewayRenderTests(unittest.TestCase):
    def test_only_known_koth_routes_added_without_changing_existing_denies(self):
        rendered = gateway.render(BASE, ['34.16.75.67', '136.108.97.182'])
        start = rendered.index(gateway.BEGIN)
        end = rendered.index(gateway.END) + len(gateway.END)
        self.assertEqual(rendered[:start] + rendered[end:], BASE)
        self.assertEqual(rendered, gateway.render(rendered, ['136.108.97.182', '34.16.75.67']))
        self.assertEqual(rendered.count('allow 34.16.75.67/32;'), 3)
        self.assertNotIn('location /internal/ {\n', rendered)

    def test_subnets_injection_missing_deny_and_modified_managed_block_rejected(self):
        for sources in [[], ['0.0.0.0/0'], ['127.0.0.1; allow all'], ['::1']]:
            with self.assertRaises(ValueError):
                gateway.render(BASE, sources)
        with self.assertRaises(ValueError):
            gateway.render(BASE.replace('location /internal/', 'location /other/'), ['127.0.0.1'])
        rendered = gateway.render(BASE, ['127.0.0.1'])
        with self.assertRaises(ValueError):
            gateway.render(rendered.replace('deny all;', 'allow all;', 1), ['127.0.0.1'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX atomic file replacement')
    def test_failed_configuration_or_reload_restores_exact_original_and_reloads(self):
        for failure in [0, 1]:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as root:
                path = Path(root) / 'nginx.conf'
                path.write_bytes(b'original configuration')
                outcomes = [None] * 4
                outcomes[failure] = RuntimeError('nginx failed')
                with patch.object(gateway, 'nginx', side_effect=outcomes) as command:
                    with self.assertRaisesRegex(RuntimeError, 'ROLLBACK_VERIFIED'):
                        gateway.replace_and_reload(path, path.read_bytes(), b'candidate', 0o644, 'gateway')
                self.assertEqual(path.read_bytes(), b'original configuration')
                self.assertEqual(command.call_args_list[-2].args[1], ['-t'])
                self.assertEqual(command.call_args_list[-1].args[1], ['-s', 'reload'])
                self.assertEqual(list(Path(root).iterdir()), [path])


@unittest.skipUnless(os.environ.get('MSGCTF_KOTH_GATEWAY_HTTP') == '1', 'real nginx HTTP stage')
class RealGatewayHTTPTests(unittest.TestCase):
    def test_real_nginx_acl_uri_guard_auth_forwarding_and_default_deny(self):
        binary = shutil.which('nginx') or '/usr/sbin/nginx'
        self.assertTrue(Path(binary).is_file(), 'CI must install nginx for the required HTTP stage')
        requests = []

        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append({'path': self.path, 'forwarded': self.headers.get('X-Forwarded-For')})
                self.send_response(405)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"code":"METHOD_NOT_ALLOWED"}')

            def do_POST(self):
                requests.append({'path': self.path, 'authorization': self.headers.get('Authorization'), 'forwarded': self.headers.get('X-Forwarded-For')})
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"code":"INVALID_INTERNAL_TOKEN"}')

            def log_message(self, *_args):
                pass

        backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        process = None
        try:
            with tempfile.TemporaryDirectory() as root:
                root = Path(root)
                with socket.socket() as port_socket:
                    port_socket.bind(('127.0.0.1', 0))
                    port = port_socket.getsockname()[1]
                rendered = gateway.render(BASE, ['127.0.0.1']).replace('http://backend:8080', 'http://127.0.0.1:' + str(backend.server_port))
                config = root / 'nginx.conf'
                config.write_text('daemon off; master_process off;\npid ' + str(root / 'nginx.pid') + ';\nerror_log ' + str(root / 'error.log') + ';\nevents {}\nhttp { access_log off; server { listen 127.0.0.1:' + str(port) + ';\n' + rendered + '\n} }\n')
                checked = subprocess.run([binary, '-t', '-c', str(config)], capture_output=True)
                self.assertEqual(checked.returncode, 0, checked.stderr.decode())
                process = subprocess.Popen([binary, '-c', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                def request(path, method='POST', source='127.0.0.1'):
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3, source_address=(source, 0))
                    try:
                        connection.request(method, path, headers={'Authorization': 'test-only-key', 'X-Forwarded-For': '127.0.0.1'})
                        response = connection.getresponse()
                        response.read()
                        return response.status
                    finally:
                        connection.close()

                for _attempt in range(50):
                    try:
                        if request('/healthz', 'GET') == 204:
                            break
                    except OSError:
                        time.sleep(0.02)
                challenge = '00000000-0000-4000-8000-000000000001'
                routes = ['/internal/koth/team_tokens/verify', '/internal/teams', '/internal/v1/koth_environments/' + challenge, '/internal/v1/koth_environments/' + challenge + '/status', '/internal/v1/koth_environments/' + challenge + '/image_export']
                for route in routes:
                    self.assertEqual(request(route), 401, route)
                    self.assertEqual(requests[-1]['authorization'], 'test-only-key')
                    self.assertEqual(requests[-1]['forwarded'], '127.0.0.1')
                    count = len(requests)
                    self.assertEqual(request(route, source='127.0.0.2'), 404, route)
                    self.assertEqual(len(requests), count, 'spoofed source header reached backend')
                self.assertEqual(request(routes[0], 'GET'), 405)
                for route in ['/internal', '/internal/other', '/internal/teams/', routes[0] + '/extra', '/internal/v1/koth_environments/not-a-uuid', '/internal/koth/team_tokens/%76erify', '/internal//koth/team_tokens/verify']:
                    count = len(requests)
                    self.assertEqual(request(route), 404, route)
                    self.assertEqual(len(requests), count, route)
                self.assertEqual(request('/internal/v1/runtime-secrets/resolve'), 418, 'existing broker route changed')
        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
