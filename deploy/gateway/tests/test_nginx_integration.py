import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
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

    def blackhole_first_upstream_connection(self, target, suffix, count=1):
        tool = os.environ['GATEWAY_TEST_IPTABLES']
        chain = 'GW111_' + suffix
        command = [tool, '-w', '5', '-t', 'mangle']
        subprocess.run(command + ['-N', chain], check=True, capture_output=True)
        jump = ['-p', 'tcp', '-d', '127.0.0.1', '--dport', str(target), '--syn', '-j', chain]
        def remove():
            subprocess.run(command + ['-D', 'OUTPUT'] + jump, capture_output=True)
            subprocess.run(command + ['-F', chain], capture_output=True)
            subprocess.run(command + ['-X', chain], capture_output=True)
        self.addCleanup(remove)
        # A dropped initial SYN is not yet a confirmed conntrack entry, so a
        # connmark cannot reliably remember that flow. Observe its SYN-SENT
        # socket in this private namespace instead, then allow only different
        # source ports. Every retransmission of the first socket stays dropped
        subprocess.run(command + ['-A', chain, '-j', 'DROP'], check=True, capture_output=True)
        subprocess.run(command + ['-I', 'OUTPUT', '1'] + jump, check=True, capture_output=True)
        fault = {'source_ports': [], 'expected_dropped_flows': count, 'error': None}
        def identify_first_flow():
            try:
                deadline = time.monotonic() + 6
                destination = f'0100007F:{target:04X}'
                while time.monotonic() < deadline:
                    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
                        fields = line.split()
                        if fields[2] == destination and fields[3] == '02':
                            source = int(fields[1].split(':')[1], 16)
                            if source not in fault['source_ports']:fault['source_ports'].append(source)
                            if len(fault['source_ports'])==count:
                                subprocess.run(command + ['-I', chain, '1', '-p', 'tcp', '-m', 'multiport', '!', '--sports', ','.join(str(port) for port in fault['source_ports']), '-j', 'RETURN'], check=True, capture_output=True)
                                return
                    time.sleep(.005)
                raise TimeoutError('No owned SYN-SENT socket observed')
            except Exception as error:
                fault['error'] = repr(error)
        observer = threading.Thread(target=identify_first_flow, daemon=True)
        observer.start()
        self.addCleanup(observer.join, 7)
        self.faults = getattr(self, 'faults', []) + [fault]
        return remove

    def tls_http_request(self, hostname):
        context = ssl._create_unverified_context()  # isolated test certificate
        start = time.monotonic()
        with context.wrap_socket(socket.create_connection(('127.0.0.1', 443), timeout=10),
                                 server_hostname=hostname) as connection:
            connection.sendall(('GET / HTTP/1.1\r\nHost: ' + hostname + '\r\nConnection: close\r\n\r\n').encode())
            data = b''
            while chunk := connection.recv(4096):
                data += chunk
        return data, time.monotonic() - start

    @unittest.skipUnless(os.environ.get('GATEWAY_TEST_IPTABLES'), 'Requires private iptables in an isolated network namespace')
    def test_connect_retry_recovers_first_blackholed_flow_before_any_application_data(self):
        config = json.loads(c.CONFIG.read_text())
        config.pop('tcp_public_ports')
        c.CONFIG.write_text(json.dumps(config))
        self.config.write_text(self.config.read_text().replace('proxy_connect_timeout 1s;', 'proxy_connect_timeout 5s;'))
        route = self.put('transient-syn-loss', self.backend(), 'http')
        routes, deleted = c.parse_registry(c.REGISTRY.read_text(), 'gate.msgctf.kr', '127.0.0.2')
        target = routes['transient-syn-loss']['target_port']
        c.REGISTRY.write_text(c.render_legacy(routes, deleted))
        self.reload_nginx()
        time.sleep(.2)
        self.assertIn(b'200 OK', self.tls_http_request(route['hostname'])[0])
        remove = self.blackhole_first_upstream_connection(target, 'OLD')
        old_data, old_seconds = self.tls_http_request(route['hostname'])
        remove()
        self.assertEqual(old_data, b'')
        self.assertGreater(old_seconds, 4.5)
        c.REGISTRY.write_text(c.render(routes, deleted))
        self.reload_nginx()
        time.sleep(.2)
        self.assertIn(b'200 OK', self.tls_http_request(route['hostname'])[0])
        self.blackhole_first_upstream_connection(target, 'NEW')
        new_data, new_seconds = self.tls_http_request(route['hostname'])
        self.assertIn(b'200 OK', new_data)
        self.assertTrue(new_data.endswith(b'web!'))
        self.assertLess(new_seconds, 4.5)
        self.assertTrue(all(len(fault['source_ports'])==fault['expected_dropped_flows'] and not fault['error'] for fault in self.faults), self.faults)
        print(json.dumps({'fault': 'first_upstream_tcp_flow_blackholed', 'legacy_seconds': old_seconds,
                          'bounded_retry_seconds': new_seconds, 'legacy_bytes': len(old_data),
                          'retry_http_200': b'200 OK' in new_data, 'faults': self.faults}), flush=True)
        self.assertEqual(c.parse_registry(c.REGISTRY.read_text(), 'gate.msgctf.kr', '127.0.0.2'), (routes, deleted))

    def test_reset_after_receiving_command_never_replays_application_bytes(self):
        received = []
        class ResetAfterRead(socketserver.BaseRequestHandler):
            def handle(self):
                received.append(self.request.recv(4096))
                self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), ResetAfterRead)
        server.daemon_threads = True
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.put('one-command', server.server_address[1])
        with self.connect() as connection:
            connection.settimeout(2)
            connection.sendall(b'execute-once\n')
            try:
                self.assertEqual(connection.recv(4096), b'')
            except ConnectionResetError:
                pass
        time.sleep(.2)
        self.assertEqual(received, [b'execute-once\n'])

    def test_permanently_unavailable_target_has_six_attempts_and_remains_same_owner(self):
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            target = available.getsockname()[1]
        route = self.put('unavailable', target)
        start = time.monotonic()
        with self.connect() as connection:
            connection.settimeout(2)
            try:
                connection.sendall(b'not-executed')
                self.assertEqual(connection.recv(1), b'')
            except ConnectionResetError:
                pass
        self.assertLess(time.monotonic() - start, 2)
        errors = [line for line in (self.root / 'error.log').read_text().splitlines()
                  if 'connect() failed' in line and f'127.0.0.1:{target}' in line]
        self.assertEqual(len(errors), 6)
        self.assertEqual(c.dispatch({'operation': 'get', 'instance_id': 'unavailable'}), (200, route))

    @unittest.skipUnless(os.environ.get('GATEWAY_TEST_IPTABLES'), 'Requires private iptables in an isolated network namespace')
    def test_two_consecutive_blackholed_flows_require_more_than_two_attempts(self):
        route = self.put('two-blackholed-flows', self.backend(), 'http')
        routes, deleted = c.parse_registry(c.REGISTRY.read_text(), *c.read_config())
        target=routes['two-blackholed-flows']['target_port']
        c.REGISTRY.write_text(c.render_previous_retry(routes, deleted));self.reload_nginx();time.sleep(.2)
        remove=self.blackhole_first_upstream_connection(target,'TWO_OLD',2)
        old_data,old_seconds=self.tls_http_request(route['hostname']);remove()
        self.assertEqual(old_data,b'');self.assertGreater(old_seconds,3.5)
        c.REGISTRY.write_text(c.render(routes,deleted));self.reload_nginx();time.sleep(.2)
        self.blackhole_first_upstream_connection(target,'TWO_NEW',2)
        new_data,new_seconds=self.tls_http_request(route['hostname'])
        self.assertIn(b'200 OK',new_data);self.assertLess(new_seconds,3.5)
        print(json.dumps({'fault':'first_two_tcp_flows_blackholed','two_attempts_seconds':old_seconds,'six_attempts_seconds':new_seconds,'recovered':True}),flush=True)

    @unittest.skipUnless(os.environ.get('GATEWAY_TEST_IPTABLES'), 'Requires private iptables in an isolated network namespace')
    def test_five_consecutive_blackholed_flows_recover_inside_six_second_budget(self):
        route=self.put('five-blackholed-flows',self.backend(),'http')
        time.sleep(.2)  # Wait for this private NGINX's asynchronous SNI reload
        routes,_=c.parse_registry(c.REGISTRY.read_text(),*c.read_config())
        self.blackhole_first_upstream_connection(routes['five-blackholed-flows']['target_port'],'FIVE',5)
        data,seconds=self.tls_http_request(route['hostname'])
        self.assertIn(b'200 OK',data);self.assertGreater(seconds,4.5);self.assertLess(seconds,6.5)
        self.assertEqual(len(self.faults[-1]['source_ports']),5)
        print(json.dumps({'fault':'first_five_tcp_flows_blackholed','seconds':seconds,'recovered':True}),flush=True)

    @unittest.skipUnless(os.environ.get('GATEWAY_TEST_IPTABLES'), 'Requires private iptables in an isolated network namespace')
    def test_permanent_blackhole_stops_after_six_sockets_and_six_seconds(self):
        route=self.put('permanent-blackhole',self.backend(),'http')
        time.sleep(.2)  # The fault must affect the upstream, not SNI publication
        routes,_=c.parse_registry(c.REGISTRY.read_text(),*c.read_config());target=routes['permanent-blackhole']['target_port']
        command=[os.environ['GATEWAY_TEST_IPTABLES'],'-w','5','-t','mangle']
        rule=['-p','tcp','-d','127.0.0.1','--dport',str(target),'--syn','-j','DROP']
        subprocess.run(command+['-I','OUTPUT','1']+rule,check=True,capture_output=True)
        self.addCleanup(lambda:subprocess.run(command+['-D','OUTPUT']+rule,capture_output=True))
        seen=set();stopped=threading.Event()
        def observe():
            while not stopped.is_set():
                for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
                    fields=line.split()
                    if fields[2]==f'0100007F:{target:04X}' and fields[3]=='02':seen.add(fields[1])
                stopped.wait(.01)
        observer=threading.Thread(target=observe,daemon=True);observer.start()
        try:data,seconds=self.tls_http_request(route['hostname'])
        finally:stopped.set();observer.join(1)
        self.assertEqual(data,b'');self.assertEqual(len(seen),6);self.assertGreater(seconds,5.5);self.assertLess(seconds,7)
        print(json.dumps({'fault':'all_upstream_tcp_flows_blackholed','seconds':seconds,'unique_sockets':len(seen),'terminated':True}),flush=True)

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
