"""Real WAL/restore regression tests; no production PVC or host SQLite opens."""
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

import koth_storage as controller
import koth_storage_worker as worker
import install_koth_storage as installer

DEPLOY = Path(__file__).resolve().parent
LINUX = sys.platform == 'linux'
PY_WRITER = '''import json,sqlite3,sys
db=sqlite3.connect(sys.argv[1]);db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
for line in sys.stdin:
 try:
  db.executescript(json.loads(line));print('ok',flush=True)
 except Exception: print('failed',flush=True)
'''
NODE_WRITER = '''const {DatabaseSync}=require('node:sqlite'),r=require('node:readline');
const db=new DatabaseSync(process.argv[1]);db.exec('PRAGMA journal_mode=WAL;PRAGMA wal_autocheckpoint=0');
r.createInterface({input:process.stdin}).on('line',line=>{try{db.exec(JSON.parse(line));console.log('ok')}catch{console.log('failed')}});'''


@unittest.skipUnless(LINUX, 'WAL inode/fd tests require a Linux container namespace')
class RealWalTests(unittest.TestCase):
    def setUp(self):
        Path('/data').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='storage-test-', dir='/data')
        self.root, self.writers = Path(self.temp.name), []

    def tearDown(self):
        for p in self.writers:
            p.stdin.close()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
            p.stdout.close(); p.stderr.close()
        self.temp.cleanup()

    def fixture(self, game):
        request = {'format_version': 1, 'action': 'backup', 'game': game,
                   'operation_id': str(uuid.uuid4()), 'expected_pod_name': socket.gethostname(),
                   'data_root': '/data', 'store_specs': copy.deepcopy(controller.PROFILES[game]['stores'])}
        env = {**os.environ, 'PYTHONUNBUFFERED': '1', 'KUBERNETES_SERVICE_HOST': 'unit-test-pod-context', 'KOTH_MATCH_ID': 'fixture'}
        specs, paths, writers = [], [], []
        for index, spec in enumerate(request['store_specs']):
            # Keep production table/suffix contracts while using private fixture paths.
            spec['path_env'] = 'KOTH_STORAGE_TEST_PATH_' + str(index)
            spec['default_path'] = str(self.root / (game + '-' + spec['store_id'] + '.db'))
            spec['suffix'] = ''
            env[spec['path_env']] = spec['default_path']
            path = Path(spec['default_path'])
            db = sqlite3.connect(path)
            tables = {'business_rows', *spec['immutable_tables'], *spec['session_tables']}
            for table in sorted(tables):
                db.execute(f'CREATE TABLE "{table}"(id TEXT PRIMARY KEY,value BLOB)')
                db.execute(f'INSERT INTO "{table}" VALUES(?,?)', ('original', b'preserved'))
            if spec['auth_key_table']:
                db.execute(f'CREATE TABLE "{spec["auth_key_table"]}"(key_id TEXT PRIMARY KEY,retired_at REAL)')
                db.execute(f'INSERT INTO "{spec["auth_key_table"]}" VALUES(?,NULL)', ('old-key',))
            db.commit(); db.close()
            command = ['node', '-e', NODE_WRITER, str(path)] if game == 'swanopoly' else [sys.executable, '-u', '-c', PY_WRITER, str(path)]
            p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.writers.append(p); writers.append(p)
            self.sql(p, 'INSERT INTO business_rows VALUES(\'wal-only\',X\'010203\');')
            paths.append(path); specs.append(spec)
        return request, env, paths, writers

    def sql(self, process, sql):
        process.stdin.write(json.dumps(sql) + '\n'); process.stdin.flush()
        self.assertEqual(process.stdout.readline().strip(), 'ok')

    def call(self, request, env, action, payload=b'', ok=True):
        request = {**request, 'operation_id': str(uuid.uuid4()), 'action': action}
        node = request['game'] == 'swanopoly'
        command = ['node', str(DEPLOY / 'koth_storage_worker.cjs')] if node else [sys.executable, '-B', str(DEPLOY / 'koth_storage_worker.py')]
        p = subprocess.run([*command, json.dumps(request)], input=payload, capture_output=True, env=env, timeout=30)
        if ok: self.assertEqual(p.returncode, 0, p.stderr.decode(errors='replace'))
        else: self.assertNotEqual(p.returncode, 0)
        return p

    def frames(self, value):
        stream = io.BytesIO(value); header = json.loads(stream.readline())
        files = {}
        for item in header['stores']:
            data = stream.read(item['database_bytes'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), item['database_sha256'])
            files[item['store_id']] = data
        self.assertFalse(stream.read(1))
        return header, files

    def test_all_six_wal_backup_verify_restore_keep_current_keys_and_scores(self):
        for game in controller.PROFILES:
            with self.subTest(game=game):
                request, env, paths, writers = self.fixture(game)
                inodes = [Path(str(p) + '-wal').stat().st_ino for p in paths]
                old = self.call(request, env, 'backup').stdout
                header, files = self.frames(old)
                for item in header['stores']:
                    self.assertEqual(item['table_row_counts']['business_rows'], 2)
                for spec, p in zip(request['store_specs'], writers):
                    self.sql(p, 'INSERT INTO business_rows VALUES(\'new-row\',X\'04\');')
                    if spec['auth_key_table']:
                        self.sql(p, f'UPDATE "{spec["auth_key_table"]}" SET retired_at=123;INSERT INTO "{spec["auth_key_table"]}" VALUES(\'current-key\',NULL);')
                authority = self.call(request, env, 'backup').stdout
                active, _ = self.frames(authority)
                self.call(request, env, 'verify', old)
                inspected = json.loads(self.call(request, env, 'inspect').stdout)
                self.assertEqual(inspected['deleted_sqlite_handle_count'], 0)
                self.assertEqual(inodes, [Path(str(p) + '-wal').stat().st_ino for p in paths])
                # A second backup must still observe the persistent writer's latest WAL rows.
                self.assertTrue(all(i['table_row_counts']['business_rows'] == 3 for i in active['stores']))
                target_request, target_env = copy.deepcopy(request), dict(env)
                for spec in target_request['store_specs']:
                    target_env[spec['path_env']] = str(self.root / (game + '-restored-' + spec['store_id'] + '.db'))
                restored = json.loads(self.call(target_request, target_env, 'restore', old + authority).stdout)
                self.assertEqual(restored['restored_session_row_count'], 0)
                for index, item in enumerate(restored['stores']):
                    self.assertEqual(item['business_sha256'], header['stores'][index]['business_sha256'])
                    self.assertEqual(item['auth_history_sha256'], active['stores'][index]['auth_history_sha256'])
                    for table in request['store_specs'][index]['session_tables']:
                        self.assertEqual(item['table_row_counts'][table], 0)
                failed = self.call(target_request, target_env, 'restore', old + authority, ok=False)
                self.assertIn(b'RESTORE_TARGET_NOT_EMPTY', failed.stderr)
                self.assertFalse(list(Path('/data/.msgctf-storage').iterdir()))

    def test_deleted_wal_detected_before_engine_open_python_and_node(self):
        for game in ['card-battle-arena', 'swanopoly']:
            with self.subTest(game=game):
                request, env, paths, _ = self.fixture(game)
                Path(str(paths[0]) + '-wal').unlink()  # Deliberately damaged disposable fixture only.
                result = self.call(request, env, 'backup', ok=False)
                self.assertIn(b'LIVE_SQLITE_HANDLE_DELETED', result.stderr)
                self.assertFalse(Path(str(paths[0]) + '-wal').exists())

    def test_context_path_hash_truncation_wrong_game_and_trailing_bytes_rejected(self):
        for game in ['jenga', 'swanopoly']:
            request, env, paths, _ = self.fixture(game)
            frame = self.call(request, env, 'backup').stdout
            for data in [frame[:-1], frame + b'x', frame[:-1] + bytes([frame[-1] ^ 1]), frame.replace(game.encode(), b'wrong-game', 1)]:
                self.call(request, env, 'verify', data, ok=False)
            self.call({**request, 'expected_pod_name': 'wrong-pod'}, env, 'inspect', ok=False)
            no_pod = dict(env); no_pod.pop('KUBERNETES_SERVICE_HOST')
            self.call(request, no_pod, 'inspect', ok=False)
            escaped = dict(env); escaped[request['store_specs'][0]['path_env']] = '/etc/passwd'
            self.call(request, escaped, 'inspect', ok=False)
            linked = self.root / ('symlink-' + game); linked.symlink_to(paths[0])
            escaped[request['store_specs'][0]['path_env']] = str(linked)
            self.call(request, escaped, 'inspect', ok=False)
            self.call(request, env, 'restore', frame + frame, ok=False)

    def test_mutated_original_score_row_is_not_a_false_pass(self):
        for game in ['jenga', 'swanopoly']:
            request, env, paths, writers = self.fixture(game)
            frame = self.call(request, env, 'backup').stdout
            table = request['store_specs'][0]['immutable_tables'][0]
            self.sql(writers[0], f'UPDATE "{table}" SET value=X\'ff\';')
            result = self.call(request, env, 'verify', frame, ok=False)
            self.assertIn(b'ORIGINAL_ROWS_CHANGED', result.stderr)

    def test_schema_change_and_missing_authority_do_not_create_target(self):
        request, env, paths, writers = self.fixture('jenga')
        old = self.call(request, env, 'backup').stdout
        self.sql(writers[0], 'CREATE TABLE new_schema(id TEXT);')
        current = self.call(request, env, 'backup').stdout
        env[request['store_specs'][0]['path_env']] = str(self.root / 'target.db')
        result = self.call(request, env, 'restore', old + current, ok=False)
        self.assertIn(b'DATABASE_SCHEMA_CHANGED', result.stderr)
        self.assertFalse((self.root / 'target.db').exists())

    def test_large_unbuffered_python_and_node_export_contains_every_byte(self):
        for game in ('jenga', 'swanopoly'):
            request, env, paths, writers = self.fixture(game)
            self.sql(writers[0], "INSERT INTO business_rows VALUES('large',zeroblob(8*1024*1024));")
            frame = self.call(request, env, 'backup').stdout
            header, files = self.frames(frame)
            self.assertGreater(header['stores'][0]['database_bytes'], 8*1024*1024)
            self.call(request, env, 'verify', frame)

    def test_interrupted_scratch_cleanup_is_scoped(self):
        for game in ('jenga', 'swanopoly'):
            request, env, _, _ = self.fixture(game)
            operation = str(uuid.uuid4())
            request['operation_id'] = operation
            folder = Path('/data/.msgctf-storage') / (operation + '-backup')
            folder.parent.mkdir(mode=0o700, exist_ok=True); folder.mkdir(mode=0o700)
            (folder / 'backup-game.sqlite').write_bytes(b'interrupted')
            command = ['node', str(DEPLOY / 'koth_storage_worker.cjs')] if game == 'swanopoly' else [sys.executable, str(DEPLOY / 'koth_storage_worker.py')]
            p = subprocess.run([*command, json.dumps({**request, 'action': 'cleanup'})], env=env, capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(folder.exists())


class ControllerPolicyTests(unittest.TestCase):
    def test_partial_raw_writes_preserve_header_and_payload_and_zero_write_fails(self):
        class ShortWriter(io.BytesIO):
            def write(self, value): return super().write(value[:31])
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'snapshot'; path.write_bytes(bytes(range(256))*1024)
            stream = ShortWriter(); header = {'format_version': 1, 'database_bytes': path.stat().st_size}
            worker.write_bundle(stream, header, [path])
            self.assertEqual(stream.getvalue(), worker.canonical(header)+b'\n'+path.read_bytes())
        class Blocked:
            def write(self, value): return 0
        with self.assertRaisesRegex(worker.StorageError, 'OUTPUT_WRITE_INCOMPLETE'):
            worker.write_all(Blocked(), b'payload')

    def test_host_controller_and_installer_never_import_sqlite(self):
        for name in ('koth_storage.py', 'install_koth_storage.py'):
            tree = ast.parse((DEPLOY / name).read_text())
            imports = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
            imports += [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
            self.assertFalse(any('sqlite' in (n or '') for n in imports))
        self.assertEqual(len(controller.PROFILES), 6)

    def test_postgres_exec_pins_exact_pod_and_rejects_uid_replacement(self):
        kube = controller.Kube('k3s')
        kube.postgres_source = {'pod_name': 'postgres-pinned', 'pod_uid': 'expected'}
        kube.json = lambda args, **kw: {'metadata': {'uid': 'expected'}}
        args = ['exec', '-i', '-n', controller.PG_NAMESPACE, 'deployment/postgres', '-c', 'postgres', '--', 'pg_dump']
        with patch.object(controller.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'dump', b'')) as run:
            self.assertEqual(kube.run(args), b'dump')
            self.assertEqual(run.call_args.args[0][6], 'postgres-pinned')
        kube.json = lambda args, **kw: {'metadata': {'uid': 'replacement'}}
        with patch.object(controller.subprocess, 'run') as run:
            with self.assertRaisesRegex(controller.StorageError, 'POSTGRES_SOURCE_POD_CHANGED'): kube.run(args)
            run.assert_not_called()

    @unittest.skipUnless(LINUX, 'private Unix state')
    def test_archive_integrity_private_permissions_and_no_sqlite_engine(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / 'archive'; content = b'x' * 512
            header = {'format_version': 1, 'game': 'jenga', 'stores': [{'store_id': 'game', 'engine': 'sqlite', 'database_bytes': 512, 'database_sha256': hashlib.sha256(content).hexdigest()}]}
            p.write_bytes(controller.canonical(header) + b'\n' + content); p.chmod(0o600)
            controller.read_archive(p, 'jenga', expected_hash=controller.sha256(p))
            with self.assertRaises(controller.StorageError): controller.read_archive(p, 'jenga', expected_hash='0' * 64)
            p.chmod(0o644)
            with self.assertRaises(controller.StorageError): controller.read_archive(p, 'jenga')

    @unittest.skipUnless(LINUX, 'private Unix state')
    def test_installer_is_idempotent_persistent_and_rejects_changed_release_or_scope(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result = installer.install(DEPLOY, 'a' * 40, 'jenga', prefix=root)
            self.assertEqual(result, installer.install(DEPLOY, 'a' * 40, 'jenga', prefix=root))
            self.assertEqual((root / 'etc/msgctf-koth-storage/config.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / 'usr/local/lib/msgctf-koth-storage/current').resolve().name, 'a' * 40)
            with self.assertRaises(ValueError): installer.install(DEPLOY, 'a' * 40, 'swanopoly', prefix=root)
            target = root / ('usr/local/lib/msgctf-koth-storage/' + 'a' * 40) / 'koth_storage.py'
            target.write_text('modified')
            with self.assertRaises(ValueError): installer.install(DEPLOY, 'a' * 40, 'jenga', prefix=root)

    @unittest.skipUnless(LINUX, 'flock')
    def test_lock_blocks_concurrent_operation_and_releases_after_failure(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with controller.operation_lock(root, 'jenga'):
                with self.assertRaisesRegex(controller.StorageError, 'BUSY'):
                    with controller.operation_lock(root, 'jenga'): pass
            with controller.operation_lock(root, 'jenga'): pass

    @unittest.skipUnless(LINUX, 'private Unix state')
    def test_pod_uid_race_aborts_before_worker_and_namespace_cleanup_checks_uid(self):
        class Kube:
            def json(self, args, **kwargs): return {'metadata': {'uid': 'new', 'labels': {}}}
            def run(self, *a, **kw): raise AssertionError('must not execute or delete')
        with tempfile.TemporaryDirectory() as name:
            storage = controller.Storage('jenga', str(uuid.uuid4()), 'test', root=name, kube=Kube())
            with self.assertRaisesRegex(controller.StorageError, 'SOURCE_POD_CHANGED'):
                storage.execute({'pod_name': 'pod', 'pod_uid': 'old', 'namespace': 'koth-jenga'}, 'inspect')
            kube = controller.Kube(); kube.json = Kube().json; kube.run = Kube().run
            with self.assertRaisesRegex(controller.StorageError, 'CLEANUP_SCOPE_CHANGED'):
                kube.delete_owned_namespace('msgctf-storage-' + uuid.UUID(storage.operation_id).hex, 'old', storage.operation_id)

    @unittest.skipUnless(LINUX, 'private Unix state')
    def test_restore_isolated_manifest_and_failure_cleanup_never_mount_source(self):
        for fail in (False, True):
            with self.subTest(failure=fail), tempfile.TemporaryDirectory() as name:
                operation = str(uuid.uuid4()); root = Path(name)
                source = {'pod_name': 'source', 'pod_uid': 'original-pod', 'namespace': 'koth-jenga', 'node_name': 'node',
                          'container_image': 'ghcr.io/msg-ctf/jenga@sha256:' + 'a' * 64, 'pvc_uid': 'original-volume', 'runtime_class': 'gvisor'}
                class Kube:
                    def __init__(self): self.objects, self.deleted = [], []
                    def apply(self, obj):
                        self.objects.append(obj)
                        return {**obj, 'metadata': {**obj['metadata'], 'uid': 'fresh-' + obj['kind']}}
                    def json(self, args):
                        if args[1] == 'node': return {'metadata': {'labels': {'kubernetes.io/hostname': 'node'}}}
                        if args[1] == 'pvc': return {'metadata': {'uid': 'fresh-volume'}}
                        raise AssertionError(args)
                    def run(self, *a, **kw): pass
                    def delete_owned_namespace(self, *args): self.deleted.append(args)
                kube = Kube(); storage = controller.Storage('jenga', operation, 'test', root=root, kube=kube)
                item = {'store_id': 'game', 'engine': 'sqlite', 'database_path': '/data/jenga.db', 'auth_history_sha256': 'current'}
                header = {'source': source, 'stores': [item], 'game': 'jenga'}
                def execute(target, action, **kwargs):
                    if action == 'restore':
                        if fail: raise controller.StorageError('INJECTED_RESTORE_FAILURE')
                        return {'stores': [item], 'restored_session_row_count': 0}
                    return {'stores': [item]}
                with patch.object(controller, 'read_archive', return_value=(header, {})), \
                     patch.object(controller, 'discover', return_value=source), \
                     patch.object(controller, 'sqlite_payload'), \
                     patch.object(storage, 'backup', return_value={'archive_path': 'closed', 'archive_sha256': 'hash'}), \
                     patch.object(storage, 'execute', side_effect=execute):
                    if fail:
                        with self.assertRaisesRegex(controller.StorageError, 'INJECTED'): storage.restore('closed', 'hash')
                    else: self.assertTrue(storage.restore('closed', 'hash')['source_pvc_untouched'])
                self.assertEqual(len(kube.deleted), 1)
                pod = next(o for o in kube.objects if o['kind'] == 'Pod')
                self.assertFalse(pod['spec']['automountServiceAccountToken'])
                self.assertEqual(pod['spec']['volumes'][0]['persistentVolumeClaim']['claimName'], 'restore-data')
                self.assertFalse(any(o['kind'] == 'Service' for o in kube.objects))
                network = next(o for o in kube.objects if o['kind'] == 'NetworkPolicy')
                self.assertEqual(network['spec']['egress'], [])
                self.assertTrue(json.loads(storage.journal.read_text())['restore_namespace_removed'])


@unittest.skipUnless(os.environ.get('KOTH_STORAGE_PG_CONTAINER'), 'real PostgreSQL container not configured')
class RealPostgresTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.original_name = controller.PG_DATABASE
        controller.PG_DATABASE = 'storage_test_' + uuid.uuid4().hex
        container = os.environ['KOTH_STORAGE_PG_CONTAINER']
        class Kube:
            def run(self, args, *, data=None, input_file=None, output_file=None, timeout=90):
                command = ['docker', 'exec', '-i', container, *args[args.index('--') + 1:]]
                p = subprocess.run(command, input=data, stdin=input_file, stdout=output_file or subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
                if p.returncode: raise controller.StorageError('POSTGRES_TEST_COMMAND_FAILED: ' + p.stderr.decode()[:200])
                return p.stdout
        self.kube = Kube()
        self.raw(['sh', '-c', 'exec createdb -U "$POSTGRES_USER" "$1"', 'sh', controller.PG_DATABASE])
        controller.pg_command(self.kube, 'sql', data=b'''CREATE TABLE period_results(period_id text PRIMARY KEY,score integer);
CREATE TABLE submissions(id text PRIMARY KEY,verdict text,value text);
CREATE TABLE sessions(id text PRIMARY KEY);
CREATE TABLE dependency_hell_snapshot_hmac_keys(key_id text PRIMARY KEY,key_bytes bytea,active boolean);
CREATE TABLE dependency_hell_submission_transition_hmac_keys(key_id text PRIMARY KEY,key_bytes bytea,active boolean);
INSERT INTO period_results VALUES('sealed',42);INSERT INTO submissions VALUES('original','PASS','kept');INSERT INTO sessions VALUES('old-session');
INSERT INTO dependency_hell_snapshot_hmac_keys VALUES('old',decode(repeat('ab',32),'hex'),true);
INSERT INTO dependency_hell_submission_transition_hmac_keys SELECT * FROM dependency_hell_snapshot_hmac_keys;''')

    def raw(self, command):
        return self.kube.run(['exec', '--', *command])

    def tearDown(self):
        try:
            remaining = controller.pg_command(self.kube, 'sql', data=b"SELECT datname FROM pg_database WHERE datname LIKE 'msgctf_%';")
            self.assertEqual(remaining.strip(), b'', remaining)
        finally:
            self.raw(['sh', '-c', 'exec dropdb --force -U "$POSTGRES_USER" "$1"', 'sh', controller.PG_DATABASE])
            controller.PG_DATABASE = self.original_name; self.temp.cleanup()

    def backup(self, label):
        folder = self.root / label; folder.mkdir()
        return controller.postgres_backup(self.kube, folder, str(uuid.uuid4()))

    def test_real_dump_restore_preserves_scores_current_keys_clears_sessions_and_removes_clones(self):
        old_file, old = self.backup('old')
        controller.pg_command(self.kube, 'sql', data=b'''UPDATE dependency_hell_snapshot_hmac_keys SET active=false;
INSERT INTO dependency_hell_snapshot_hmac_keys VALUES('current',decode(repeat('cd',32),'hex'),true);
UPDATE dependency_hell_submission_transition_hmac_keys SET active=false;
INSERT INTO dependency_hell_submission_transition_hmac_keys VALUES('current',decode(repeat('ef',32),'hex'),true);
INSERT INTO submissions VALUES('new','PASS','newer');''')
        current_file, active = self.backup('current')
        before = controller.pg_metadata(self.kube, controller.PG_DATABASE)
        header, authority = {'stores': [old]}, {'stores': [active]}
        ranges, active_ranges = {'postgres': (0, old_file.stat().st_size)}, {'postgres': (0, current_file.stat().st_size)}
        verified = controller.postgres_verify(self.kube, old_file, header, ranges, self.root, str(uuid.uuid4()))
        self.assertEqual(verified['missing_or_changed_row_count'], 0)
        result = controller.postgres_restore_check(self.kube, old_file, header, ranges, current_file, authority, active_ranges, self.root, str(uuid.uuid4()))
        self.assertTrue(result['current_auth_history_preserved'])
        self.assertEqual(result['restored_session_row_count'], 0)
        self.assertEqual(controller.pg_metadata(self.kube, controller.PG_DATABASE), before)
        controller.pg_command(self.kube, 'sql', data=b"UPDATE period_results SET score=999;")
        with self.assertRaisesRegex(controller.StorageError, 'ORIGINAL_ROWS_CHANGED'):
            controller.postgres_verify(self.kube, old_file, header, ranges, self.root, str(uuid.uuid4()))

    def test_failed_restore_removes_temporary_database_and_live_restore_is_forbidden(self):
        broken = self.root / 'broken'; broken.write_bytes(b'not a pg_dump')
        with self.assertRaises(controller.StorageError):
            with controller.postgres_clone(self.kube, broken, str(uuid.uuid4()), 'restore'): pass
        with self.assertRaisesRegex(controller.StorageError, 'LIVE_POSTGRES_RESTORE_FORBIDDEN'):
            controller.pg_command(self.kube, 'restore')

    def test_crashed_database_cleanup_checks_marker_and_owner(self):
        operation = str(uuid.uuid4()); name = 'msgctf_restore_' + uuid.UUID(operation).hex
        self.raw(['sh', '-c', 'exec createdb -U "$POSTGRES_USER" "$1"', 'sh', name])
        try:
            with self.assertRaisesRegex(controller.StorageError, 'CLEANUP_SCOPE_CHANGED'):
                controller.postgres_cleanup(self.kube, operation)
            controller.pg_command(self.kube, 'sql', data=(f'COMMENT ON DATABASE "{name}" IS \'msgctf-koth-storage:{operation}\';').encode())
            self.assertEqual(controller.postgres_cleanup(self.kube, operation), [name])
        finally:
            self.raw(['sh', '-c', 'exec dropdb --if-exists --force -U "$POSTGRES_USER" "$1"', 'sh', name])


if __name__ == '__main__': unittest.main()
