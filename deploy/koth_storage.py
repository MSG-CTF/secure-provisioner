#!/usr/bin/env python3
"""Pinned, Pod-only backup/verification and isolated restore for six KOTH games.

This module deliberately has no SQLite dependency or host database reader.
Only closed, root-private framed archives are read by the controller.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
try:
    import fcntl
except ImportError:  # Controller policy/format tests also run on Windows.
    fcntl = None

VERSION = 1
MAX_HEADER = 65536
MAX_STORE = 512 * 1024 * 1024
MAX_BUNDLE = 10 * 1024 ** 3
MAX_ARTIFACT_PACK = 8 * 1024 ** 3
MAX_ARTIFACT_RAW = 16 * 1024 ** 3
FILE_GAMES = {'grand-tour-duel', 'dependency-hell'}
ROOT = Path('/var/lib/msgctf-koth-storage')
IDENTIFIER = re.compile(r'[a-z_][a-z0-9_]*\Z')


def store(store_id, env, default, suffix='', auth=None, sessions=(), immutable=()):
    return {'store_id': store_id, 'path_env': env, 'default_path': default, 'suffix': suffix,
            'auth_key_table': auth, 'session_tables': list(sessions), 'immutable_tables': list(immutable)}


def profile(game, container='service', root='/data', stores=()):
    return {'namespace': 'koth-' + game, 'deployment': 'game', 'container': container,
            'data_root': root, 'stores': list(stores), 'language': 'python'}


PROFILES = {
    'jenga': profile('jenga', 'jenga', stores=[store('game', 'JENGA_DB', '/data/jenga.db', auth='jenga_auth_keys',
        sessions=['jenga_auth_sessions'], immutable=['jenga_ticks', 'jenga_periods', 'jenga_mutations'])]),
    'card-battle-arena': profile('card-battle-arena', stores=[
        store('game', 'DATABASE_PATH', '/data/arena.db', sessions=['sessions'], immutable=['rounds', 'holds', 'period_snapshots', 'period_results']),
        store('auth', 'DATABASE_PATH', '/data/arena.db', '.auth.sqlite3', 'session_keys', ['session_bindings'])]),
    'grand-tour-duel': profile('grand-tour-duel', root='/var/lib/koth', stores=[
        store('game', 'KOTH_DATABASE_PATH', '/var/lib/koth/state/duel.sqlite3', sessions=['sessions'], immutable=['score_period_results', 'replays']),
        store('auth', 'KOTH_DATABASE_PATH', '/var/lib/koth/state/duel.sqlite3', '.auth.sqlite3', 'session_keys', ['session_bindings'])]),
    'pixel-smuggler': profile('pixel-smuggler', stores=[
        store('game', 'DATABASE_PATH', '/data/pixel-smuggler.db', sessions=['sessions'], immutable=['rounds', 'mode_decks', 'best_submissions', 'score_snapshots']),
        store('auth', 'DATABASE_PATH', '/data/pixel-smuggler.db', '.auth.sqlite3', 'session_keys', ['session_bindings'])]),
    'swanopoly': {**profile('swanopoly', 'backend', stores=[store('game', 'STATE_DIR', '/data', '/${KOTH_MATCH_ID}/swan.db',
        'session_keys', ['sessions', 'session_bindings'], ['bot_codes', 'bot_submissions', 'bot_period_evaluations', 'period_results', 'period_team_scores'])]), 'language': 'node'},
    'dependency-hell': {'namespace': 'dependency-hell', 'deployment': 'backend', 'container': 'backend', 'data_root': '/data',
        'language': 'python', 'stores': [store('auth', 'DATA_DIR', '/data', '/session-bindings.sqlite3', 'session_keys', ['session_bindings'])]},
}
PG_NAMESPACE = 'dependency-hell-database'
PG_DEPLOYMENT = 'postgres'
PG_CONTAINER = 'postgres'
PG_DATABASE = 'dependency_hell'
PG_AUTH_TABLES = ('dependency_hell_snapshot_hmac_keys', 'dependency_hell_submission_transition_hmac_keys')


class StorageError(Exception):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def valid_uuid(value):
    try:
        valid = isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int
    except ValueError:
        valid = False
    if not valid:
        raise StorageError('INVALID_OPERATION_ID')
    return value


def private_file(path):
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise StorageError('PRIVATE_ARCHIVE_REQUIRED')
    return info


def read_archive(path, game, *, expected_hash=None, sqlite_only=False, artifact_only=False):
    info = private_file(path)
    if info.st_size > MAX_BUNDLE + MAX_HEADER or expected_hash and sha256(path) != expected_hash:
        raise StorageError('ARCHIVE_HASH_MISMATCH')
    with Path(path).open('rb') as stream:
        line = stream.readline(MAX_HEADER + 1)
        if len(line) > MAX_HEADER or not line.endswith(b'\n'):
            raise StorageError('INVALID_ARCHIVE')
        header = json.loads(line)
        if header.get('format_version') not in {1, 2} or header.get('game') != game:
            raise StorageError('INVALID_ARCHIVE')
        expected = [s['store_id'] for s in PROFILES[game]['stores']] + (['postgres'] if game == 'dependency-hell' and not sqlite_only else [])
        has_files = isinstance(header.get('stores'), list) and any(s.get('store_id') == 'artifacts' for s in header['stores'])
        if artifact_only:
            expected = ['artifacts']
        elif has_files:
            expected += ['artifacts']
        if has_files and game not in FILE_GAMES or header.get('format_version') == 2 and not has_files:
            raise StorageError('INVALID_ARCHIVE')
        if not isinstance(header.get('stores'), list) or [s.get('store_id') for s in header['stores']] != expected:
            raise StorageError('INVALID_ARCHIVE')
        ranges, total = {}, 0
        for item in header['stores']:
            size, digest = item.get('database_bytes'), item.get('database_sha256')
            is_files = item['store_id'] == 'artifacts'
            valid_size = type(size) is int and (1 <= size <= MAX_ARTIFACT_PACK if is_files else 512 <= size <= MAX_STORE)
            if not valid_size or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
                raise StorageError('INVALID_ARCHIVE')
            wanted_engine = 'file_bundle' if is_files else 'postgresql' if item['store_id'] == 'postgres' else 'sqlite'
            if item.get('engine') != wanted_engine:
                raise StorageError('INVALID_ARCHIVE')
            if is_files:
                roots = item.get('artifact_roots')
                keys = {'sources', 'replays'} if game == 'grand-tour-duel' else {'artifacts'}
                raw_size, count = item.get('uncompressed_bytes'), item.get('reference_count')
                if (not isinstance(roots, dict) or set(roots) != keys
                        or any(not isinstance(v, str) or not PurePosixPath(v).is_absolute() or PurePosixPath(v) == PurePosixPath(PROFILES[game]['data_root']) or not PurePosixPath(v).is_relative_to(PROFILES[game]['data_root']) or PurePosixPath(v).as_posix() != v or '..' in PurePosixPath(v).parts for v in roots.values())
                        or type(raw_size) is not int or not 0 <= raw_size <= MAX_ARTIFACT_RAW or type(count) is not int or not 0 <= count <= 100000
                        or item.get('compression') != 'zlib_per_file_v1' or not re.fullmatch(r'[a-f0-9]{64}', item.get('references_sha256', ''))):
                    raise StorageError('INVALID_ARTIFACT_METADATA')
            ranges[item['store_id']] = (stream.tell(), size)
            h, remaining = hashlib.sha256(), size
            while remaining:
                block = stream.read(min(remaining, 1024 * 1024))
                if not block:
                    raise StorageError('ARCHIVE_TRUNCATED')
                h.update(block); remaining -= len(block)
            if h.hexdigest() != digest:
                raise StorageError('ARCHIVE_HASH_MISMATCH')
            total += size
        if total > MAX_BUNDLE or stream.read(1):
            raise StorageError('INVALID_ARCHIVE')
    return header, ranges


def copy_range(source, output, offset, size):
    source.seek(offset)
    while size:
        block = source.read(min(size, 1024 * 1024))
        if not block:
            raise StorageError('ARCHIVE_TRUNCATED')
        output.write(block); size -= len(block)


def sqlite_payload(archive, output, header, ranges, *, include_artifacts=True):
    sqlite_stores = [s for s in header['stores'] if s['engine'] == 'sqlite' or include_artifacts and header['game'] == 'grand-tour-duel' and s['engine'] == 'file_bundle']
    output.write(canonical({'format_version': VERSION, 'game': header['game'], 'stores': sqlite_stores}) + b'\n')
    with Path(archive).open('rb') as source:
        for item in sqlite_stores:
            copy_range(source, output, *ranges[item['store_id']])


def artifact_payload(archive, output, header, ranges):
    items = [s for s in header['stores'] if s['engine'] == 'file_bundle']
    if len(items) != 1:
        raise StorageError('COMPLETE_ARTIFACT_BACKUP_REQUIRED')
    output.write(canonical({'format_version': VERSION, 'game': header['game'], 'stores': items}) + b'\n')
    with Path(archive).open('rb') as source:
        copy_range(source, output, *ranges['artifacts'])


def require_artifacts(header):
    if header['game'] in FILE_GAMES and not any(s['engine'] == 'file_bundle' for s in header['stores']):
        raise StorageError('COMPLETE_ARTIFACT_BACKUP_REQUIRED')


def restore_capacity(header):
    raw = sum(s.get('uncompressed_bytes', s['database_bytes']) for s in header['stores'])
    packed = sum(s['database_bytes'] for s in header['stores'])
    needed = raw + packed + 512 * 1024 ** 2
    size = 2
    while size * 1024 ** 3 < needed:
        size *= 2
    if size > 32:
        raise StorageError('RESTORE_CAPACITY_LIMIT')
    return str(size) + 'Gi'


class Kube:
    def __init__(self, binary=None):
        self.prefix = [binary or shutil.which('k3s') or '/usr/local/bin/k3s', 'kubectl']
        self.postgres_source = None

    def pin_postgres(self):
        if self.postgres_source is None:
            deployment = self.json(['get', 'deployment', PG_DEPLOYMENT, '-n', PG_NAMESPACE])
            sets = self.json(['get', 'replicasets', '-n', PG_NAMESPACE])['items']
            owners = {s['metadata']['uid'] for s in sets if any(r.get('controller') and r['uid'] == deployment['metadata']['uid'] for r in s['metadata'].get('ownerReferences', []))}
            pods = [p for p in self.json(['get', 'pods', '-n', PG_NAMESPACE])['items']
                    if p['status'].get('phase') == 'Running' and not p['metadata'].get('deletionTimestamp')
                    and any(r.get('controller') and r['uid'] in owners for r in p['metadata'].get('ownerReferences', []))
                    and p['status'].get('containerStatuses') and all(s.get('ready') for s in p['status']['containerStatuses'])]
            if len(pods) != 1 or deployment['status'].get('readyReplicas') != 1:
                raise StorageError('POSTGRES_SOURCE_NOT_READY')
            pod = pods[0]
            self.postgres_source = {'pod_name': pod['metadata']['name'], 'pod_uid': pod['metadata']['uid']}
        current = self.json(['get', 'pod', self.postgres_source['pod_name'], '-n', PG_NAMESPACE])
        if current['metadata']['uid'] != self.postgres_source['pod_uid']:
            raise StorageError('POSTGRES_SOURCE_POD_CHANGED')
        return self.postgres_source

    def run(self, args, *, data=None, input_file=None, output_file=None, timeout=90):
        pinned = args[:7] == ['exec', '-i', '-n', PG_NAMESPACE, 'deployment/' + PG_DEPLOYMENT, '-c', PG_CONTAINER]
        if pinned:
            source = self.pin_postgres()
            args = [*args[:4], source['pod_name'], *args[5:]]
        result = subprocess.run(self.prefix + args, input=data, stdin=input_file,
                                stdout=output_file if output_file is not None else subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
        if result.returncode:
            raise StorageError('KUBERNETES_OPERATION_FAILED')
        if pinned: self.pin_postgres()
        return result.stdout

    def json(self, args, *, optional=False):
        result = self.run(args + (['--ignore-not-found'] if optional else []) + ['-o', 'json'])
        return json.loads(result) if result else None

    def apply(self, value):
        return json.loads(self.run(['create', '-f', '-', '-o', 'json'], data=canonical(value)))

    def delete_owned_namespace(self, name, uid, operation_id):
        ns = self.json(['get', 'namespace', name], optional=True)
        if ns is None:
            return
        if (name != 'msgctf-storage-' + uuid.UUID(operation_id).hex or ns['metadata']['uid'] != uid
                or ns['metadata'].get('labels', {}).get('msgctf.io/storage-operation') != operation_id):
            raise StorageError('CLEANUP_SCOPE_CHANGED')
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}, 'propagationPolicy': 'Foreground'}
        self.run(['delete', '--raw', '/api/v1/namespaces/' + name, '-f', '-'], data=canonical(options))
        deadline = time.monotonic() + 80
        while time.monotonic() < deadline:
            current = self.json(['get', 'namespace', name], optional=True)
            if current is None:
                return
            if current['metadata']['uid'] != uid:
                raise StorageError('CLEANUP_SCOPE_CHANGED')
            time.sleep(1)
        raise StorageError('CLEANUP_PENDING')


def discover(kube, game):
    fixed = PROFILES[game]
    deployment = kube.json(['get', 'deployment', fixed['deployment'], '-n', fixed['namespace']])
    sets = kube.json(['get', 'replicasets', '-n', fixed['namespace']])['items']
    owners = {item['metadata']['uid'] for item in sets if any(r.get('controller') and r['uid'] == deployment['metadata']['uid'] for r in item['metadata'].get('ownerReferences', []))}
    pods = [p for p in kube.json(['get', 'pods', '-n', fixed['namespace']])['items']
            if p['status'].get('phase') == 'Running' and not p['metadata'].get('deletionTimestamp')
            and any(r.get('controller') and r['uid'] in owners for r in p['metadata'].get('ownerReferences', []))
            and all(s.get('ready') for s in p['status'].get('containerStatuses', []))]
    if not pods or deployment['status'].get('readyReplicas') != deployment['spec'].get('replicas', 1):
        raise StorageError('SOURCE_NOT_READY')
    pod = sorted(pods, key=lambda p: p['metadata']['name'])[0]
    container = next(c for c in pod['spec']['containers'] if c['name'] == fixed['container'])
    if not re.fullmatch(r'ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}', container['image']):
        raise StorageError('PINNED_IMAGE_REQUIRED')
    status = next(s for s in pod['status']['containerStatuses'] if s['name'] == fixed['container'])
    if status['imageID'] != container['image']:
        raise StorageError('SOURCE_IMAGE_CHANGED')
    mount = next((m for m in container.get('volumeMounts', []) if m['mountPath'] == fixed['data_root']), None)
    if not mount or mount.get('subPath'):
        raise StorageError('DIRECT_PVC_MOUNT_REQUIRED')
    volume = next(v for v in pod['spec']['volumes'] if v['name'] == mount['name'])
    claim = volume.get('persistentVolumeClaim', {}).get('claimName')
    if not claim:
        raise StorageError('DIRECT_PVC_MOUNT_REQUIRED')
    pvc = kube.json(['get', 'pvc', claim, '-n', fixed['namespace']])
    return {'namespace': fixed['namespace'], 'pod_name': pod['metadata']['name'], 'pod_uid': pod['metadata']['uid'],
            'node_name': pod['spec']['nodeName'], 'runtime_class': pod['spec'].get('runtimeClassName'),
            'container': fixed['container'], 'container_image': container['image'], 'pvc_name': claim, 'pvc_uid': pvc['metadata']['uid'],
            'replica_count': deployment['spec'].get('replicas', 1)}


def worker_command(game, request, directory=None):
    directory = Path(directory).resolve() if directory else Path(__file__).resolve().parent
    if PROFILES[game]['language'] == 'node':
        source = (directory / 'koth_storage_worker.cjs').read_text(encoding='utf-8')
        source += '\nrun(JSON.parse(process.argv[1])).catch(e=>{console.error(JSON.stringify({error_code:e.storageCode||"STORAGE_WORKER_FAILED"}));process.exitCode=1;});'
        return ['node', '-e', source, canonical(request).decode()]
    helper = (directory / 'koth_storage_artifacts.py').read_text(encoding='utf-8')
    bootstrap = 'import sys,types\na=types.ModuleType("koth_storage_artifacts")\nexec(' + repr(helper) + ',a.__dict__)\nsys.modules[a.__name__]=a\n'
    return ['python', '-B', '-c', bootstrap + (directory / 'koth_storage_worker.py').read_text(encoding='utf-8').replace('from __future__ import annotations', ''), canonical(request).decode()]


class Storage:
    def __init__(self, game, operation_id, actor, *, root=ROOT, kube=None):
        self.game, self.operation_id, self.actor = game, valid_uuid(operation_id), actor
        if game not in PROFILES or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,50}', actor):
            raise StorageError('INVALID_REQUEST')
        self.root, self.kube = Path(root), kube or Kube()
        for directory in [self.root, self.root / 'archives', self.root / 'journals']:
            if directory.is_symlink():
                raise StorageError('STATE_DIRECTORY_UNSAFE')
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if directory.stat().st_uid != os.geteuid() or directory.stat().st_mode & 0o077:
                raise StorageError('STATE_DIRECTORY_UNSAFE')
        self.journal = self.root / 'journals' / (operation_id + '.json')
        self.source_override = None

    def source(self):
        # Recovery controllers use an isolated maintenance Pod only after all
        # application writers have terminated. Normal operations still discover.
        return self.source_override or discover(self.kube, self.game)

    def save(self, value):
        entry = {'format_version': VERSION, 'game': self.game, 'operation_id': self.operation_id, 'actor': self.actor,
                 'recorded_at': datetime.now(timezone.utc).isoformat(), **value}
        fd, name = tempfile.mkstemp(prefix=self.operation_id + '-', suffix='.new', dir=self.journal.parent)
        target = Path(name)
        try:
            with os.fdopen(fd, 'wb') as file:
                file.write(canonical(entry)); file.flush(); os.fsync(file.fileno())
            os.replace(target, self.journal)
            with os.fdopen(os.open(self.journal.with_suffix('.jsonl'), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'ab') as events:
                events.write(canonical(entry) + b'\n'); events.flush(); os.fsync(events.fileno())
        finally:
            target.unlink(missing_ok=True)
        return entry

    def request(self, source, action, *, operation_id=None, include_artifacts=True):
        result = {'format_version': VERSION, 'action': action, 'game': self.game,
                'operation_id': operation_id or self.operation_id, 'expected_pod_name': source['pod_name'],
                'data_root': PROFILES[self.game]['data_root'], 'store_specs': copy.deepcopy(PROFILES[self.game]['stores'])}
        if self.game == 'grand-tour-duel':
            result['artifact_bundle'] = include_artifacts and action in {'backup', 'verify', 'restore', 'rebase'}
        return result

    def execute(self, source, action, *, input_file=None, output_file=None, operation_id=None, include_artifacts=True):
        before = self.kube.json(['get', 'pod', source['pod_name'], '-n', source['namespace']])
        if before['metadata']['uid'] != source['pod_uid']:
            raise StorageError('SOURCE_POD_CHANGED')
        result = self.kube.run(['exec', '-i', '-n', source['namespace'], source['pod_name'], '-c', source['container'], '--',
                               *worker_command(self.game, self.request(source, action, operation_id=operation_id, include_artifacts=include_artifacts))],
                              input_file=input_file, output_file=output_file, timeout=1200 if self.game in FILE_GAMES else 140)
        after = self.kube.json(['get', 'pod', source['pod_name'], '-n', source['namespace']])
        if after['metadata']['uid'] != source['pod_uid']:
            raise StorageError('SOURCE_POD_CHANGED')
        return json.loads(result) if output_file is None else None

    def execute_artifacts(self, source, action, references, *, archive=None, header=None, ranges=None, output_file=None):
        line = canonical({'references': references}) + b'\n'
        if len(line) > 32 * 1024 ** 2:
            raise StorageError('ARTIFACT_REFERENCE_LIMIT')
        with tempfile.TemporaryFile(dir=self.root) as payload:
            payload.write(line)
            if archive:
                artifact_payload(archive, payload, header, ranges)
            payload.seek(0)
            return self.execute(source, action, input_file=payload, output_file=output_file)

    def inspect(self):
        source = self.source()
        result = self.execute(source, 'inspect')
        return {'source': source, **result}

    def backup(self, *, operation_id=None, include_artifacts=True):
        operation = operation_id or self.operation_id
        archive = self.root / 'archives' / (self.game + '-' + operation + '.msgkoth')
        if archive.exists():
            header, _ = read_archive(archive, self.game)
            if include_artifacts:
                require_artifacts(header)
            return {'archive_path': str(archive), 'archive_sha256': sha256(archive), 'source': header['source'], 'stores': header['stores']}
        source = self.source()
        with tempfile.TemporaryDirectory(prefix='backup-', dir=self.root) as folder:
            private = Path(folder) / 'sqlite.frame'
            with private.open('xb') as output:
                os.chmod(private, 0o600)
                self.execute(source, 'backup', output_file=output, operation_id=operation, include_artifacts=include_artifacts)
                output.flush(); os.fsync(output.fileno())
            # The SQLite-only frame is parsed without importing an engine.
            if self.game == 'dependency-hell':
                sqlite_header, sqlite_ranges = read_archive(private, self.game, sqlite_only=True)
                pg_file, pg_meta = postgres_backup(self.kube, Path(folder), operation, include_references=include_artifacts)
                references = pg_meta.pop('_artifact_references', [])
                stores = sqlite_header['stores'] + [pg_meta]
                if include_artifacts:
                    artifact_file = Path(folder) / 'artifacts.frame'
                    with artifact_file.open('xb') as output:
                        os.chmod(artifact_file, 0o600)
                        self.execute_artifacts(source, 'artifact_backup', references, output_file=output)
                        output.flush(); os.fsync(output.fileno())
                    artifact_header, artifact_ranges = read_archive(artifact_file, self.game, artifact_only=True)
                    if artifact_header['stores'][0].get('database_references_sha256') != pg_meta['artifact_database_references_sha256']:
                        raise StorageError('ARTIFACT_DATABASE_REFERENCES_MISMATCH')
                    stores += artifact_header['stores']
            else:
                sqlite_header, sqlite_ranges = read_archive(private, self.game)
                stores = sqlite_header['stores']
            temporary = archive.with_suffix('.partial')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, 'wb') as output, private.open('rb') as stream:
                    output.write(canonical({'format_version': 2 if any(s['engine']=='file_bundle' for s in stores) else VERSION, 'game': self.game, 'source': source, 'stores': stores, 'scope': 'databases_and_referenced_files' if include_artifacts and self.game in FILE_GAMES else 'databases_only'}) + b'\n')
                    for item in sqlite_header['stores']:
                        copy_range(stream, output, *sqlite_ranges[item['store_id']])
                    if self.game == 'dependency-hell':
                        with pg_file.open('rb') as pg: shutil.copyfileobj(pg, output)
                        if include_artifacts:
                            with artifact_file.open('rb') as files: copy_range(files, output, *artifact_ranges['artifacts'])
                    output.flush(); os.fsync(output.fileno())
                read_archive(temporary, self.game)
                if include_artifacts:
                    require_artifacts({'game': self.game, 'stores': stores})
                os.chmod(temporary, 0o400); os.replace(temporary, archive)
            finally:
                temporary.unlink(missing_ok=True)
        return {'archive_path': str(archive), 'archive_sha256': sha256(archive), 'source': source, 'stores': stores}

    def verify(self, archive, expected_hash):
        header, ranges = read_archive(archive, self.game, expected_hash=expected_hash)
        require_artifacts(header)
        source = self.source()
        if header['source']['pvc_uid'] != source['pvc_uid']:
            raise StorageError('SOURCE_VOLUME_CHANGED')
        with tempfile.TemporaryFile(dir=self.root) as payload:
            sqlite_payload(archive, payload, header, ranges); payload.seek(0)
            result = self.execute(source, 'verify', input_file=payload)
        if self.game == 'dependency-hell':
            callback = lambda refs: self.execute_artifacts(source, 'artifact_verify', refs, archive=archive, header=header, ranges=ranges)
            result['postgres'] = postgres_verify(self.kube, archive, header, ranges, self.root, self.operation_id, artifact_callback=callback)
            result['artifacts'] = result['postgres']['artifacts']
            result['live_artifacts'] = self.execute_artifacts(source, 'artifact_check', postgres_references(self.kube, PG_DATABASE))
        return {'source': source, **result}

    def restore(self, archive, expected_hash):
        """Restore to a new network-isolated namespace/PVC; never promote it."""
        historical, ranges = read_archive(archive, self.game, expected_hash=expected_hash)
        require_artifacts(historical)
        authority_operation = str(uuid.uuid5(uuid.UUID(self.operation_id), 'current-authority'))
        current = self.backup(operation_id=authority_operation, include_artifacts=False)
        authority, authority_ranges = read_archive(current['archive_path'], self.game, expected_hash=current['archive_sha256'])
        source = discover(self.kube, self.game)
        if authority['source']['pod_uid'] != source['pod_uid']:
            raise StorageError('SOURCE_POD_CHANGED')
        database_paths = lambda h: [s.get('database_path') for s in h['stores'] if s['engine'] != 'file_bundle']
        if historical['source']['pvc_uid'] != source['pvc_uid'] or database_paths(historical) != database_paths(authority):
            raise StorageError('SOURCE_VOLUME_OR_SCOPE_CHANGED')
        artifact_store = next((s for s in historical['stores'] if s['engine']=='file_bundle'), None)
        if artifact_store and self.execute(source, 'artifact_meta')['artifact_roots'] != artifact_store['artifact_roots']:
            raise StorageError('ARTIFACT_ROOT_SCOPE_CHANGED')
        ns_name = 'msgctf-storage-' + uuid.UUID(self.operation_id).hex
        labels = {'msgctf.io/storage-operation': self.operation_id, 'msgctf.io/storage-role': 'restore'}
        namespace = self.kube.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns_name, 'labels': labels}})
        ns_uid = namespace['metadata']['uid']
        result, completed = None, False
        try:
            self.save({'phase': 'restore_namespace_created', 'restore_namespace': ns_name, 'restore_namespace_uid': ns_uid,
                       'archive_sha256': expected_hash, 'source': source})
            self.kube.apply({'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                'metadata': {'name': 'deny-all', 'namespace': ns_name},
                'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}})
            self.kube.apply({'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': 'restore-data', 'namespace': ns_name, 'labels': labels},
                'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': restore_capacity(historical)}}}})
            node = self.kube.json(['get', 'node', source['node_name']])
            hostname = node['metadata']['labels']['kubernetes.io/hostname']
            env = []
            if artifact_store and self.game == 'grand-tour-duel':
                env += [{'name':'KOTH_SUBMISSIONS_DIR','value':artifact_store['artifact_roots']['sources']}, {'name':'KOTH_REPLAYS_DIR','value':artifact_store['artifact_roots']['replays']}]
            for spec, item in zip(PROFILES[self.game]['stores'], [s for s in authority['stores'] if s['engine'] == 'sqlite']):
                database = item['database_path']
                if self.game == 'swanopoly':
                    match = Path(database).parent.name
                    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', match):
                        raise StorageError('INVALID_MATCH_SCOPE')
                    values = {'STATE_DIR': str(Path(database).parent.parent), 'KOTH_MATCH_ID': match}
                else:
                    base = database[:-len(spec['suffix'])] if spec['suffix'] else database
                    values = {spec['path_env']: base}
                for key, value in values.items():
                    entry = {'name': key, 'value': value}
                    if entry not in env:
                        env.append(entry)
            language = PROFILES[self.game]['language']
            command = ['node', '-e', 'setInterval(()=>{},3600000)'] if language == 'node' else ['python', '-B', '-c', 'import time;time.sleep(3600)']
            pod_spec = {'restartPolicy': 'Never', 'terminationGracePeriodSeconds': 1, 'automountServiceAccountToken': False,
                'nodeSelector': {'kubernetes.io/hostname': hostname}, 'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001, 'fsGroup': 10001},
                'containers': [{'name': 'worker', 'image': source['container_image'], 'imagePullPolicy': 'Never', 'command': command, 'env': env,
                    'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'RuntimeDefault'}},
                    'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'cpu': '1', 'memory': '1Gi'}},
                    'volumeMounts': [{'name': 'data', 'mountPath': PROFILES[self.game]['data_root']}, {'name': 'tmp', 'mountPath': '/tmp'}]}],
                'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'restore-data'}}, {'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '16Mi'}}]}
            if source['runtime_class']:
                pod_spec['runtimeClassName'] = source['runtime_class']
            created = self.kube.apply({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'restore', 'namespace': ns_name, 'labels': labels}, 'spec': pod_spec})
            self.kube.run(['wait', '--for=condition=Ready', 'pod/restore', '-n', ns_name, '--timeout=120s'], timeout=125)
            pvc = self.kube.json(['get', 'pvc', 'restore-data', '-n', ns_name])
            if pvc['metadata']['uid'] == source['pvc_uid']:
                raise StorageError('RESTORE_SOURCE_VOLUME_FORBIDDEN')
            target = {**source, 'namespace': ns_name, 'pod_name': 'restore', 'pod_uid': created['metadata']['uid'], 'container': 'worker',
                      'pvc_name': 'restore-data', 'pvc_uid': pvc['metadata']['uid']}
            with tempfile.TemporaryFile(dir=self.root) as payload:
                sqlite_payload(archive, payload, historical, ranges)
                sqlite_payload(current['archive_path'], payload, authority, authority_ranges, include_artifacts=False)
                payload.seek(0); result = self.execute(target, 'restore', input_file=payload)
            if self.game == 'dependency-hell':
                callback = lambda refs: self.execute_artifacts(target, 'artifact_restore', refs, archive=archive, header=historical, ranges=ranges)
                result['postgres'] = postgres_restore_check(self.kube, archive, historical, ranges,
                    current['archive_path'], authority, authority_ranges, self.root, self.operation_id, artifact_callback=callback)
                result['artifacts'] = result['postgres']['artifacts']
            observed = self.execute(source, 'inspect')
            if [s['auth_history_sha256'] for s in observed['stores']] != [s['auth_history_sha256'] for s in authority['stores'] if s['engine'] == 'sqlite']:
                raise StorageError('SOURCE_AUTHORITY_CHANGED')
            result.update({'source': source, 'restore_pvc_uid': pvc['metadata']['uid'], 'source_pvc_untouched': True,
                           'restore_namespace': ns_name, 'network_isolated': True, 'participant_service_created': False, 'restore_pvc_storage': restore_capacity(historical)})
            completed = True
        finally:
            self.kube.delete_owned_namespace(ns_name, ns_uid, self.operation_id)
            self.save({'phase': 'complete' if completed else 'failed', 'restore_namespace': ns_name,
                       'restore_namespace_uid': ns_uid, 'restore_namespace_removed': True, 'source': source})
        result['restore_namespace_removed'] = True
        return result


def pg_command(kube, command, *, database=None, input_file=None, output_file=None, data=None):
    database = database or PG_DATABASE
    if database != PG_DATABASE and not re.fullmatch(r'msgctf_(?:backup|verify|restore)_[0-9a-f]{32}', database):
        raise StorageError('POSTGRES_TARGET_FORBIDDEN')
    if command == 'dump':
        args = ['sh', '-c', 'exec pg_dump -Fc -U "$POSTGRES_USER" -d "$1"', 'sh', database]
    elif command == 'restore':
        if database == PG_DATABASE:
            raise StorageError('LIVE_POSTGRES_RESTORE_FORBIDDEN')
        args = ['sh', '-c', 'exec pg_restore --exit-on-error -U "$POSTGRES_USER" -d "$1"', 'sh', database]
    elif command == 'sql':
        args = ['sh', '-c', 'exec psql -X -q -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$1"', 'sh', database]
    else:
        raise StorageError('INVALID_REQUEST')
    return kube.run(['exec', '-i', '-n', PG_NAMESPACE, 'deployment/' + PG_DEPLOYMENT, '-c', PG_CONTAINER, '--', *args],
                    data=data, input_file=input_file, output_file=output_file, timeout=120)


@contextmanager
def postgres_clone(kube, dump, operation_id, purpose, *, retain=False):
    name = 'msgctf_' + purpose + '_' + uuid.UUID(operation_id).hex
    if purpose not in {'backup', 'verify', 'restore'}:
        raise StorageError('POSTGRES_TARGET_FORBIDDEN')
    args = ['exec', '-i', '-n', PG_NAMESPACE, 'deployment/' + PG_DEPLOYMENT, '-c', PG_CONTAINER, '--',
            'sh', '-c', 'createdb -U "$POSTGRES_USER" -T template0 "$1"', 'sh', name]
    kube.run(args)
    completed = False
    try:
        # Existing app roles receive no CONNECT privilege on the temporary DB.
        pg_command(kube, 'sql', data=('REVOKE CONNECT ON DATABASE "' + name + '" FROM PUBLIC;').encode())
        pg_command(kube, 'sql', data=('COMMENT ON DATABASE "' + name + '" IS \'msgctf-koth-storage:' + operation_id + '\';').encode())
        with Path(dump).open('rb') as stream:
            pg_command(kube, 'restore', database=name, input_file=stream)
        yield name
        completed = True
    finally:
        if not retain or not completed:
            kube.run(['exec', '-i', '-n', PG_NAMESPACE, 'deployment/' + PG_DEPLOYMENT, '-c', PG_CONTAINER, '--',
                      'sh', '-c', 'exec dropdb --force -U "$POSTGRES_USER" "$1"', 'sh', name])


def postgres_cleanup(kube, operation_id):
    """Recover only this operation's marked, migration-owner temporary databases."""
    operations = [operation_id, str(uuid.uuid5(uuid.UUID(operation_id), 'current-authority'))]
    removed = []
    for operation in operations:
        for purpose in ('backup', 'verify', 'restore'):
            name = 'msgctf_' + purpose + '_' + uuid.UUID(operation).hex
            sql = ("SELECT json_build_object('owner',pg_get_userbyid(datdba),'current_user',current_user,'marker',shobj_description(oid,'pg_database')) FROM pg_database WHERE datname='" + name + "';")
            raw = pg_command(kube, 'sql', data=sql.encode()).strip()
            if not raw: continue
            entry = json.loads(raw)
            if entry['owner'] != entry['current_user'] or entry['marker'] != 'msgctf-koth-storage:' + operation:
                raise StorageError('POSTGRES_CLEANUP_SCOPE_CHANGED')
            kube.run(['exec', '-i', '-n', PG_NAMESPACE, 'deployment/' + PG_DEPLOYMENT, '-c', PG_CONTAINER, '--',
                      'sh', '-c', 'exec dropdb --force -U "$POSTGRES_USER" "$1"', 'sh', name])
            removed.append(name)
    return removed


PG_METADATA = b"""
CREATE TEMP TABLE storage_metadata(table_name text,row_count bigint,row_sha256 text);
DO $body$ DECLARE t record; n bigint; h text; BEGIN
 FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename LOOP
  EXECUTE format('SELECT count(*), encode(sha256(convert_to(COALESCE(string_agg(row_to_json(x)::text,E''\\n'' ORDER BY row_to_json(x)::text),''''),''UTF8'')),''hex'') FROM public.%I x',t.tablename) INTO n,h;
  INSERT INTO storage_metadata VALUES(t.tablename,n,h);
 END LOOP;
END $body$;
SELECT json_build_object(
 'table_row_counts',json_object_agg(table_name,row_count ORDER BY table_name),
 'business_sha256',encode(sha256(convert_to(COALESCE(string_agg(table_name||':'||row_sha256,E'\\n' ORDER BY table_name) FILTER(WHERE table_name NOT IN('sessions','dependency_hell_snapshot_hmac_keys','dependency_hell_submission_transition_hmac_keys')),''),'UTF8')),'hex'),
 'auth_history_sha256',encode(sha256(convert_to(COALESCE(string_agg(table_name||':'||row_sha256,E'\\n' ORDER BY table_name) FILTER(WHERE table_name IN('dependency_hell_snapshot_hmac_keys','dependency_hell_submission_transition_hmac_keys')),''),'UTF8')),'hex')
) FROM storage_metadata;
"""
PG_IMMUTABLE = b"""SELECT json_build_object(
'period_results',(SELECT COALESCE(json_object_agg(period_id,encode(sha256(convert_to(row_to_json(t)::text,'UTF8')),'hex')),'{}'::json) FROM period_results t),
'terminal_submissions',(SELECT COALESCE(json_object_agg(id,encode(sha256(convert_to((to_jsonb(t)-'artifact_path')::text,'UTF8')),'hex')),'{}'::json) FROM submissions t WHERE verdict<>'PENDING'));"""
PG_REFERENCES = b"""SELECT COALESCE(json_agg(row_to_json(t)),'[]'::json) FROM (
SELECT DISTINCT artifact_path,sha256,size_bytes FROM submissions WHERE artifact_path IS NOT NULL
ORDER BY artifact_path,sha256,size_bytes) t;"""


def postgres_references(kube, database):
    rows = json.loads(pg_command(kube, 'sql', database=database, data=PG_REFERENCES))
    if not isinstance(rows, list) or len(canonical({'references': rows})) + 1 > 32 * 1024 ** 2:
        raise StorageError('ARTIFACT_REFERENCE_LIMIT')
    return rows


def pg_metadata(kube, database):
    result = json.loads(pg_command(kube, 'sql', database=database, data=PG_METADATA))
    if not set(PG_AUTH_TABLES) <= set(result['table_row_counts']):
        raise StorageError('AUTH_HISTORY_MISSING')
    return result


def postgres_backup(kube, folder, operation_id, *, include_references=False):
    dump = folder / 'postgres.dump'
    with dump.open('xb') as output:
        os.chmod(dump, 0o600); pg_command(kube, 'dump', output_file=output); output.flush(); os.fsync(output.fileno())
    with postgres_clone(kube, dump, operation_id, 'backup') as database:
        meta = pg_metadata(kube, database)
        if include_references:
            meta['_artifact_references'] = postgres_references(kube, database)
            meta['artifact_database_references_sha256'] = hashlib.sha256(canonical(meta['_artifact_references'])).hexdigest()
    return dump, {'store_id': 'postgres', 'engine': 'postgresql', 'database_bytes': dump.stat().st_size,
                  'database_sha256': sha256(dump), 'database_name': PG_DATABASE, **meta}


def extract_postgres(archive, ranges, target):
    with Path(archive).open('rb') as source, target.open('xb') as output:
        os.chmod(target, 0o600); copy_range(source, output, *ranges['postgres'])
    return target


def postgres_verify(kube, archive, header, ranges, root, operation_id, *, artifact_callback=None):
    artifacts = None
    with tempfile.TemporaryDirectory(dir=root) as folder:
        dump = extract_postgres(archive, ranges, Path(folder) / 'postgres.dump')
        with postgres_clone(kube, dump, operation_id, 'verify') as database:
            original = json.loads(pg_command(kube, 'sql', database=database, data=PG_IMMUTABLE))
            if artifact_callback:
                artifacts = artifact_callback(postgres_references(kube, database))
        current = json.loads(pg_command(kube, 'sql', data=PG_IMMUTABLE))
    if not all(current[table].get(key) == value for table in original for key, value in original[table].items()):
        raise StorageError('ORIGINAL_ROWS_CHANGED')
    result = {'immutable_original_row_counts': {t: len(v) for t, v in original.items()}, 'missing_or_changed_row_count': 0,
              'postgres_context': 'database_pod', 'temporary_database_removed': True}
    if artifacts is not None: result['artifacts'] = artifacts
    return result


def postgres_restore_check(kube, archive, header, ranges, authority_archive, authority_header, authority_ranges, root, operation_id, *, artifact_callback=None, retain=False):
    artifacts = None
    with tempfile.TemporaryDirectory(dir=root) as folder:
        folder = Path(folder); historical = extract_postgres(archive, ranges, folder / 'historical.dump')
        current = extract_postgres(authority_archive, authority_ranges, folder / 'authority.dump')
        with postgres_clone(kube, historical, operation_id, 'restore', retain=retain) as database:
            sql = folder / 'auth.sql'
            with sql.open('xb') as output, current.open('rb') as stream:
                os.chmod(sql, 0o600); output.write(b'BEGIN;TRUNCATE public.sessions;TRUNCATE public.dependency_hell_snapshot_hmac_keys, public.dependency_hell_submission_transition_hmac_keys;\n')
                output.flush()
                # SQL-only pg_restore may need seek/EOF while selecting tables.
                # Stage the bounded, hash-checked dump inside the database Pod.
                script = '''set -eu
umask 077
folder=$(mktemp -d /tmp/msgctf-storage-auth-XXXXXX)
trap 'rm -f -- "$folder/archive.dump"; rmdir -- "$folder"' EXIT HUP INT TERM
head -c "$1" > "$folder/archive.dump"
actual=$(sha256sum "$folder/archive.dump")
test "${actual%% *}" = "$2"
pg_restore --file=- --data-only --table=dependency_hell_snapshot_hmac_keys --table=dependency_hell_submission_transition_hmac_keys "$folder/archive.dump"
'''
                kube.run(['exec', '-i', '-n', PG_NAMESPACE, 'deployment/' + PG_DEPLOYMENT, '-c', PG_CONTAINER, '--',
                    'timeout', '-k', '5', '90', 'sh', '-c', script, 'sh', str(current.stat().st_size), sha256(current)],
                    input_file=stream, output_file=output, timeout=105)
                output.write(b'\nCOMMIT;\n')
            with sql.open('rb') as input_file:
                pg_command(kube, 'sql', database=database, input_file=input_file)
            observed = pg_metadata(kube, database)
            old = next(s for s in header['stores'] if s['store_id'] == 'postgres')
            active = next(s for s in authority_header['stores'] if s['store_id'] == 'postgres')
            if observed['business_sha256'] != old['business_sha256'] or observed['auth_history_sha256'] != active['auth_history_sha256'] or observed['table_row_counts'].get('sessions', 0):
                raise StorageError('RESTORE_VERIFICATION_FAILED')
            if artifact_callback:
                artifacts = artifact_callback(postgres_references(kube, database))
        if pg_metadata(kube, PG_DATABASE)['auth_history_sha256'] != active['auth_history_sha256']:
            raise StorageError('SOURCE_AUTHORITY_CHANGED')
    result = {'business_sha256': observed['business_sha256'], 'current_auth_history_preserved': True,
             'restored_session_row_count': 0, 'source_database_untouched': True, 'temporary_database_removed': not retain,
            'postgres_context': 'database_pod'}
    if retain: result['restored_database_name'] = database
    if artifacts is not None: result['artifacts'] = artifacts
    return result


@contextmanager
def operation_lock(root, game):
    if fcntl is None:
        raise StorageError('LINUX_CONTROLLER_REQUIRED')
    path = root / (game + '.lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise StorageError('STORAGE_OPERATION_BUSY') from None
        yield


@contextmanager
def action_audit(storage, action):
    try:
        yield
    except Exception as error:
        previous = json.loads(storage.journal.read_text()) if storage.journal.exists() else {}
        keep = {k: previous[k] for k in ('restore_namespace', 'restore_namespace_uid', 'source', 'restore_namespace_removed') if k in previous}
        storage.save({'phase': 'failed', 'action': action,
                      'error_code': str(error) if isinstance(error, StorageError) else 'STORAGE_OPERATION_FAILED', **keep})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'backup', 'verify', 'restore', 'cleanup'])
    parser.add_argument('--game', required=True, choices=sorted(PROFILES))
    parser.add_argument('--operation-id', required=True)
    parser.add_argument('--actor', required=True)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--sha256')
    args = parser.parse_args()
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise StorageError('ROOT_LINUX_CONTROLLER_REQUIRED')
    config_path = Path('/etc/msgctf-koth-storage/config.json'); private_file(config_path)
    config = json.loads(config_path.read_text())
    if config['game'] != args.game:
        raise StorageError('HOST_GAME_SCOPE_MISMATCH')
    directory = Path(__file__).resolve().parent
    if (not re.fullmatch(r'[0-9a-f]{40}', config.get('source_sha', '')) or directory.name != config['source_sha']
            or set(config.get('files', {})) != {'koth_storage.py', 'koth_storage_worker.py', 'koth_storage_worker.cjs', 'koth_core_egress.py', 'koth_storage_artifacts.py', 'koth_storage_cutover.py'}
            or any(sha256(directory / name) != digest for name, digest in config['files'].items())):
        raise StorageError('INSTALLED_SOURCE_CHANGED')
    storage = Storage(args.game, args.operation_id, args.actor)
    with operation_lock(storage.root, args.game), action_audit(storage, args.action):
        if args.action != 'cleanup': storage.save({'phase': 'started', 'action': args.action})
        if args.action in {'verify', 'restore'}:
            if not args.archive or not args.sha256 or not re.fullmatch(r'[0-9a-f]{64}', args.sha256):
                raise StorageError('EXPECTED_ARCHIVE_HASH_REQUIRED')
        if args.action == 'inspect': result = storage.inspect()
        elif args.action == 'backup': result = storage.backup()
        elif args.action == 'verify': result = storage.verify(args.archive, args.sha256)
        elif args.action == 'restore': result = storage.restore(args.archive, args.sha256)
        else:
            if not storage.journal.exists():
                raise StorageError('RESTORE_JOURNAL_REQUIRED')
            private_file(storage.journal); journal = json.loads(storage.journal.read_text())
            if journal['game'] != args.game or journal['operation_id'] != args.operation_id:
                raise StorageError('CLEANUP_SCOPE_CHANGED')
            if journal.get('restore_namespace'):
                storage.kube.delete_owned_namespace(journal['restore_namespace'], journal['restore_namespace_uid'], args.operation_id)
            source = discover(storage.kube, args.game)
            result = storage.execute(source, 'cleanup')
            if args.game == 'dependency-hell': result['removed_temporary_databases'] = postgres_cleanup(storage.kube, args.operation_id)
            result['restore_namespace_removed'] = True
        output = {'format_version': VERSION, 'operation_id': args.operation_id, 'game': args.game, 'action': args.action,
                  'actor': args.actor, 'tool_source_sha': config['source_sha'], **result}
        storage.save({'phase': 'complete', 'result': output})
        print(json.dumps(output))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        code = str(error) if isinstance(error, StorageError) else 'STORAGE_OPERATION_FAILED'
        sys.stderr.write(json.dumps({'error_code': code}) + '\n'); raise SystemExit(1) from None
