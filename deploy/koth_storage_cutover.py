#!/usr/bin/env python3
"""Fenced production storage cutover with durable decisions and safe rollback.

All database/file engines run in pinned Pods. The host transports closed bytes.
Before publishing traffic a failed transaction rolls back. Once publishing has
begun, recovery rolls forward: a stale volume must never discard accepted writes.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

import koth_storage as s

FENCE = 'msgctf.io/storage-route'
AGENT = 'koth-environment-agent.service'
TERMINAL = {'committed', 'rolled_back'}
FAULTS = ('none', 'after_freeze', 'after_restore', 'after_pvc_switch', 'after_pg_swap', 'after_ready')


def atomic_json(path, value):
    fd, name = tempfile.mkstemp(prefix='.cutover-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(s.canonical(value)); out.flush(); os.fsync(out.fileno())
        os.chmod(name, 0o600); os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def sql_identifier(value):
    if not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', value):
        raise s.StorageError('POSTGRES_IDENTIFIER_UNSUPPORTED')
    return '"' + value + '"'


def pg_control(kube, sql):
    return kube.run(['exec', '-i', '-n', s.PG_NAMESPACE, 'deployment/' + s.PG_DEPLOYMENT, '-c', s.PG_CONTAINER,
                     '--', 'sh', '-c', 'exec psql -X -q -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres'], data=sql.encode(), timeout=120)


def pg_databases(kube):
    sql_identifier(s.PG_DATABASE)
    sql = """SELECT COALESCE(json_agg(row_to_json(x)),'[]'::json) FROM (
    SELECT oid::text AS database_oid,datname AS database_name,pg_get_userbyid(datdba) AS owner,
    datallowconn AS allow_connections,datconnlimit AS connection_limit,
    pg_encoding_to_char(encoding) AS encoding,datcollate AS collate,datctype AS ctype,
    shobj_description(oid,'pg_database') AS marker,
    (SELECT COALESCE(json_agg(json_build_object('role',CASE WHEN setrole=0 THEN NULL ELSE pg_get_userbyid(setrole) END,'config',setconfig)),'[]'::json)
     FROM pg_db_role_setting WHERE setdatabase=pg_database.oid) AS settings,
    (SELECT COALESCE(json_agg(json_build_object('grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
     'privilege',a.privilege_type,'grantable',a.is_grantable)),'[]'::json) FROM aclexplode(COALESCE(datacl,acldefault('d',datdba))) a) AS privileges
    FROM pg_database WHERE datname='dependency_hell' OR datname LIKE 'msgctf\\_%' ESCAPE '\\' ORDER BY datname) x;"""
    sql=sql.replace("datname='dependency_hell'", "datname='"+s.PG_DATABASE+"'")
    return {v['database_name']: v for v in json.loads(pg_control(kube, sql))}


def pg_swap_sql(current, candidate, previous):
    # Database rename and ALLOW_CONNECTIONS changes are transactional. Connect to
    # postgres, not either database being renamed. OID checks happen under fence.
    old, new, saved = map(sql_identifier, (current, candidate, previous))
    return (f'BEGIN; ALTER DATABASE {old} ALLOW_CONNECTIONS false; ALTER DATABASE {new} ALLOW_CONNECTIONS false; '
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN ('{current}','{candidate}') AND pid<>pg_backend_pid(); "
            f'ALTER DATABASE {old} RENAME TO {saved}; ALTER DATABASE {new} RENAME TO {old}; '
            f'ALTER DATABASE {old} ALLOW_CONNECTIONS true; COMMIT;')


def require_no_loss(candidate, latest):
    """An online recovery must preserve *all* frozen business rows, not only scores."""
    old = {v['store_id']: v for v in candidate['stores'] if v['engine'] != 'file_bundle'}
    new = {v['store_id']: v for v in latest['stores'] if v['engine'] != 'file_bundle'}
    if set(old) != set(new) or any(old[k].get('schema_sha256') != new[k].get('schema_sha256')
                                  or old[k]['business_sha256'] != new[k]['business_sha256'] for k in new):
        raise s.StorageError('RECOVERY_WOULD_DISCARD_CURRENT_BUSINESS_ROWS')
    paths = lambda h: [(v['store_id'], v.get('database_path')) for v in h['stores'] if v['engine'] == 'sqlite']
    if paths(candidate) != paths(latest):
        raise s.StorageError('DATABASE_SCOPE_CHANGED')
    files = lambda h: [(v['artifact_roots'], v['references_sha256']) for v in h['stores'] if v['engine'] == 'file_bundle']
    if files(candidate) != files(latest):
        raise s.StorageError('ARTIFACT_DATABASE_REFERENCES_MISMATCH')


def production_capacity(header, original):
    match=re.fullmatch(r'([1-9][0-9]*)(Gi|Mi)',original)
    if not match: raise s.StorageError('SOURCE_CAPACITY_UNSUPPORTED')
    amount=int(match[1])*(1024 if match[2]=='Gi' else 1)
    size=max((amount+1023)//1024,int(s.restore_capacity(header)[:-2]))
    if size>32: raise s.StorageError('RESTORE_CAPACITY_LIMIT')
    return str(size)+'Gi'


class Cutover:
    def __init__(self, storage, *, system=None):
        self.storage, self.kube, self.root = storage, storage.kube, storage.root
        self.game, self.operation_id = storage.game, storage.operation_id
        self.profile = s.PROFILES[self.game]
        folder = self.root / 'cutovers'
        if folder.is_symlink(): raise s.StorageError('STATE_DIRECTORY_UNSAFE')
        folder.mkdir(mode=0o700, exist_ok=True)
        if folder.stat().st_uid != os.geteuid() or folder.stat().st_mode & 0o077:
            raise s.StorageError('STATE_DIRECTORY_UNSAFE')
        self.path = folder / (self.operation_id + '.json')
        self.active = self.root / 'active-cutover.json'
        self.system = system or self.system_command
        self.state = self.read(self.path) if self.path.exists() else {}
        if self.state and (self.state.get('operation_id')!=self.operation_id or self.state.get('game')!=self.game or self.state.get('format_version')!=1):
            raise s.StorageError('CUTOVER_SCOPE_CHANGED')

    @staticmethod
    def read(path):
        s.private_file(path)
        return json.loads(path.read_text())

    @staticmethod
    def system_command(args, *, optional=False):
        result = subprocess.run(args, capture_output=True, timeout=45)
        if result.returncode and not optional: raise s.StorageError('SYSTEM_SERVICE_OPERATION_FAILED')
        return result.returncode == 0

    def save(self, phase=None, **values):
        self.state.update(values)
        if phase: self.state['phase'] = phase
        self.state['recorded_at'] = datetime.now(timezone.utc).isoformat()
        atomic_json(self.path, self.state)
        fd = os.open(self.path.with_suffix('.jsonl'), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as events:
            # Events contain transition metadata, never full templates/credentials.
            events.write(s.canonical(self.status()) + b'\n'); events.flush(); os.fsync(events.fileno())

    def status(self):
        allowed = ('format_version', 'game', 'operation_id', 'actor', 'phase', 'decision', 'recorded_at', 'fault',
                   'archive_sha256', 'original_pvc_uid', 'candidate_pvc_uid', 'candidate_pvc_name', 'error_code',
                   'restored_file_count', 'current_auth_history_preserved', 'restored_session_row_count',
                   'postgres_original_oid', 'postgres_candidate_oid', 'postgres_previous_database', 'failed_candidate_retired', 'result')
        return {key: self.state[key] for key in allowed if key in self.state}

    def plan(self, archive=None, expected_hash=None, fault='none'):
        if self.state:
            if (self.state.get('archive'), self.state.get('expected_hash'), self.state.get('fault')) != (str(archive) if archive else None, expected_hash, fault):
                raise s.StorageError('OPERATION_ID_REUSED_WITH_DIFFERENT_REQUEST')
            return self.status()
        if fault not in FAULTS: raise s.StorageError('INVALID_FAULT')
        if bool(archive) != bool(expected_hash): raise s.StorageError('EXPECTED_ARCHIVE_HASH_REQUIRED')
        if archive:
            header, _ = s.read_archive(archive, self.game, expected_hash=expected_hash); s.require_artifacts(header)
        self.state = {'format_version': 1, 'game': self.game, 'operation_id': self.operation_id, 'actor': self.storage.actor,
                      'archive': str(archive) if archive else None, 'expected_hash': expected_hash, 'fault': fault, 'decision': 'rollback'}
        self.save('planned')
        return self.status()

    def resource(self, kind, name):
        return self.kube.json(['get', kind, name, '-n', self.profile['namespace']])

    def patch(self, kind, name, uid, path, before, after):
        obj = self.resource(kind, name)
        value = obj
        for field in path.strip('/').split('/'): value = value[field]
        if obj['metadata']['uid'] != uid or value not in (before, after):
            raise s.StorageError('CUTOVER_RESOURCE_CONFLICT')
        if value == after: return
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': uid},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                 {'op': 'test', 'path': path, 'value': before}, {'op': 'replace', 'path': path, 'value': after}]
        self.kube.run(['patch', kind, name, '-n', self.profile['namespace'], '--type=json', '-p', s.canonical(patch).decode()])

    def preflight(self):
        source = s.discover(self.kube, self.game)
        namespace = self.profile['namespace']
        resources = self.kube.json(['get', 'deployments,statefulsets,daemonsets,jobs,cronjobs', '-n', namespace])['items']
        if not resources or any(v['kind'] != 'Deployment' for v in resources):
            raise s.StorageError('UNSUPPORTED_STORAGE_WRITER')
        deployments = {}
        for value in resources:
            name, spec = value['metadata']['name'], value['spec']
            # Preserve every non-storage field and all separate internal workers.
            deployments[name] = {'uid': value['metadata']['uid'], 'replicas': spec.get('replicas', 1),
                                 'before': spec['template'], 'after': copy.deepcopy(spec['template'])}
            if not 1 <= deployments[name]['replicas'] <= 32: raise s.StorageError('INVALID_REPLICA_SCOPE')
        services = {}
        for value in self.kube.json(['get', 'services', '-n', namespace])['items']:
            selector = value['spec'].get('selector')
            if not selector or FENCE in selector: raise s.StorageError('SERVICE_FENCE_CONFLICT')
            services[value['metadata']['name']] = {'uid': value['metadata']['uid'], 'before': selector,
                                                  'after': {**selector, FENCE: self.operation_id}}
        if not services: raise s.StorageError('SERVICE_FENCE_REQUIRED')
        autoscalers = {}
        for value in self.kube.json(['get', 'hpa', '-n', namespace])['items']:
            target = value['spec']['scaleTargetRef']
            if target.get('kind') != 'Deployment' or target['name'] not in deployments:
                raise s.StorageError('UNSUPPORTED_AUTOSCALER')
            autoscalers[value['metadata']['name']] = {'uid': value['metadata']['uid'], 'before': target,
                'after': {**target, 'name': 'storage-fenced-' + uuid.UUID(self.operation_id).hex}}
        inspected = self.storage.inspect()
        roots = self.storage.execute(source, 'artifact_meta')['artifact_roots'] if self.game in s.FILE_GAMES else None
        pvc = self.resource('pvc', source['pvc_name'])
        if pvc['metadata']['uid'] != source['pvc_uid'] or pvc['status']['phase'] != 'Bound':
            raise s.StorageError('SOURCE_VOLUME_CHANGED')
        # Dynamic replacement is deliberately a separate pool. Never reformat or
        # rebind a source PV, and never delete a rollback PVC automatically.
        classes = self.kube.json(['get', 'storageclasses'])['items']
        if not any(v['metadata']['name'] == 'local-path' for v in classes):
            raise s.StorageError('RECOVERY_STORAGE_CLASS_REQUIRED')
        marker = 'recovery-' + uuid.UUID(self.operation_id).hex
        for entry in deployments.values():
            for volume in entry['after']['spec'].get('volumes', []):
                if volume.get('persistentVolumeClaim', {}).get('claimName') == source['pvc_name']:
                    volume['persistentVolumeClaim']['claimName'] = marker
        pg = {}
        if self.game == 'dependency-hell':
            pg = pg_databases(self.kube)[s.PG_DATABASE]
            if not pg['allow_connections']: raise s.StorageError('POSTGRES_SOURCE_NOT_READY')
        self.save('prepared', source=source, deployments=deployments, services=services, autoscalers=autoscalers,
                  original_pvc_uid=source['pvc_uid'], original_pvc_storage=pvc['spec']['resources']['requests']['storage'],
                  candidate_pvc_name=marker, store_metadata=inspected['stores'],
                  artifact_roots=roots, agent_was_active=self.system(['systemctl', 'is-active', '--quiet', AGENT], optional=True),
                  postgres=pg, postgres_original_oid=pg.get('database_oid'),
                  postgres_previous_database='msgctf_previous_' + uuid.UUID(self.operation_id).hex,
                  postgres_candidate_database='msgctf_restore_' + uuid.UUID(self.operation_id).hex)
        if self.active.exists() and self.read(self.active).get('operation_id') != self.operation_id:
            raise s.StorageError('STORAGE_OPERATION_BUSY')
        atomic_json(self.active, {'game': self.game, 'operation_id': self.operation_id})

    def fence(self, enabled):
        for name, value in self.state['services'].items():
            old, new = (value['before'], value['after']) if enabled else (value['after'], value['before'])
            self.patch('service', name, value['uid'], '/spec/selector', old, new)

    def autoscale(self, paused):
        for name, value in self.state['autoscalers'].items():
            old, new = (value['before'], value['after']) if paused else (value['after'], value['before'])
            self.patch('hpa', name, value['uid'], '/spec/scaleTargetRef', old, new)

    def scale(self, stopped):
        for name, value in self.state['deployments'].items():
            obj = self.resource('deployment', name)
            if obj['metadata']['uid'] != value['uid'] or obj['spec']['template'] not in (value['before'], value['after']):
                raise s.StorageError('CUTOVER_RESOURCE_CONFLICT')
            wanted = 0 if stopped else value['replicas']
            self.patch('deployment', name, value['uid'], '/spec/replicas', obj['spec']['replicas'], wanted)

    def wait_stopped(self):
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            pods = self.kube.json(['get', 'pods', '-n', self.profile['namespace']])['items']
            remaining = [v for v in pods if v['metadata'].get('labels', {}).get('msgctf.io/storage-operation') != self.operation_id
                         and v['status'].get('phase') not in {'Succeeded', 'Failed'}]
            if not remaining:
                if self.game=='dependency-hell':
                    raw=s.pg_command(self.kube,'sql',data=b"SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename<>current_user;")
                    if int(raw.strip())!=0: raise s.StorageError('UNFENCED_POSTGRES_CLIENTS')
                return
            time.sleep(1)
        raise s.StorageError('WRITER_DRAIN_TIMEOUT')

    def templates(self, forward):
        for name, value in self.state['deployments'].items():
            obj = self.resource('deployment', name)
            if obj['spec'].get('replicas', 1) != 0: raise s.StorageError('WRITERS_NOT_STOPPED')
            old, new = (value['before'], value['after']) if forward else (value['after'], value['before'])
            self.patch('deployment', name, value['uid'], '/spec/template', old, new)

    def worker(self, target=False):
        source = self.state['source']
        namespace = source['namespace']
        name = ('storage-target-' if target else 'storage-source-') + uuid.UUID(self.operation_id).hex[:12]
        claim = self.state['candidate_pvc_name'] if target else source['pvc_name']
        expected_uid = self.state.get('candidate_pvc_uid') if target else source['pvc_uid']
        pvc = self.resource('pvc', claim)
        if expected_uid and pvc['metadata']['uid'] != expected_uid: raise s.StorageError('SOURCE_VOLUME_CHANGED')
        labels = {'msgctf.io/storage-operation': self.operation_id, 'msgctf.io/storage-role': 'maintenance'}
        found = self.kube.json(['get', 'pod', name, '-n', namespace], optional=True)
        if found:
            if found['metadata'].get('labels', {}) != labels or found['spec']['volumes'][0].get('persistentVolumeClaim', {}).get('claimName') != claim:
                raise s.StorageError('MAINTENANCE_POD_CONFLICT')
        else:
            env = []
            for spec, item in zip(self.profile['stores'], self.state['store_metadata']):
                database = item['database_path']
                if self.game == 'swanopoly':
                    values = {'STATE_DIR': str(Path(database).parent.parent), 'KOTH_MATCH_ID': Path(database).parent.name}
                else:
                    values = {spec['path_env']: database[:-len(spec['suffix'])] if spec['suffix'] else database}
                for key, value in values.items():
                    entry = {'name': key, 'value': value}
                    if entry not in env: env.append(entry)
            if self.game == 'grand-tour-duel':
                env += [{'name': 'KOTH_SUBMISSIONS_DIR', 'value': self.state['artifact_roots']['sources']},
                        {'name': 'KOTH_REPLAYS_DIR', 'value': self.state['artifact_roots']['replays']}]
            language = self.profile['language']
            command = ['node', '-e', 'setInterval(()=>{},3600000)'] if language == 'node' else ['python', '-B', '-c', 'import time;time.sleep(7200)']
            node = self.kube.json(['get', 'node', source['node_name']])
            spec = {'restartPolicy': 'Never', 'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 1,
                'nodeSelector': {'kubernetes.io/hostname': node['metadata']['labels']['kubernetes.io/hostname']},
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001, 'fsGroup': 10001},
                'containers': [{'name': 'worker', 'image': source['container_image'], 'imagePullPolicy': 'Never', 'command': command, 'env': env,
                    'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'RuntimeDefault'}},
                    'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'cpu': '1', 'memory': '1Gi'}},
                    'volumeMounts': [{'name': 'data', 'mountPath': self.profile['data_root']}, {'name': 'tmp', 'mountPath': '/tmp'}]}],
                'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': claim}}, {'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '16Mi'}}]}
            if source['runtime_class']: spec['runtimeClassName'] = source['runtime_class']
            policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                'metadata': {'name': name, 'namespace': namespace, 'labels': labels},
                'spec': {'podSelector': {'matchLabels': labels}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}}
            self.kube.apply(policy)
            found = self.kube.apply({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace, 'labels': labels}, 'spec': spec})
        self.kube.run(['wait', '--for=condition=Ready', 'pod/' + name, '-n', namespace, '--timeout=120s'], timeout=125)
        return {**source, 'pod_name': name, 'pod_uid': found['metadata']['uid'], 'container': 'worker',
                'pvc_name': claim, 'pvc_uid': pvc['metadata']['uid']}

    def remove_workers(self):
        for prefix in ('storage-source-', 'storage-target-'):
            name = prefix + uuid.UUID(self.operation_id).hex[:12]
            for kind in ('pod', 'networkpolicy'):
                obj = self.kube.json(['get', kind, name, '-n', self.profile['namespace']], optional=True)
                if obj is None: continue
                if obj['metadata'].get('labels', {}).get('msgctf.io/storage-operation') != self.operation_id:
                    raise s.StorageError('CLEANUP_SCOPE_CHANGED')
                plural = 'pods' if kind == 'pod' else 'networkpolicies'
                api = '/api/v1' if kind == 'pod' else '/apis/networking.k8s.io/v1'
                options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': obj['metadata']['uid']}}
                self.kube.run(['delete', '--raw', api + '/namespaces/' + self.profile['namespace'] + '/' + plural + '/' + name, '-f', '-'], data=s.canonical(options))
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            pods = self.kube.json(['get', 'pods', '-n', self.profile['namespace'], '-l', 'msgctf.io/storage-operation=' + self.operation_id])['items']
            if not pods: return
            time.sleep(1)
        raise s.StorageError('MAINTENANCE_CLEANUP_PENDING')

    def freeze(self):
        self.save('freezing')
        if self.state['agent_was_active']: self.system(['systemctl', 'stop', AGENT])
        self.fence(True); self.autoscale(True); self.scale(True); self.wait_stopped()
        self.save('frozen')

    def fail(self, point):
        if self.state['fault'] == point: raise s.StorageError('INJECTED_' + point.upper())

    def capture(self, source, purpose, *, files=True):
        self.storage.source_override = source
        return self.storage.backup(operation_id=str(uuid.uuid5(uuid.UUID(self.operation_id), purpose)), include_artifacts=files)

    def prepare(self):
        frozen = self.capture(self.worker(), 'frozen-latest')
        latest, _ = s.read_archive(frozen['archive_path'], self.game, expected_hash=frozen['archive_sha256'])
        archive = self.state['archive'] or frozen['archive_path']
        digest = self.state['expected_hash'] or frozen['archive_sha256']
        header, ranges = s.read_archive(archive, self.game, expected_hash=digest)
        s.require_artifacts(header); require_no_loss(header, latest)
        if header['source']['pvc_uid'] != self.state['original_pvc_uid']:
            raise s.StorageError('SOURCE_VOLUME_CHANGED')
        need = sum(v.get('uncompressed_bytes', v['database_bytes']) for v in header['stores']) + sum(v['database_bytes'] for v in header['stores']) + 2 * 1024**3
        if shutil.disk_usage('/var/lib/rancher/k3s/storage').free < need: raise s.StorageError('RECOVERY_STORAGE_CAPACITY_INSUFFICIENT')
        self.save('restore_intent', frozen=frozen, selected_archive=archive, archive_sha256=digest)
        name = self.state['candidate_pvc_name']
        if self.kube.json(['get', 'pvc', name, '-n', self.profile['namespace']], optional=True):
            raise s.StorageError('RESTORE_TARGET_NOT_EMPTY')
        labels = {'msgctf.io/storage-operation': self.operation_id, 'msgctf.io/storage-role': 'recovery'}
        pvc = self.kube.apply({'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim',
            'metadata': {'name': name, 'namespace': self.profile['namespace'], 'labels': labels},
            'spec': {'storageClassName': 'local-path', 'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': production_capacity(header,self.state['original_pvc_storage'])}}}})
        self.save(candidate_pvc_uid=pvc['metadata']['uid'])
        target = self.worker(True)
        with tempfile.TemporaryFile(dir=self.root) as payload:
            s.sqlite_payload(archive, payload, header, ranges)
            _, active_ranges = s.read_archive(frozen['archive_path'], self.game)
            s.sqlite_payload(frozen['archive_path'], payload, latest, active_ranges, include_artifacts=False)
            payload.seek(0)
            result = self.storage.execute(target, 'restore', input_file=payload)
        if self.game == 'dependency-hell':
            callback = lambda refs: self.storage.execute_artifacts(target, 'artifact_restore', refs, archive=archive, header=header, ranges=ranges)
            pg_result = s.postgres_restore_check(self.kube, archive, header, ranges, frozen['archive_path'], latest, active_ranges,
                                                self.root, self.operation_id, artifact_callback=callback, retain=True)
            result['postgres'] = pg_result
            databases = pg_databases(self.kube)
            self.save(postgres_candidate_oid=databases[self.state['postgres_candidate_database']]['database_oid'])
        self.save('restored', restore_proof=result, restored_file_count=next((v.get('reference_count',0) for v in header['stores'] if v['engine']=='file_bundle'), 0),
                  current_auth_history_preserved=True, restored_session_row_count=0)

    def postgres_switch(self, forward):
        if self.game != 'dependency-hell': return
        dbs = pg_databases(self.kube)
        current, candidate, previous = s.PG_DATABASE, self.state['postgres_candidate_database'], self.state['postgres_previous_database']
        old_oid, new_oid = self.state['postgres_original_oid'], self.state.get('postgres_candidate_oid')
        if forward:
            if dbs.get(current, {}).get('database_oid') == new_oid and new_oid:
                if dbs.get(previous, {}).get('database_oid') != old_oid: raise s.StorageError('POSTGRES_SWAP_CONFLICT')
                return
            if (dbs.get(current, {}).get('database_oid') != old_oid or previous in dbs or not new_oid
                    or dbs.get(candidate, {}).get('database_oid') != new_oid
                    or dbs[candidate]['marker'] != 'msgctf-koth-storage:' + self.operation_id):
                raise s.StorageError('POSTGRES_SWAP_CONFLICT')
            original = self.state['postgres']; q = sql_identifier(candidate)
            if any(dbs[candidate][key] != original[key] for key in ('encoding','collate','ctype')):
                raise s.StorageError('POSTGRES_DATABASE_PROPERTIES_CHANGED')
            sql = f'ALTER DATABASE {q} OWNER TO {sql_identifier(original["owner"])}; REVOKE ALL ON DATABASE {q} FROM PUBLIC; '
            limit=original['connection_limit']
            if type(limit) is not int or not -1<=limit<=100000: raise s.StorageError('POSTGRES_DATABASE_PROPERTIES_CHANGED')
            sql+=f'ALTER DATABASE {q} CONNECTION LIMIT {limit}; '
            for setting in original['settings']:
                for config in setting['config']:
                    key,value=config.split('=',1)
                    prefix=f'ALTER ROLE {sql_identifier(setting["role"])} IN DATABASE {q}' if setting['role'] else f'ALTER DATABASE {q}'
                    sql+=prefix+' SET '+sql_identifier(key)+" TO '"+value.replace("'","''")+"'; "
            for grant in original['privileges']:
                if grant['privilege'] not in {'CREATE','CONNECT','TEMPORARY'}: raise s.StorageError('POSTGRES_PRIVILEGE_UNSUPPORTED')
                role = 'PUBLIC' if grant['grantee']=='PUBLIC' else sql_identifier(grant['grantee'])
                sql += f'GRANT {grant["privilege"]} ON DATABASE {q} TO {role}' + (' WITH GRANT OPTION' if grant['grantable'] else '') + '; '
            pg_control(self.kube, sql)
            pg_control(self.kube, pg_swap_sql(current, candidate, previous))
        else:
            if dbs.get(current, {}).get('database_oid') == old_oid:
                if previous in dbs: raise s.StorageError('POSTGRES_SWAP_CONFLICT')
                return
            if (not new_oid or dbs.get(current, {}).get('database_oid') != new_oid or candidate in dbs
                    or dbs.get(previous, {}).get('database_oid') != old_oid):
                raise s.StorageError('POSTGRES_SWAP_CONFLICT')
            pg_control(self.kube, pg_swap_sql(current, previous, candidate))

    def wait_ready(self, forward):
        for name in self.state['deployments']:
            self.kube.run(['rollout', 'status', 'deployment/' + name, '-n', self.profile['namespace'], '--timeout=180s'], timeout=190)
        source = s.discover(self.kube, self.game)
        uid = self.state['candidate_pvc_uid'] if forward else self.state['original_pvc_uid']
        if source['pvc_uid'] != uid: raise s.StorageError('LIVE_VOLUME_CHANGED')
        self.storage.source_override = source
        return source

    def validate(self, source, authority=None):
        frozen = self.state.get('frozen') or authority
        header, ranges = s.read_archive(frozen['archive_path'], self.game, expected_hash=frozen['archive_sha256'])
        active,_=s.read_archive(authority['archive_path'],self.game,expected_hash=authority['archive_sha256']) if authority else (header,None)
        has_files=any(v['engine']=='file_bundle' for v in header['stores'])
        with tempfile.TemporaryFile(dir=self.root) as payload:
            s.sqlite_payload(frozen['archive_path'], payload, header, ranges); payload.seek(0)
            self.storage.execute(source, 'verify', input_file=payload,include_artifacts=has_files)
        inspected = self.storage.execute(source, 'inspect')
        expected = [v for v in active['stores'] if v['engine']=='sqlite']
        for spec, item, original in zip(self.profile['stores'], inspected['stores'], expected):
            if item['auth_history_sha256'] != original['auth_history_sha256'] or any(item['table_row_counts'].get(t,0) for t in spec['session_tables']):
                raise s.StorageError('LIVE_AUTHORITY_OR_SESSION_MISMATCH')
        if self.game == 'dependency-hell':
            callback = (lambda refs: self.storage.execute_artifacts(source, 'artifact_verify', refs, archive=frozen['archive_path'], header=header, ranges=ranges)) if has_files else None
            s.postgres_verify(self.kube, frozen['archive_path'], header, ranges, self.root,
                              str(uuid.uuid5(uuid.UUID(self.operation_id),'validate-live')), artifact_callback=callback)
            actual = s.pg_metadata(self.kube,s.PG_DATABASE)
            pg = next(v for v in active['stores'] if v['engine']=='postgresql')
            if actual['auth_history_sha256'] != pg['auth_history_sha256'] or actual['table_row_counts'].get('sessions',0):
                raise s.StorageError('LIVE_AUTHORITY_OR_SESSION_MISMATCH')
        return {'original_rows_preserved': True, 'current_auth_history_preserved': True, 'restored_session_row_count': 0,
                'live_pvc_uid': source['pvc_uid'], 'live_replica_count': source['replica_count']}

    def finish(self, forward, result):
        # Durable commit decision MUST precede the first route opening. Recovery
        # cannot distinguish a request accepted between two API calls otherwise.
        self.save('publishing', decision='commit' if forward else 'rollback_publish', result=result)
        self.fence(False); self.autoscale(False)
        if self.state['agent_was_active'] and not os.environ.get('MSGCTF_BOOT_RECOVERY'):
            self.system(['systemctl','start',AGENT])
        self.save('committed' if forward else 'rolled_back', result=result)
        if self.active.exists():
            if self.read(self.active).get('operation_id') != self.operation_id: raise s.StorageError('CUTOVER_RESOURCE_CONFLICT')
            self.active.unlink()
            directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
        return self.status()

    def rollback(self):
        self.save('rollback_freezing')
        if self.state['agent_was_active']: self.system(['systemctl','stop',AGENT])
        self.fence(True); self.autoscale(True); self.scale(True); self.wait_stopped()
        # kubectl/SSH death does not necessarily terminate an exec process. Kill
        # owned maintenance Pods before touching the original store on recovery.
        self.remove_workers()
        # Once application startup was attempted, capture current authority from
        # the candidate before reverting, so retirement cannot be resurrected.
        target_live = self.resource('deployment', self.profile['deployment'])['spec']['template'] == self.state['deployments'][self.profile['deployment']]['after']
        authority = self.capture(self.worker(target_live), 'rollback-authority', files=False)
        header, ranges = s.read_archive(authority['archive_path'], self.game, expected_hash=authority['archive_sha256'])
        original = self.worker()
        for purpose in ('frozen-latest','rollback-authority'):
            child=str(uuid.uuid5(uuid.UUID(self.operation_id),purpose))
            self.storage.execute(original,'cleanup',operation_id=child)
        # New confirmed rows created by an autonomous worker while fenced cannot
        # be silently discarded. Keep both stores and stay fenced on this conflict.
        with tempfile.TemporaryFile(dir=self.root) as payload:
            s.sqlite_payload(authority['archive_path'],payload,header,ranges,include_artifacts=False); payload.seek(0)
            self.storage.execute(original,'verify',input_file=payload,include_artifacts=False)
        if self.game=='dependency-hell' and target_live:
            # The source immutable set is pinned before any swap. Full business
            # equality protects newly committed PostgreSQL work as well.
            latest = next(v for v in header['stores'] if v['engine']=='postgresql')
            frozen, _ = s.read_archive(self.state['frozen']['archive_path'],self.game)
            base = next(v for v in frozen['stores'] if v['engine']=='postgresql')
            if latest['business_sha256'] != base['business_sha256']:
                raise s.StorageError('ROLLBACK_WOULD_DISCARD_CURRENT_BUSINESS_ROWS')
        with tempfile.TemporaryFile(dir=self.root) as payload:
            s.sqlite_payload(authority['archive_path'],payload,header,ranges,include_artifacts=False); payload.seek(0)
            self.storage.execute(original,'revoke_sessions',input_file=payload,include_artifacts=False)
        self.save('rollback_swap_intent')
        self.postgres_switch(False)
        if self.game=='dependency-hell': self.sync_pg_authority(authority)
        self.templates(False); self.remove_workers(); self.scale(False)
        source=self.wait_ready(False)
        result=self.validate(source,authority)
        result['automatic_rollback']=True
        return self.finish(False,result)

    def sync_pg_authority(self, authority):
        header,ranges=s.read_archive(authority['archive_path'],self.game,expected_hash=authority['archive_sha256'])
        before=s.pg_metadata(self.kube,s.PG_DATABASE)
        with tempfile.TemporaryDirectory(dir=self.root) as folder:
            folder=Path(folder); dump=s.extract_postgres(authority['archive_path'],ranges,folder/'authority.dump'); sql=folder/'auth.sql'
            with sql.open('xb') as output, dump.open('rb') as stream:
                os.chmod(sql,0o600)
                output.write(b'BEGIN;TRUNCATE public.sessions;TRUNCATE public.dependency_hell_snapshot_hmac_keys,public.dependency_hell_submission_transition_hmac_keys;\n');output.flush()
                command='''set -eu
umask 077
folder=$(mktemp -d /tmp/msgctf-storage-auth-XXXXXX)
trap 'rm -f -- "$folder/archive.dump"; rmdir -- "$folder"' EXIT HUP INT TERM
head -c "$1" > "$folder/archive.dump"
actual=$(sha256sum "$folder/archive.dump")
test "${actual%% *}" = "$2"
pg_restore --file=- --data-only --table=dependency_hell_snapshot_hmac_keys --table=dependency_hell_submission_transition_hmac_keys "$folder/archive.dump"
'''
                self.kube.run(['exec','-i','-n',s.PG_NAMESPACE,'deployment/'+s.PG_DEPLOYMENT,'-c',s.PG_CONTAINER,'--',
                               'timeout','-k','5','90','sh','-c',command,'sh',str(dump.stat().st_size),s.sha256(dump)],input_file=stream,output_file=output,timeout=105)
                output.write(b'\nCOMMIT;\n')
            with sql.open('rb') as stream: s.pg_command(self.kube,'sql',input_file=stream)
        after=s.pg_metadata(self.kube,s.PG_DATABASE)
        expected=next(v for v in header['stores'] if v['engine']=='postgresql')
        if (after['business_sha256']!=before['business_sha256'] or after['auth_history_sha256']!=expected['auth_history_sha256']
                or after['table_row_counts'].get('sessions',0)):
            raise s.StorageError('RESTORE_VERIFICATION_FAILED')

    def recover(self):
        if not self.state: return self.status()
        if self.state.get('phase') in TERMINAL:
            if self.active.exists() and self.read(self.active).get('operation_id')==self.operation_id: self.active.unlink()
            return self.status()
        if self.state.get('phase')=='planned': return self.status()
        try:
            if self.state.get('decision') in {'commit','rollback_publish'}:
                forward=self.state['decision']=='commit'
                # No stale rollback is allowed after the first public route may
                # have opened. Preserve the active PVC and finish publication.
                self.wait_ready(forward)
                return self.finish(forward,self.state['result'])
            return self.rollback()
        except Exception as error:
            self.save('needs_recovery',error_code=str(error) if isinstance(error,s.StorageError) else 'CUTOVER_RECOVERY_FAILED')
            raise

    def retire_failed(self):
        if self.state.get('phase')!='rolled_back' or self.active.exists():
            raise s.StorageError('ONLY_INACTIVE_FAILED_CANDIDATE_CAN_BE_RETIRED')
        name=self.state['candidate_pvc_name']
        objects=self.kube.json(['get','pods,deployments,statefulsets,daemonsets,jobs,cronjobs','-n',self.profile['namespace']])['items']
        def referenced(value):
            if isinstance(value,dict):
                return value.get('persistentVolumeClaim',{}).get('claimName')==name or any(referenced(v) for v in value.values())
            return isinstance(value,list) and any(referenced(v) for v in value)
        if any(referenced(v) for v in objects): raise s.StorageError('CANDIDATE_VOLUME_STILL_REFERENCED')
        if self.game=='dependency-hell':
            dbs=pg_databases(self.kube);candidate=self.state['postgres_candidate_database']
            if dbs.get(s.PG_DATABASE,{}).get('database_oid')!=self.state['postgres_original_oid']:
                raise s.StorageError('POSTGRES_SWAP_CONFLICT')
            if candidate in dbs:
                value=dbs[candidate]
                if (value['marker']!='msgctf-koth-storage:'+self.operation_id
                        or self.state.get('postgres_candidate_oid') and value['database_oid']!=self.state['postgres_candidate_oid']):
                    raise s.StorageError('POSTGRES_CLEANUP_SCOPE_CHANGED')
                pg_control(self.kube,'DROP DATABASE '+sql_identifier(candidate)+' WITH (FORCE);')
        pvc=self.kube.json(['get','pvc',name,'-n',self.profile['namespace']],optional=True)
        if pvc:
            if (pvc['metadata']['uid']!=self.state.get('candidate_pvc_uid')
                    or pvc['metadata'].get('labels',{}).get('msgctf.io/storage-operation')!=self.operation_id):
                raise s.StorageError('CLEANUP_SCOPE_CHANGED')
            options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':pvc['metadata']['uid']}}
            self.kube.run(['delete','--raw','/api/v1/namespaces/'+self.profile['namespace']+'/persistentvolumeclaims/'+name,'-f','-'],data=s.canonical(options))
            self.kube.run(['wait','--for=delete','pvc/'+name,'-n',self.profile['namespace'],'--timeout=120s'],timeout=125)
        self.save(failed_candidate_retired=True)
        return self.status()

    def run(self):
        if not self.state: raise s.StorageError('CUTOVER_PLAN_REQUIRED')
        if self.state['phase'] != 'planned': return self.recover()
        self.preflight()
        try:
            self.freeze(); self.fail('after_freeze')
            self.prepare(); self.fail('after_restore')
            self.save('pvc_switch_intent'); self.templates(True); self.fail('after_pvc_switch')
            self.save('postgres_swap_intent'); self.postgres_switch(True); self.fail('after_pg_swap')
            self.remove_workers(); self.save('application_start_intent'); self.scale(False)
            source=self.wait_ready(True); self.save('ready'); self.fail('after_ready')
            result=self.validate(source)
            return self.finish(True,result)
        except Exception as error:
            self.save(error_code=str(error) if isinstance(error,s.StorageError) else 'CUTOVER_FAILED')
            return self.recover()


def installation():
    config_path=Path('/etc/msgctf-koth-storage/config.json');s.private_file(config_path)
    config=json.loads(config_path.read_text()); directory=Path(__file__).resolve().parent
    expected={'koth_storage.py','koth_storage_worker.py','koth_storage_worker.cjs','koth_core_egress.py','koth_storage_artifacts.py','koth_storage_cutover.py'}
    if (directory.name!=config.get('source_sha') or set(config.get('files',{}))!=expected
            or any(s.sha256(directory/name)!=digest for name,digest in config['files'].items())):
        raise s.StorageError('INSTALLED_SOURCE_CHANGED')
    return config


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['start','run','recover','status','retire-failed'])
    parser.add_argument('--game',choices=sorted(s.PROFILES))
    parser.add_argument('--operation-id')
    parser.add_argument('--actor',default='automatic-recovery')
    parser.add_argument('--archive',type=Path);parser.add_argument('--sha256')
    parser.add_argument('--fault',choices=FAULTS,default='none')
    args=parser.parse_args()
    if not hasattr(os,'geteuid') or os.geteuid()!=0:raise s.StorageError('ROOT_LINUX_CONTROLLER_REQUIRED')
    config=installation();game=args.game or config['game']
    if game!=config['game']:raise s.StorageError('HOST_GAME_SCOPE_MISMATCH')
    operation=args.operation_id
    if not operation:
        active=s.ROOT/'active-cutover.json'
        if args.action!='recover' or not active.exists():
            if args.action=='recover': print(json.dumps({'phase':'idle','game':game}));return
            raise s.StorageError('INVALID_OPERATION_ID')
        operation=Cutover.read(active)['operation_id']
    storage=s.Storage(game,operation,args.actor)
    if args.action=='status':
        print(json.dumps({**Cutover(storage).status(),'tool_source_sha':config['source_sha']}));return
    with s.operation_lock(storage.root,game):
        task=Cutover(storage)
        if args.action=='start':
            task.plan(args.archive,args.sha256,args.fault)
            if task.state['phase'] in TERMINAL:print(json.dumps(task.status()));return
            exe='/usr/local/sbin/msgctf-koth-cutover'
            stop=exe+' recover --game '+game+' --operation-id '+operation
            command=['systemd-run','--quiet','--no-block','--collect','--unit=msgctf-koth-cutover-'+operation,
                     '--property=Type=oneshot','--property=TimeoutStartSec=2400','--property=ExecStopPost='+stop,
                     exe,'run','--game',game,'--operation-id',operation,'--actor',args.actor]
            task.system(command)
            print(json.dumps({'phase':'dispatched','game':game,'operation_id':operation}));return
        result=task.run() if args.action=='run' else task.recover() if args.action=='recover' else task.retire_failed()
        print(json.dumps({**result,'tool_source_sha':config['source_sha']}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        code=str(error) if isinstance(error,s.StorageError) else 'CUTOVER_OPERATION_FAILED'
        sys.stderr.write(json.dumps({'error_code':code})+'\n');raise SystemExit(1) from None
