#!/usr/bin/env python3
"""Fixed-command SSH helper for one exclusive VM. No secrets in replies or logs."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.request import Request, urlopen

BASE = Path('/var/lib/msgctf-vm')
RUN = Path('/run/msgctf-vm')
PROFILES = Path('/etc/msgctf-vm/profiles')
OWNER = BASE / 'owner.json'


class Rejected(Exception):
    def __init__(self, code): self.code = code


def command(args, timeout=30):
    p = subprocess.run(args, capture_output=True, timeout=timeout)
    if p.returncode:
        raise Rejected('VM_DOCKER_FAILED')
    return p.stdout


def docker(args, timeout=30):
    return command(['docker'] + args, timeout)


def atomic(path, obj):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        os.chmod(tmp, 0o600)
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def validate_identity(req):
    for key in ('instance_id', 'team_id'):
        value = uuid.UUID(req[key])
        if value.int == 0 or str(value) != req[key]: raise Rejected('VM_IDENTITY_INVALID')
    if not re.fullmatch('[a-f0-9]{64}', req.get('uid', '')): raise Rejected('VM_IDENTITY_INVALID')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', req.get('target_id', '')): raise Rejected('VM_IDENTITY_INVALID')


def same_owner(first, second):
    return all(first.get(key) == second.get(key) for key in ('instance_id', 'team_id', 'uid', 'target_id'))


def project(req): return 'ctf-' + req['instance_id'].replace('-', '')


def owned_ids(kind, req):
    args = [kind, 'ls', '-q', '--filter', 'label=msgctf.io/instance-id=' + req['instance_id']]
    if kind == 'container': args.append('-a')
    result = docker(args).decode().split()
    for ident in result:
        obj = json.loads(docker([kind, 'inspect', ident]))[0]
        labels = obj.get('Config', {}).get('Labels', {}) if kind == 'container' else obj.get('Labels', {})
        if any(labels.get('msgctf.io/' + name.replace('_', '-')) != req[name] for name in ('instance_id', 'team_id', 'uid', 'target_id')):
            raise Rejected('RUNTIME_OWNERSHIP_MISMATCH')
    return result


def cleanup(req):
    # Validate ALL objects before the first deletion; do not remove someone else's resource.
    containers = owned_ids('container', req)
    networks = owned_ids('network', req)
    volumes = owned_ids('volume', req)
    if containers: docker(['container', 'rm', '-f'] + containers, 60)
    if networks: docker(['network', 'rm'] + networks)
    if volumes: docker(['volume', 'rm'] + volumes)
    if any(owned_ids(kind, req) for kind in ('container', 'network', 'volume')): raise Rejected('VM_DELETE_INCOMPLETE')
    temp = RUN / req['instance_id']
    if temp.exists(): shutil.rmtree(temp)


def load_profile(sha):
    if not re.fullmatch('[a-f0-9]{64}', sha): raise Rejected('VM_PROFILE_INVALID')
    path = PROFILES / (sha + '.json')
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022: raise Rejected('VM_PROFILE_INVALID')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha: raise Rejected('VM_PROFILE_INVALID')
    profile=json.loads(raw)
    for service in profile['compose']['services'].values():
        if (service.get('privileged') or service.get('network_mode') or service.get('pid') or service.get('devices')
                or service.get('volumes') or service.get('build') or service.get('env_file')
                or service.get('cgroup_parent')!='msg-afterimage.slice' or service.get('storage_opt')!={'size':'250M'}):
            raise Rejected('VM_PROFILE_INVALID')
    for network in profile['compose']['networks'].values():
        if network.get('external') or network.get('name'): raise Rejected('VM_PROFILE_INVALID')
    return profile


def require_storage_quota():
    info = json.loads(docker(['info', '--format', '{{json .}}']))
    quota = command(['xfs_quota', '-x', '-c', 'state -p', info['DockerRootDir']])
    if info['Driver'] != 'overlay2' or b'Enforcement: ON' not in quota:
        raise Rejected('VM_QUOTA_UNAVAILABLE')


def states(req):
    out = []
    for ident in owned_ids('container', req):
        obj = json.loads(docker(['container', 'inspect', ident]))[0]
        state = obj['State']
        health = state.get('Health', {}).get('Status')
        out.append({'name': obj['Config']['Labels']['com.docker.compose.service'],
                    'running': state.get('Running', False),
                    'ready': state.get('Running', False) and not state.get('OOMKilled') and health in (None, 'healthy'),
                    'restarts': obj.get('RestartCount', 0)})
    return sorted(out, key=lambda x: x['name'])


def status(req, owner):
    if owner.get('state') == 'deleted': return {'ok': True, 'deleted': True, 'ready': False, 'containers': []}
    rows = states(req)
    ready = len(rows) == len(owner['services']) and all(row['ready'] for row in rows)
    if ready:
        health=load_profile(owner['profile_sha256'])['public_readiness']
        try:
            with urlopen('http://127.0.0.1:'+str(health['port'])+health['path'],timeout=2) as response:
                ready=response.status==200
        except OSError: ready=False
    return {'ok': True, 'ready': ready, 'deleted': False, 'containers': rows}


def create(req, owner):
    profile = load_profile(req['profile_sha256'])
    require_storage_quota()
    if req['target_id'] != profile['target_id']: raise Rejected('VM_PROFILE_INVALID')
    if owner:
        if not same_owner(req, owner):
            if any(owned_ids(kind, req) for kind in ('container', 'network', 'volume')): raise Rejected('VM_BUSY')
            return {'ok': False, 'code': 'VM_BUSY', 'cleanup_completed': True}
        if owner['profile_sha256'] != req['profile_sha256']: raise Rejected('VM_PROFILE_INVALID')
        if owner['state'] == 'deleted': raise Rejected('VM_INSTANCE_TOMBSTONED')
        current = status(req, owner)
        if current['ready']: return current
    if (BASE / 'tombstones' / (req['instance_id'] + '.json')).exists(): raise Rejected('VM_INSTANCE_TOMBSTONED')
    cfg = copy.deepcopy(profile['compose'])
    values = req['env']
    if set(values) != set(cfg['services']): raise Rejected('ENVIRONMENT_MISMATCH')
    if Path('/run').stat().st_dev == Path('/').stat().st_dev: raise Rejected('VM_TMPFS_REQUIRED')
    label = {'msgctf.io/' + key.replace('_', '-'): req[key] for key in ('instance_id', 'team_id', 'uid', 'target_id')}
    for name, service in cfg['services'].items():
        env = values[name]
        if set(env) != set(profile['env_names'][name]): raise Rejected('ENVIRONMENT_MISMATCH')
        if len(env) > 128 or any(not re.fullmatch('[A-Z_][A-Z0-9_]{0,63}', k) or not isinstance(v, str) or len(v.encode()) > 4096 or '\0' in v for k,v in env.items()): raise Rejected('ENVIRONMENT_MISMATCH')
        # Compose interpolates even JSON string values. Escape dollar signs literally.
        service['environment'] = {k:v.replace('$', '$$') for k,v in env.items()}
        service['labels'] = dict(service.get('labels', {}), **label)
        # All images are prefetched by an operator. No guest has registry credentials.
        info = json.loads(docker(['image', 'inspect', service['image']]))[0]
        if service['image'] not in info.get('RepoDigests', []): raise Rejected('VM_IMAGE_NOT_AVAILABLE')
    for spec in cfg['networks'].values(): spec['labels'] = dict(spec.get('labels', {}), **label)
    for spec in cfg.get('volumes', {}).values(): spec['labels'] = dict(spec.get('labels', {}), **label)
    owner = {key:req[key] for key in ('instance_id', 'team_id', 'uid', 'target_id', 'profile_sha256')}
    owner.update(state='creating', services=sorted(cfg['services']))
    atomic(OWNER, owner)
    directory = RUN / req['instance_id']
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / 'compose.json'
    atomic(path, cfg)
    try:
        docker(['compose', '-p', project(req), '-f', str(path), 'up', '-d', '--no-build', '--pull', 'never'], 80)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            answer = status(req, owner)
            if answer['ready']:
                owner['state'] = 'ready'
                atomic(OWNER, owner)
                return answer
            time.sleep(1)
        raise Rejected('VM_READY_TIMEOUT')
    except BaseException:
        cleanup(req)
        owner['state'] = 'deleted'
        atomic(BASE / 'tombstones' / (req['instance_id'] + '.json'), owner)
        OWNER.unlink()
        return {'ok': False, 'code': 'VM_CREATE_FAILED', 'cleanup_completed': True}


def dispatch(req):
    if req.get('action') == 'observe': return observe(req)
    validate_identity(req)
    owner = json.loads(OWNER.read_text()) if OWNER.exists() else None
    action = req['action']
    if action == 'create': return create(req, owner)
    if action not in ('delete', 'status'): raise Rejected('VM_ACTION_INVALID')
    if owner and not same_owner(owner, req): raise Rejected('RUNTIME_OWNERSHIP_MISMATCH')
    if not owner:
        tombstone = BASE / 'tombstones' / (req['instance_id'] + '.json')
        if tombstone.exists() and not same_owner(req, json.loads(tombstone.read_text())): raise Rejected('RUNTIME_OWNERSHIP_MISMATCH')
        # Absence is only success after checking there are no leftover owned objects.
        if action == 'delete':
            cleanup(req)
            atomic(tombstone, dict(req, state='deleted'))
        return {'ok': True, 'deleted': True, 'ready': False, 'containers': []}
    if action == 'status': return status(req, owner)
    cleanup(req)
    owner['state'] = 'deleted'
    atomic(BASE / 'tombstones' / (req['instance_id'] + '.json'), owner)
    OWNER.unlink()
    return {'ok': True, 'deleted': True, 'ready': False, 'containers': []}


def observe(req):
    start=datetime.now(timezone.utc).isoformat()
    profile=load_profile(req['profile_sha256'])
    if req.get('target_id') != profile['target_id']: raise Rejected('VM_PROFILE_INVALID')
    with urlopen(Request('http://169.254.169.254/computeMetadata/v1/instance/id',headers={'Metadata-Flavor':'Google'}),timeout=2) as r: instance=r.read().decode()
    require_storage_quota()
    owner=json.loads(OWNER.read_text()) if OWNER.exists() else None
    limits=profile['resource_limits']
    def cpu(): return [int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
    a=cpu();time.sleep(0.1);b=cpu();total=sum(b)-sum(a);idle=(b[3]+b[4])-(a[3]+a[4])
    used_cpu=round((total-idle)/total*(os.cpu_count() or 1)*1000) if total else 0
    memory={row.split(':')[0]:int(row.split()[1]) for row in Path('/proc/meminfo').read_text().splitlines()}
    allocated=limits if owner else {key:0 for key in limits}
    return {'ok':True,'provider_instance_id':instance,'target_id':req['target_id'],'observed_at':start,
      'ready':not owner or owner.get('profile_sha256')==req['profile_sha256'],
      'node_allocatable':limits,'allocated_requests':allocated,
      'node_usage':{'cpu_millicores':used_cpu,'memory_mib':(memory['MemTotal']-memory['MemAvailable'])//1024}}


def main():
    os.umask(0o077)
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    RUN.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (BASE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            raw = sys.stdin.buffer.read((128 << 10) + 1)
            if len(raw) > 128 << 10: raise Rejected('VM_REQUEST_TOO_LARGE')
            req=json.loads(raw)
            if '--observe-only' in sys.argv and req.get('action')!='observe': raise Rejected('VM_ACTION_INVALID')
            result = dispatch(req)
        except Rejected as error: result = {'ok': False, 'code': error.code}
        except BaseException: result = {'ok': False, 'code': 'VM_AGENT_FAILED'}
        print(json.dumps(result))


if __name__ == '__main__': main()
