#!/usr/bin/env python3
"""Add narrowly scoped KOTH routes to the migrated Core HTTPS gateway."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid

BEGIN = '    # MSGCTF_KOTH_INTERNAL_BEGIN\n'
END = '    # MSGCTF_KOTH_INTERNAL_END\n'
ANCHOR = '    location @callback_denied { return 404; }'
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'


def render(original, addresses):
    sources = sorted({str(ipaddress.IPv4Address(value)) for value in addresses})
    if not 1 <= len(sources) <= 16 or any('/' in value for value in addresses):
        raise ValueError('EXACT_IPV4_SOURCES_REQUIRED')
    if original.count(ANCHOR) != 1 or 'location /internal/ { return 404; }' not in original:
        raise ValueError('EXPECTED_INTERNAL_DENY_GATEWAY_REQUIRED')
    locations = ['= /internal/koth/team_tokens/verify', '= /internal/teams',
                 '~ "^/internal/v1/koth_environments/' + UUID + '(?:/(?:status|image_export))?$"']
    blocks = []
    for location in locations:
        # Use the raw URI guard too: nginx normalizes escapes before location matching.
        lines = ['    location ' + location + ' {',
                 '        if ($request_uri ~* "%|\\\\\\\\|//|/\\\\.\\\\.(?:/|\\\\?|$)") { return 404; }',
                 '        error_page 403 =404 @callback_denied;']
        lines += ['        allow ' + address + '/32;' for address in sources]
        lines += ['        deny all;', '        client_max_body_size 64k;',
                  '        set $koth_backend http://backend:8080;',
                  '        proxy_pass $koth_backend$request_uri;',
                  '        proxy_set_header Host msgctf.kr;',
                  '        proxy_set_header X-Forwarded-Proto https;',
                  '        proxy_set_header X-Forwarded-For $remote_addr;',
                  '        proxy_set_header X-Real-IP $remote_addr;',
                  '        proxy_set_header Connection "";',
                  '        proxy_http_version 1.1;',
                  '        proxy_connect_timeout 3s;',
                  '        proxy_read_timeout 30s;', '    }']
        blocks.append('\n'.join(lines) + '\n')
    block = BEGIN + ''.join(blocks) + END
    if BEGIN in original or END in original:
        if original.count(BEGIN) != 1 or original.count(END) != 1 or block not in original:
            raise ValueError('MANAGED_KOTH_ROUTE_DRIFT')
        return original
    return original.replace(ANCHOR, block + ANCHOR)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def atomic(path, raw, mode):
    fd, name = tempfile.mkstemp(prefix='.koth-gateway-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def nginx(gateway, action):
    p = subprocess.run(['docker', 'exec', gateway, 'nginx', '-c', '/etc/ctf-https/nginx.conf', *action],
                       capture_output=True, timeout=20)
    if p.returncode:
        raise RuntimeError('GATEWAY_NGINX_COMMAND_FAILED')


def replace_and_reload(path, original, candidate, mode, gateway):
    atomic(path, candidate, mode)
    try:
        nginx(gateway, ['-t'])
        nginx(gateway, ['-s', 'reload'])
    except Exception:
        atomic(path, original, mode)
        nginx(gateway, ['-t'])
        nginx(gateway, ['-s', 'reload'])
        raise RuntimeError('GATEWAY_UPDATE_FAILED_ROLLBACK_VERIFIED') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/opt/ctf-external/https/config/nginx.conf')
    parser.add_argument('--gateway', default='ctf-external-https-gateway-1')
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--allow-source', action='append', required=True)
    parser.add_argument('--operation-id', required=True)
    parser.add_argument('--actor', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('ROOT_OPERATOR_REQUIRED')
    if str(uuid.UUID(args.operation_id)) != args.operation_id or not re.fullmatch(r'[a-zA-Z0-9_.@-]{1,80}', args.actor):
        raise ValueError('INVALID_OPERATION_ID_OR_ACTOR')
    if not re.fullmatch(r'[a-f0-9]{64}', args.expected_sha256) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}', args.gateway):
        raise ValueError('INVALID_CONFIG_DIGEST_OR_CONTAINER')
    path = Path(args.config)
    info = path.lstat()
    if not path.is_absolute() or path.resolve() != path or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('ROOT_OWNED_CONFIG_REQUIRED')
    import fcntl
    lock = os.open('/run/lock/msgctf-koth-core-gateway.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw = path.read_bytes()
        if digest(raw) != args.expected_sha256:
            raise ValueError('GATEWAY_CONFIG_CHANGED')
        container = json.loads(subprocess.check_output(['docker', 'inspect', args.gateway]))[0]
        if not any(m['Type'] == 'bind' and m['Source'] == str(path.parent) and m['Destination'] == '/etc/ctf-https' for m in container['Mounts']):
            raise ValueError('GATEWAY_CONFIG_MOUNT_MISMATCH')
        candidate = render(raw.decode('utf-8'), args.allow_source).encode('utf-8')
        proof = {'operation_id': args.operation_id, 'actor': args.actor, 'before_sha256': digest(raw),
                 'after_sha256': digest(candidate), 'allowed_source_ipv4': sorted(set(args.allow_source)),
                 'internal_default_deny_preserved': True, 'action': 'apply' if args.apply else 'plan',
                 'gateway_image_id': container['Image'], 'gateway_uid': container['Id'],
                 'config_path': str(path), 'changed': raw != candidate}
        if args.apply:
            nginx(args.gateway, ['-t'])
            if raw == candidate:
                proof.update(configuration_test_passed=True, idempotent_noop=True, graceful_reload=False)
                print(json.dumps(proof, sort_keys=True))
                return
            root = Path('/var/lib/msgctf-koth-core-gateway') / args.operation_id
            root.mkdir(parents=True, mode=0o700, exist_ok=True)
            if root.is_symlink() or root.stat().st_uid != 0 or root.stat().st_mode & 0o077:
                raise ValueError('ROOT_ONLY_CASE_REQUIRED')
            backup = root / 'nginx.before.conf'
            if not backup.exists():
                fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
            if backup.is_symlink() or backup.read_bytes() != raw:
                raise ValueError('CASE_BACKUP_MISMATCH')
            if path.read_bytes() != raw:
                raise ValueError('GATEWAY_CONFIG_CHANGED')
            replace_and_reload(path, raw, candidate, stat.S_IMODE(info.st_mode), args.gateway)
            proof.update(configuration_test_passed=True, graceful_reload=True, rollback_backup=str(backup))
            atomic(root / 'result.json', json.dumps(proof, sort_keys=True).encode(), 0o400)
        print(json.dumps(proof, sort_keys=True))
    finally:
        os.close(lock)


if __name__ == '__main__':
    main()
