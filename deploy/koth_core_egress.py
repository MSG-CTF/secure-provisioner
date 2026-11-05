#!/usr/bin/env python3
"""Move existing KOTH Core-only HTTPS egress rules to a verified Core address."""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import sys

from koth_storage import (PROFILES, Storage, StorageError, canonical, operation_lock,
                          private_file, sha256, action_audit)


def address(value):
    try: result = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError: raise StorageError('PUBLIC_IPV4_REQUIRED') from None
    if not result.is_global: raise StorageError('PUBLIC_IPV4_REQUIRED')
    return str(result)


def core_health(ip):
    connection = http.client.HTTPSConnection('msgctf.kr', 443, timeout=10, context=ssl.create_default_context())
    # Pin transport to the operator-supplied address, retaining TLS SNI/hostname checks.
    connection._create_connection = lambda *_args, **_kwargs: socket.create_connection((ip, 443), timeout=10)
    try:
        connection.request('GET', '/healthz', headers={'Host': 'msgctf.kr'})
        response = connection.getresponse(); payload = response.read(8193)
        if response.status != 200 or len(payload) > 8192: raise StorageError('CORE_HEALTH_FAILED')
        data = json.loads(payload)
        if any(data.get(k) != 'ok' for k in ('status', 'database', 'cache')): raise StorageError('CORE_HEALTH_FAILED')
        return {'http': 200, 'tls_hostname': 'msgctf.kr', 'address': ip, 'database': 'ok', 'cache': 'ok'}
    finally:
        connection.close()


def policy_change(policy, previous, target):
    """Never add a policy, broaden ports, or alter ingress/unrelated peers."""
    after = copy.deepcopy(policy['spec']); edits = []
    for rule_index, rule in enumerate(after.get('egress', [])):
        ports = rule.get('ports', [])
        if len(ports) != 1 or ports[0].get('port') != 443 or ports[0].get('protocol', 'TCP') != 'TCP': continue
        for peer_index, peer in enumerate(rule.get('to', [])):
            if set(peer) != {'ipBlock'} or peer['ipBlock'] != {'cidr': previous + '/32'}: continue
            peer['ipBlock']['cidr'] = target + '/32'
            edits.append({'op': 'replace', 'path': f'/spec/egress/{rule_index}/to/{peer_index}/ipBlock/cidr', 'value': target + '/32'})
    if not edits: return None
    meta = policy['metadata']
    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': meta['uid']},
             {'op': 'test', 'path': '/metadata/resourceVersion', 'value': meta['resourceVersion']},
             {'op': 'test', 'path': '/spec', 'value': policy['spec']}, *edits]
    return {'name': meta['name'], 'uid': meta['uid'], 'patch': patch, 'after_spec': after,
            'before_spec_sha256': hashlib.sha256(canonical(policy['spec'])).hexdigest(),
            'after_spec_sha256': hashlib.sha256(canonical(after)).hexdigest(), 'rule_count': len(edits)}


def move(storage, previous, target, apply=False):
    previous, target = address(previous), address(target)
    if previous == target: raise StorageError('DISTINCT_ADDRESSES_REQUIRED')
    health = core_health(target)
    namespace = PROFILES[storage.game]['namespace']
    policies = storage.kube.json(['get', 'networkpolicies', '-n', namespace])['items']
    changes = [change for p in policies if (change := policy_change(p, previous, target))]
    result = {'game': storage.game, 'namespace': namespace, 'previous_address': previous, 'address': target,
              'core_health': health, 'action': 'apply' if apply else 'plan',
              'changes': [{k: v for k, v in c.items() if k != 'patch'} for c in changes],
              'created_policy_count': 0, 'unrelated_rules_preserved': True}
    # Durable plan precedes every mutation, allowing inspection of partial progress.
    storage.save({'phase': 'core_egress_planned', 'result': result})
    if apply:
        for change in changes:
            raw = storage.kube.run(['patch', 'networkpolicy', change['name'], '-n', namespace,
                '--type=json', '--patch', canonical(change['patch']).decode(), '-o', 'json'])
            updated = json.loads(raw)
            if updated['metadata']['uid'] != change['uid'] or updated['spec'] != change['after_spec']:
                raise StorageError('CORE_POLICY_READBACK_MISMATCH')
            change['applied'] = True
            storage.save({'phase': 'core_egress_applying', 'result': {**result,
                'applied_policy_names': [c['name'] for c in changes if c.get('applied')]}})
        # Persistent operator pin is independent of game image/Pod redeployment.
        pin = storage.root / ('core-endpoint-' + storage.game + '.json')
        fd = os.open(pin, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(canonical({'hostname': 'msgctf.kr', 'address': target, 'operation_id': storage.operation_id}))
            output.flush(); os.fsync(output.fileno())
    result['applied_policy_count'] = len(changes) if apply else 0
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'apply'])
    parser.add_argument('--game', required=True, choices=sorted(PROFILES))
    parser.add_argument('--previous-address', required=True)
    parser.add_argument('--address', required=True)
    parser.add_argument('--operation-id', required=True)
    parser.add_argument('--actor', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0: raise StorageError('ROOT_LINUX_CONTROLLER_REQUIRED')
    config_path = Path('/etc/msgctf-koth-storage/config.json'); private_file(config_path)
    config = json.loads(config_path.read_text()); directory = Path(__file__).resolve().parent
    if (config['game'] != args.game or directory.name != config['source_sha']
            or sha256(Path(__file__)) != config['files'].get('koth_core_egress.py')
            or any(sha256(directory / n) != digest for n, digest in config['files'].items())):
        raise StorageError('INSTALLED_SOURCE_CHANGED')
    storage = Storage(args.game, args.operation_id, args.actor)
    with operation_lock(storage.root, args.game), action_audit(storage, 'core_egress_' + args.action):
        result = move(storage, args.previous_address, args.address, args.action == 'apply')
        output = {'format_version': 1, 'operation_id': args.operation_id, 'actor': args.actor,
                  'tool_source_sha': config['source_sha'], **result}
        storage.save({'phase': 'complete', 'result': output}); print(json.dumps(output))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        sys.stderr.write(json.dumps({'error_code': str(error) if isinstance(error, StorageError) else 'CORE_EGRESS_FAILED'}) + '\n')
        raise SystemExit(1) from None
