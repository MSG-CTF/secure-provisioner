#!/usr/bin/env python3
"""Bootstrap preapproved idle K3s nodes before image-agent enrollment.

Run on the trusted control host after the Broker has drained the exact targets.
Registry credentials are read from a protected file, sent over the authenticated
Kubernetes connection, and retained only in the node's root-only K3s registry
configuration. No credential is included in a command argument or report.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

try:
    from . import image_prefetch_enroll as enrollment
except ImportError:
    import image_prefetch_enroll as enrollment

MAINTENANCE_IMAGE = 'docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
NAMESPACE = 'runtime-image-bootstrap'
OWNER = 'image-preparation-bootstrap-v1'


class BootstrapError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise BootstrapError(code)


def decode_registry(raw):
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        try:
            import yaml
            value = yaml.safe_load(raw)
        except ImportError:
            raise BootstrapError('YAML_SUPPORT_UNAVAILABLE') from None
        except Exception:
            raise BootstrapError('INVALID_REGISTRY_CONFIG') from None
    require(isinstance(value, dict), 'INVALID_REGISTRY_CONFIG')
    return value


def registry_configuration(original, credential):
    require(isinstance(original, dict) and isinstance(credential, dict), 'INVALID_REGISTRY_CONFIG')
    require(set(credential) == {'username', 'password'}, 'INVALID_REGISTRY_CREDENTIAL')
    require(all(isinstance(v, str) and 1 <= len(v) <= 8192 and not any(c in v for c in '\r\n\x00')
                for v in credential.values()), 'INVALID_REGISTRY_CREDENTIAL')
    updated = copy.deepcopy(original)
    require(isinstance(updated.get('configs', {}), dict), 'INVALID_REGISTRY_CONFIG')
    configs = updated.setdefault('configs', {})
    require(isinstance(configs.get('ghcr.io', {}), dict), 'INVALID_REGISTRY_CONFIG')
    configs.setdefault('ghcr.io', {})['auth'] = dict(credential)
    return updated


def verify_idle(pods):
    require(isinstance(pods, list), 'INVALID_POD_INVENTORY')
    for pod in pods:
        meta = pod.get('metadata', {})
        namespace = meta.get('namespace', '')
        if namespace.startswith('ctf-'):
            # A terminal or terminating challenge still has resources to clean.
            raise BootstrapError('CHALLENGE_RESOURCES_PRESENT')


def verify_probe(pod, node, image):
    require(pod.get('metadata', {}).get('labels', {}).get('msgctf.bootstrap') == OWNER, 'PROBE_OWNER_MISMATCH')
    spec = pod.get('spec', {})
    containers = spec.get('containers', [])
    require(spec.get('nodeName') == node['node_name'] and len(containers) == 1, 'PROBE_NODE_MISMATCH')
    require(containers[0].get('image') == image and containers[0].get('imagePullPolicy') == 'Always', 'PROBE_NOT_FRESH')
    states = pod.get('status', {}).get('containerStatuses', [])
    require(len(states) == 1 and states[0].get('ready') is True and 'running' in states[0].get('state', {}), 'REGISTRY_PULL_NOT_READY')
    digest = image.rsplit('@', 1)[1]
    require(states[0].get('imageID', '').endswith('@' + digest), 'REGISTRY_DIGEST_MISMATCH')


def verify_identity(node, expected):
    try:
        enrollment.verify_node(node, expected, require_agent_label=False)
    except enrollment.EnrollmentError:
        raise BootstrapError('NODE_IDENTITY_MISMATCH') from None
    require(node.get('metadata', {}).get('uid') == expected['target_id'], 'NODE_TARGET_MISMATCH')


class Client:
    def __init__(self, kubeconfig, binary='/usr/local/bin/k3s'):
        require(Path(binary).is_absolute(), 'INVALID_KUBERNETES_BINARY')
        self.prefix = [binary, 'kubectl', '--kubeconfig', str(kubeconfig)]

    def call(self, args, body=None, timeout=25):
        try:
            result = subprocess.run(self.prefix + ['--request-timeout='+str(max(5, timeout-2))+'s'] + args,
                                    input=body, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise BootstrapError('KUBERNETES_UNAVAILABLE') from None
        require(result.returncode == 0, 'KUBERNETES_COMMAND_FAILED')
        return result.stdout

    def get(self, kind, name=None, namespace=None, all_namespaces=False, optional=False):
        args = ['get', kind]
        if name:
            args.append(name)
        if namespace:
            args += ['-n', namespace]
        if all_namespaces:
            args.append('-A')
        if optional:
            args.append('--ignore-not-found')
        raw = self.call(args + ['-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    def execute(self, command, body=None, timeout=25):
        return self.call(['exec', '-i', 'registry-admin', '-n', NAMESPACE, '--'] + command, body, timeout)


def maintenance_pod(node):
    return {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': 'registry-admin', 'namespace': NAMESPACE, 'labels': {'msgctf.bootstrap': OWNER}},
            'spec': {'nodeName': node['node_name'], 'hostPID': True, 'automountServiceAccountToken': False,
                     'restartPolicy': 'Never', 'terminationGracePeriodSeconds': 1,
                     'containers': [{'name': 'admin', 'image': MAINTENANCE_IMAGE, 'imagePullPolicy': 'IfNotPresent',
                                     'command': ['/bin/sh', '-ec', 'sleep 900'],
                                     'securityContext': {'privileged': True, 'runAsUser': 0, 'readOnlyRootFilesystem': True},
                                     'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}},
                                     'volumeMounts': [{'name': 'config', 'mountPath': '/host-k3s'}]}],
                     'volumes': [{'name': 'config', 'hostPath': {'path': '/etc/rancher/k3s', 'type': 'Directory'}}]}}


def probe_pod(node, image):
    return {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': 'registry-probe', 'namespace': NAMESPACE, 'labels': {'msgctf.bootstrap': OWNER}},
            'spec': {'nodeName': node['node_name'], 'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                     'terminationGracePeriodSeconds': 1,
                     'containers': [{'name': 'probe', 'image': image, 'imagePullPolicy': 'Always',
                                     'command': ['/bin/sh', '-ec', 'sleep 120'],
                                     'securityContext': {'runAsUser': 10001, 'runAsNonRoot': True, 'allowPrivilegeEscalation': False,
                                                         'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                                     'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}}}]}}


def wait_node(client, expected, timeout=150):
    deadline = time.monotonic() + timeout
    # Do not accept the old API server's Ready status immediately after a
    # nonblocking systemd restart was acknowledged.
    time.sleep(5)
    stable = 0
    while time.monotonic() < deadline:
        try:
            value = client.get('nodes', expected['node_name'])
            verify_identity(value, expected)
            stable += 1
            if stable >= 2:
                return value
        except BootstrapError as error:
            if str(error) == 'NODE_TARGET_MISMATCH':
                raise
            stable = 0
        time.sleep(2)
    raise BootstrapError('NODE_RECOVERY_TIMEOUT')


def remove_owned_namespace(client, uid):
    current = client.get('namespace', NAMESPACE, optional=True)
    if current is None:
        return
    require(current['metadata'].get('labels', {}).get('msgctf.bootstrap') == OWNER and current['metadata']['uid'] == uid,
            'MAINTENANCE_OWNER_MISMATCH')
    options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}}
    client.call(['delete', '--raw', '/api/v1/namespaces/' + NAMESPACE, '-f', '-'], json.dumps(options))
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if client.get('namespace', NAMESPACE, optional=True) is None:
            return
        time.sleep(1)
    raise BootstrapError('MAINTENANCE_CLEANUP_TIMEOUT')


def wait_agent(client, node, timeout=90):
    # The DaemonSet can report a completed zero-pod rollout before it observes
    # the new node label. Require the actual reviewed agent to become Ready.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return enrollment.verify_agent(client.get('pods', namespace=node['namespace']), node)
        except enrollment.EnrollmentError:
            time.sleep(1)
    raise BootstrapError('AGENT_NOT_VERIFIED')


def bootstrap_node(client, node, credential, probe_image, agent_manifest, *, apply=False):
    enrollment.validate_policy({'version': 1, 'nodes': [node]})
    require(node['namespace'] == 'runtime-image-preparation', 'INVALID_AGENT_NAMESPACE')
    require(enrollment.IMAGE.fullmatch(probe_image) is not None, 'INVALID_PROBE_IMAGE')
    before = client.get('nodes', node['node_name'])
    verify_identity(before, node)
    verify_idle(client.get('pods', all_namespaces=True)['items'])
    require(client.get('namespace', NAMESPACE, optional=True) is None, 'MAINTENANCE_ALREADY_EXISTS')
    if not apply:
        return {'target_id': node['target_id'], 'status': 'DRY_RUN', 'node_identity_verified': True, 'idle': True}
    namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NAMESPACE,
                 'labels': {'msgctf.bootstrap': OWNER, 'pod-security.kubernetes.io/enforce': 'privileged'}}}
    client.call(['create', '-f', '-'], json.dumps(namespace))
    namespace_uid = client.get('namespace', NAMESPACE)['metadata']['uid']
    changed = False
    try:
        client.call(['create', '-f', '-'], json.dumps(maintenance_pod(node)))
        client.call(['wait', 'pod/registry-admin', '-n', NAMESPACE, '--for=condition=Ready', '--timeout=60s'], timeout=70)
        raw = client.execute(['/bin/sh', '-ec', 'if [ -f /host-k3s/registries.yaml ]; then cat /host-k3s/registries.yaml; fi'])
        original = decode_registry(raw)
        updated = registry_configuration(original, credential)
        if original != updated:
            # Drain is a caller precondition; recheck workload absence immediately before restart.
            verify_idle(client.get('pods', all_namespaces=True)['items'])
            writer = ('umask 077; test ! -L /host-k3s/registries.yaml; '
                      'if [ -f /host-k3s/registries.yaml ] && [ ! -e /host-k3s/registries.before-image-preparation.yaml ]; then '
                      'cp /host-k3s/registries.yaml /host-k3s/registries.before-image-preparation.yaml; '
                      'chmod 600 /host-k3s/registries.before-image-preparation.yaml; fi; '
                      'cat > /host-k3s/.image-preparation-registry.tmp; chmod 600 /host-k3s/.image-preparation-registry.tmp; '
                      'mv /host-k3s/.image-preparation-registry.tmp /host-k3s/registries.yaml')
            client.execute(['/bin/sh', '-ec', writer], json.dumps(updated) + '\n')
            changed = True
            try:
                client.execute(['/bin/sh', '-ec', 'chroot /proc/1/root /usr/bin/systemctl --no-block restart k3s'])
            except BootstrapError:
                pass  # The accepted restart can close exec before its response arrives.
            wait_node(client, node)
            client.call(['wait', 'pod/registry-admin', '-n', NAMESPACE, '--for=condition=Ready', '--timeout=60s'], timeout=70)
        client.call(['create', '-f', '-'], json.dumps(probe_pod(node, probe_image)))
        client.call(['wait', 'pod/registry-probe', '-n', NAMESPACE, '--for=condition=Ready', '--timeout=90s'], timeout=100)
        verify_probe(client.get('pod', 'registry-probe', namespace=NAMESPACE), node, probe_image)
        rendered = agent_manifest.replace('REPLACE_NODE_NAME', node['node_name']).replace('REPLACE_WITH_REVIEWED_AGENT_IMAGE_AT_SHA256', node['agent_image'])
        agent_namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': node['namespace'],
                           'labels': {'pod-security.kubernetes.io/enforce': 'privileged'}}}
        client.call(['apply', '-f', '-'], json.dumps(agent_namespace))
        client.call(['apply', '--dry-run=server', '-f', '-'], rendered)
        client.call(['apply', '-f', '-'], rendered)
        client.call(['label', 'node', node['node_name'], 'msgctf.io/image-preparation-agent=true', '--overwrite'])
        client.call(['rollout', 'status', 'daemonset/runtime-image-agent', '-n', node['namespace'], '--timeout=90s'], timeout=100)
        wait_agent(client, node)
        return {'target_id': node['target_id'], 'node_name': node['node_name'], 'node_identity_verified': True,
                'registry_configuration_changed': changed, 'fresh_private_pull_verified': True, 'agent_verified': True,
                'credentials_logged': False}
    finally:
        remove_owned_namespace(client, namespace_uid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--kubeconfig', type=Path, required=True)
    parser.add_argument('--registry-auth', type=Path, required=True)
    parser.add_argument('--probe-image', required=True)
    parser.add_argument('--agent-manifest', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(not args.apply or getattr(os, 'geteuid', lambda: -1)() == 0, 'ROOT_REQUIRED')
    policy = enrollment.validate_policy(enrollment.read_json(args.policy))
    require(len(policy['nodes']) == 1, 'EXACTLY_ONE_DRAINED_NODE_REQUIRED')
    source = enrollment.read_bytes(args.kubeconfig)
    kubeconfig = enrollment.KubernetesClient().static_config(source)
    registry = decode_registry(enrollment.read_bytes(args.registry_auth).decode())
    credential = registry.get('configs', {}).get('ghcr.io', {}).get('auth', {})
    registry_configuration({}, credential)
    manifest = enrollment.read_bytes(args.agent_manifest).decode()
    with tempfile.TemporaryDirectory(prefix='image-bootstrap-config-') as directory:
        path = Path(directory)/'config.json'
        with os.fdopen(os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(enrollment.encoded_json(kubeconfig))
        print(json.dumps(bootstrap_node(Client(path), policy['nodes'][0], credential, args.probe_image, manifest, apply=args.apply)))


if __name__ == '__main__':
    try:
        main()
    except (BootstrapError, enrollment.EnrollmentError, OSError, ValueError):
        raise SystemExit('Image preparation bootstrap rejected; keep the target drained and inspect the protected configuration') from None
