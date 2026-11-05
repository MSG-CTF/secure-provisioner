import copy
import json
import unittest
from unittest.mock import patch

import koth_core_egress as endpoint
from koth_storage import StorageError


class CoreEgressTests(unittest.TestCase):
    def policy(self):
        return {'metadata': {'name': 'boundary', 'uid': 'uid', 'resourceVersion': '42'},
                'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [{'ports': [{'port': 8080}]}],
                         'egress': [{'ports': [{'port': 53, 'protocol': 'UDP'}], 'to': [{'ipBlock': {'cidr': '10.0.0.0/8'}}]},
                                    {'ports': [{'port': 443, 'protocol': 'TCP'}], 'to': [{'ipBlock': {'cidr': '34.158.192.98/32'}}, {'ipBlock': {'cidr': '8.8.8.8/32'}}]}]}}

    def test_only_exact_old_core_https_peer_changes_with_uid_and_revision_guards(self):
        before = self.policy(); original = copy.deepcopy(before)
        change = endpoint.policy_change(before, '34.158.192.98', '136.108.97.182')
        self.assertEqual(before, original)
        self.assertEqual(change['after_spec']['ingress'], before['spec']['ingress'])
        self.assertEqual(change['after_spec']['egress'][0], before['spec']['egress'][0])
        self.assertEqual(change['after_spec']['egress'][1]['to'][1], before['spec']['egress'][1]['to'][1])
        self.assertEqual(change['patch'][:2], [{'op': 'test', 'path': '/metadata/uid', 'value': 'uid'}, {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '42'}])
        self.assertEqual(change['patch'][-1]['value'], '136.108.97.182/32')

    def test_no_new_policy_no_port_broadening_and_no_subnet_or_exception_rewrite(self):
        for peer in ({'cidr': '34.158.192.0/24'}, {'cidr': '34.158.192.98/32', 'except': ['34.158.192.98/32']}):
            policy = self.policy(); policy['spec']['egress'][1]['to'][0]['ipBlock'] = peer
            self.assertIsNone(endpoint.policy_change(policy, '34.158.192.98', '136.108.97.182'))
        for ports in ([], [{'port': 443, 'protocol': 'UDP'}], [{'port': 443}, {'port': 5432}]):
            policy = self.policy(); policy['spec']['egress'][1]['ports'] = ports
            self.assertIsNone(endpoint.policy_change(policy, '34.158.192.98', '136.108.97.182'))
        for value in ('127.0.0.1', '10.0.0.1', '::1', '0.0.0.0/0'):
            with self.assertRaises(StorageError): endpoint.address(value)

    def test_plan_has_no_mutation_and_stale_uid_does_not_fall_back_to_apply(self):
        class Kube:
            def json(self, args): return {'items': [CoreEgressTests().policy()]}
            def run(self, *args): raise StorageError('STALE_REVISION')
        class Storage:
            game='jenga';kube=Kube()
            def save(self, value): pass
        with patch.object(endpoint, 'core_health', return_value={'http': 200}):
            result = endpoint.move(Storage(), '34.158.192.98', '136.108.97.182')
            self.assertEqual(result['created_policy_count'], 0)
            with self.assertRaisesRegex(StorageError, 'STALE_REVISION'):
                endpoint.move(Storage(), '34.158.192.98', '136.108.97.182', True)
