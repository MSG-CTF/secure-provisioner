import copy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

import image_preparation_bootstrap as bootstrap
import image_prefetch_enroll as enrollment
from test_image_prefetch_enroll import node as node_fixture

TARGET='de42849c-e0dc-43d4-8e63-9bb2bd056db4'
IMAGE='ghcr.io/msg-ctf/challenges/example/web@sha256:'+'a'*64
AGENT='ghcr.io/msg-ctf/runtime-image-agent@sha256:'+'b'*64
EXPECTED={'target_id':TARGET,'node_name':'runtime-a','machine_id':'machine-a',
          'provider_id':'gce://project/zone/runtime-a','architecture':'AMD64',
          'namespace':'runtime-image-preparation','agent_image':AGENT}


class FakeClient:
    def __init__(self, pods=None, namespace=None):
        self.pods=pods or []
        self.namespace=namespace
        self.calls=[]
        self.node=node_fixture(uid=TARGET)
        self.node['metadata']['labels']={}

    def get(self, kind, name=None, namespace=None, all_namespaces=False, optional=False):
        if kind=='nodes':return copy.deepcopy(self.node)
        if kind=='pods':return {'items':copy.deepcopy(self.pods)}
        if kind=='namespace':
            value=self.namespace
            self.namespace=None
            return value
        raise AssertionError(kind)

    def call(self,args,body=None,timeout=25):
        self.calls.append((args,body))
        return ''


def running_probe():
    value=bootstrap.probe_pod(EXPECTED,IMAGE)
    value['status']={'phase':'Running','containerStatuses':[{'ready':True,'state':{'running':{}},'imageID':IMAGE}]}
    return value


class BootstrapTests(unittest.TestCase):
    def test_registry_merge_preserves_mirrors_tls_other_registry_and_input(self):
        original={'mirrors':{'internal':{'endpoint':['https://mirror.example']}},
                  'configs':{'ghcr.io':{'tls':{'ca_file':'/etc/ssl/approved.pem'},'auth':{'username':'old','password':'old'}},
                             'internal':{'auth':{'username':'another','password':'unchanged'}}}}
        frozen=copy.deepcopy(original)
        credential={'username':'reader','password':'private-test-credential'}
        result=bootstrap.registry_configuration(original,credential)
        self.assertEqual(original,frozen)
        self.assertEqual(result['mirrors'],original['mirrors'])
        self.assertEqual(result['configs']['internal'],original['configs']['internal'])
        self.assertEqual(result['configs']['ghcr.io']['tls'],original['configs']['ghcr.io']['tls'])
        self.assertEqual(result['configs']['ghcr.io']['auth'],credential)
        result['configs']['ghcr.io']['auth']['password']='changed'
        self.assertEqual(credential['password'],'private-test-credential')

    def test_credential_errors_never_echo_secret(self):
        for credential in [{'username':'reader','password':'DO-NOT-LOG\nsecret'},
                           {'username':'reader','password':'DO-NOT-LOG','unexpected':True},
                           {'username':'','password':'DO-NOT-LOG'}]:
            with self.subTest(credential_keys=list(credential)):
                with self.assertRaises(bootstrap.BootstrapError) as error:
                    bootstrap.registry_configuration({},credential)
                self.assertNotIn('DO-NOT-LOG',str(error.exception))

    def test_non_mapping_registry_is_rejected(self):
        for source in [[],None,{'configs':[]},{'configs':{'ghcr.io':[]}}]:
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.registry_configuration(source,{'username':'reader','password':'secret'})

    def test_terminal_and_terminating_challenges_still_block_restart(self):
        for phase in ['Pending','Running','Succeeded','Failed']:
            pod={'metadata':{'namespace':'ctf-owned','deletionTimestamp':'2026-11-02T00:00:00Z'},'status':{'phase':phase}}
            with self.subTest(phase=phase), self.assertRaisesRegex(bootstrap.BootstrapError,'CHALLENGE_RESOURCES_PRESENT'):
                bootstrap.verify_idle([pod])

    def test_busy_node_is_rejected_before_any_mutation(self):
        client=FakeClient(pods=[{'metadata':{'namespace':'ctf-existing'}}])
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.bootstrap_node(client,EXPECTED,{},IMAGE,'',apply=True)
        self.assertEqual(client.calls,[])

    def test_dry_run_does_not_create_or_write_credentials(self):
        client=FakeClient()
        out=bootstrap.bootstrap_node(client,EXPECTED,{'username':'x','password':'DO-NOT-LOG'},IMAGE,'',apply=False)
        self.assertEqual(out['status'],'DRY_RUN')
        self.assertEqual(client.calls,[])
        self.assertNotIn('DO-NOT-LOG',json.dumps(out))

    def test_label_is_optional_only_for_initial_bootstrap(self):
        value=node_fixture(uid=TARGET)
        value['metadata']['labels']={}
        bootstrap.verify_identity(value,EXPECTED)
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.verify_node(value,EXPECTED)

    def test_bootstrap_still_rejects_node_identity_and_platform_changes(self):
        for change in [lambda n:n['metadata'].update(uid='different'),
                       lambda n:n['status']['nodeInfo'].update(machineID='another-machine'),
                       lambda n:n['spec'].update(providerID='gce://other/node'),
                       lambda n:n['status']['nodeInfo'].update(architecture='arm64'),
                       lambda n:n['spec'].update(unschedulable=True)]:
            value=node_fixture(uid=TARGET)
            change(value)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.verify_identity(value,EXPECTED)

    def test_existing_maintenance_namespace_is_not_adopted(self):
        client=FakeClient(namespace={'metadata':{'uid':'other','labels':{'msgctf.bootstrap':'other'}}})
        with self.assertRaisesRegex(bootstrap.BootstrapError,'MAINTENANCE_ALREADY_EXISTS'):
            bootstrap.bootstrap_node(client,EXPECTED,{},IMAGE,'',apply=True)
        self.assertEqual(client.calls,[])

    def test_agent_cannot_be_installed_into_challenge_namespace(self):
        client=FakeClient()
        expected=dict(EXPECTED,namespace='ctf-example')
        with self.assertRaisesRegex(bootstrap.BootstrapError,'INVALID_AGENT_NAMESPACE'):
            bootstrap.bootstrap_node(client,expected,{},IMAGE,'',apply=True)
        self.assertEqual(client.calls,[])

    def test_probe_requires_remote_pull_and_exact_digest_node_and_owner(self):
        bootstrap.verify_probe(running_probe(),EXPECTED,IMAGE)
        changes=[lambda p:p['spec']['containers'][0].update(imagePullPolicy='IfNotPresent'),
                 lambda p:p['spec'].update(nodeName='another'),
                 lambda p:p['metadata']['labels'].update({'msgctf.bootstrap':'another'}),
                 lambda p:p['status']['containerStatuses'][0].update(imageID='ghcr.io/x@y'),
                 lambda p:p['status']['containerStatuses'][0].update(ready=False)]
        for change in changes:
            value=running_probe()
            change(value)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.verify_probe(value,EXPECTED,IMAGE)

    def test_cleanup_uses_uid_precondition(self):
        client=FakeClient(namespace={'metadata':{'uid':'owned','labels':{'msgctf.bootstrap':bootstrap.OWNER}}})
        bootstrap.remove_owned_namespace(client,'owned')
        self.assertEqual(json.loads(client.calls[0][1])['preconditions'],{'uid':'owned'})

    def test_replaced_maintenance_namespace_is_never_deleted(self):
        client=FakeClient(namespace={'metadata':{'uid':'replacement','labels':{'msgctf.bootstrap':bootstrap.OWNER}}})
        with self.assertRaisesRegex(bootstrap.BootstrapError,'MAINTENANCE_OWNER_MISMATCH'):
            bootstrap.remove_owned_namespace(client,'owned')
        self.assertEqual(client.calls,[])

    def test_command_stderr_and_timeout_do_not_expose_credentials(self):
        client=bootstrap.Client('/protected/config',binary=sys.executable)
        failure=subprocess.CompletedProcess([],1,stdout='',stderr='password=DO-NOT-LOG')
        with patch.object(bootstrap.subprocess,'run',return_value=failure):
            with self.assertRaises(bootstrap.BootstrapError) as error:
                client.call(['get','nodes'])
            self.assertNotIn('DO-NOT-LOG',str(error.exception))
        with patch.object(bootstrap.subprocess,'run',side_effect=subprocess.TimeoutExpired([],2,stderr='DO-NOT-LOG')):
            with self.assertRaisesRegex(bootstrap.BootstrapError,'KUBERNETES_UNAVAILABLE'):
                client.call(['get','nodes'])

    def test_registry_body_uses_stdin_not_process_arguments(self):
        client=bootstrap.Client('/protected/config',binary=sys.executable)
        with patch.object(bootstrap.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout='',stderr='')) as run:
            client.execute(['/bin/sh','-ec','cat > /protected/config'],'DO-NOT-LOG')
        self.assertNotIn('DO-NOT-LOG',str(run.call_args.args))
        self.assertEqual(run.call_args.kwargs['input'],'DO-NOT-LOG')

    def test_registry_parser_handles_empty_and_rejects_non_object(self):
        self.assertEqual(bootstrap.decode_registry(''),{})
        for raw in ['null','[]','"DO-NOT-LOG"']:
            with self.assertRaises(bootstrap.BootstrapError) as error:
                bootstrap.decode_registry(raw)
            self.assertNotIn('DO-NOT-LOG',str(error.exception))

    def test_agent_waits_for_real_ready_pod_after_zero_pod_rollout(self):
        client=FakeClient()
        verified={'metadata':{'uid':'reviewed-agent'}}
        with patch.object(bootstrap.enrollment,'verify_agent',side_effect=[enrollment.EnrollmentError('AGENT_UNAVAILABLE'),verified]) as verify:
            with patch.object(bootstrap.time,'sleep'):
                self.assertEqual(bootstrap.wait_agent(client,EXPECTED),verified)
        self.assertEqual(verify.call_count,2)

    def test_agent_wait_is_bounded(self):
        client=FakeClient()
        with patch.object(bootstrap.time,'monotonic',side_effect=[0,0,91]),patch.object(bootstrap.time,'sleep'):
            with self.assertRaisesRegex(bootstrap.BootstrapError,'AGENT_NOT_VERIFIED'):
                bootstrap.wait_agent(client,EXPECTED)


if __name__=='__main__':
    unittest.main()
