"""Storage recovery decision, fencing, real SQLite and real PostgreSQL regressions."""
import copy
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

import koth_storage as s
import koth_storage_cutover as c
import test_koth_storage as fixtures
import install_koth_storage as installer


class ContractTests(unittest.TestCase):
    def header(self):
        return {'stores':[{'engine':'sqlite','store_id':'game','database_path':'/data/game.db',
                           'business_sha256':'business','schema_sha256':'schema','auth_history_sha256':'active'},
                          {'engine':'file_bundle','artifact_roots':{'sources':'/data/sources'},'references_sha256':'refs'}]}

    def test_restore_rejects_missing_or_changed_current_business_schema_paths_and_files(self):
        active=self.header()
        for path,value in [('business_sha256','old'),('schema_sha256','changed'),('database_path','/data/other.db')]:
            old=copy.deepcopy(active);old['stores'][0][path]=value
            with self.subTest(field=path),self.assertRaises(s.StorageError):c.require_no_loss(old,active)
        old=copy.deepcopy(active);old['stores'][1]['references_sha256']='mixed'
        with self.assertRaises(s.StorageError):c.require_no_loss(old,active)
        old=copy.deepcopy(active);old['stores']=old['stores'][1:]
        with self.assertRaises(s.StorageError):c.require_no_loss(old,active)

    def test_current_retired_key_history_is_separate_from_business_eligibility(self):
        old=self.header();active=copy.deepcopy(old);active['stores'][0]['auth_history_sha256']='retired-plus-new'
        c.require_no_loss(old,active)

    def test_sql_identifiers_and_fault_points_cannot_inject_control_commands(self):
        for value in ['postgres;DROP DATABASE x','/data','mixedCase','x";--','a'*64]:
            with self.assertRaises(s.StorageError):c.sql_identifier(value)
        self.assertEqual(c.sql_identifier('msgctf_previous_123'),'"msgctf_previous_123"')

    def test_replacement_capacity_never_shrinks_source_and_is_bounded(self):
        header={'stores':[{'database_bytes':1024,'engine':'sqlite'}]}
        self.assertEqual(c.production_capacity(header,'10Gi'),'10Gi')
        self.assertEqual(c.production_capacity(header,'512Mi'),'2Gi')
        for value in ['128Gi','unbounded','-1Gi']:
            with self.assertRaises(s.StorageError):c.production_capacity(header,value)

    def test_cutover_host_never_loads_database_engine_or_executes_artifact(self):
        tree=ast.parse(Path(c.__file__).read_text())
        imports=[node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom)]
        imports += [alias.name for node in ast.walk(tree) if isinstance(node,ast.Import) for alias in node.names]
        self.assertFalse({'sqlite3','psycopg','psycopg2'} & set(imports))

    def test_environment_image_rollout_preserves_promoted_pvc_binding(self):
        import test_koth_environment_agent as f
        config,game,desired=f.fixture()
        kube=f.FakeKubernetes(game,desired['settings'])
        kube.current['spec']['volumes'][0]['persistentVolumeClaim']['claimName']='recovery-'+('a'*32)
        changed=kube.template(kube.current,desired)
        self.assertEqual(changed['spec']['volumes'],kube.current['spec']['volumes'])
        self.assertEqual(changed['spec']['containers'][0]['image'],desired['settings']['containers'][0]['image'])


@unittest.skipUnless(sys.platform=='linux','root-private state and atomic Unix fsync')
class RecoveryDecisionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.storage=s.Storage('jenga',str(uuid.uuid4()),'test',root=self.root,kube=object())
        self.task=c.Cutover(self.storage,system=lambda *a,**kw:True)
        self.task.plan()

    def tearDown(self):self.temp.cleanup()

    def test_operation_id_reuse_changes_are_rejected_and_private_plan_survives_restart(self):
        with self.assertRaisesRegex(s.StorageError,'REUSED'):self.task.plan(fault='after_ready')
        self.assertEqual(self.task.path.stat().st_mode&0o777,0o600)
        restarted=c.Cutover(self.storage)
        self.assertEqual(restarted.state,self.task.state)

    def test_prepublication_crash_recovery_chooses_rollback(self):
        for phase in ['freezing','restore_intent','pvc_switch_intent','postgres_swap_intent','application_start_intent','ready']:
            self.task.save(phase,decision='rollback')
            with patch.object(self.task,'rollback',return_value={'phase':'rolled_back'}) as rollback:
                self.assertEqual(self.task.recover()['phase'],'rolled_back');rollback.assert_called_once()

    def test_after_publication_starts_recovery_never_chooses_stale_volume(self):
        self.task.save('needs_recovery',decision='commit',result={'live_pvc_uid':'new'})
        with patch.object(self.task,'rollback',side_effect=AssertionError('would lose accepted writes')), \
             patch.object(self.task,'wait_ready') as ready,patch.object(self.task,'finish',return_value={'phase':'committed'}) as finish:
            self.assertEqual(self.task.recover()['phase'],'committed')
            ready.assert_called_once_with(True);finish.assert_called_once_with(True,{'live_pvc_uid':'new'})

    def test_durable_decision_precedes_first_route_open_even_when_opening_throws(self):
        self.task.save('ready',agent_was_active=False)
        def fence(enabled):
            saved=json.loads(self.task.path.read_text())
            self.assertFalse(enabled);self.assertEqual(saved['decision'],'commit');self.assertEqual(saved['phase'],'publishing')
            raise s.StorageError('SIMULATED_PARTIAL_SERVICE_API_FAILURE')
        with patch.object(self.task,'fence',side_effect=fence):
            with self.assertRaises(s.StorageError):self.task.finish(True,{'live_pvc_uid':'new'})
        self.assertEqual(c.Cutover(self.storage).state['decision'],'commit')

    def test_failed_rollback_retains_fence_journal_and_recovery_does_not_claim_success(self):
        self.task.save('frozen')
        with patch.object(self.task,'rollback',side_effect=s.StorageError('CUTOVER_RESOURCE_CONFLICT')):
            with self.assertRaises(s.StorageError):self.task.recover()
        self.assertEqual(self.task.state['phase'],'needs_recovery')
        self.assertEqual(self.task.state['decision'],'rollback')

    def test_compare_and_swap_rejects_replaced_uid_and_foreign_changes(self):
        class Kube:
            def __init__(self,obj):self.obj=obj;self.calls=[]
            def json(self,args):return self.obj
            def run(self,args):self.calls.append(args)
        original={'metadata':{'uid':'uid','resourceVersion':'17'},'spec':{'selector':{'app':'game'}}}
        k=Kube(original);self.task.kube=k
        self.task.patch('service','game','uid','/spec/selector',{'app':'game'},{'app':'game',c.FENCE:'op'})
        changes=json.loads(k.calls[0][-1]);self.assertEqual(changes[0],{'op':'test','path':'/metadata/uid','value':'uid'})
        self.assertEqual(changes[1]['value'],'17')
        for uid,selector in [('replacement',{'app':'game'}),('uid',{'app':'foreign'})]:
            k.obj={'metadata':{'uid':uid,'resourceVersion':'18'},'spec':{'selector':selector}};k.calls=[]
            with self.assertRaisesRegex(s.StorageError,'CONFLICT'):
                self.task.patch('service','game','uid','/spec/selector',{'app':'game'},{c.FENCE:'op'})
            self.assertEqual(k.calls,[])

    def test_hpa_pausing_preserves_object_and_changes_only_scale_target(self):
        value={'uid':'autoscaler-uid','before':{'apiVersion':'apps/v1','kind':'Deployment','name':'backend'},
               'after':{'apiVersion':'apps/v1','kind':'Deployment','name':'storage-fenced-op'}}
        self.task.state['autoscalers']={'backend':value}
        with patch.object(self.task,'patch') as write:
            self.task.autoscale(True);self.task.autoscale(False)
            self.assertEqual(write.call_args_list[0].args,('hpa','backend','autoscaler-uid','/spec/scaleTargetRef',value['before'],value['after']))
            self.assertEqual(write.call_args_list[1].args[-2:],(value['after'],value['before']))

    def test_installer_boot_order_and_active_transaction_guard(self):
        prefix=self.root/'install';prefix.mkdir()
        installer.install(fixtures.DEPLOY,'a'*40,'jenga',prefix=prefix)
        unit=(prefix/'etc/systemd/system/msgctf-koth-storage-recover.service').read_text()
        self.assertIn('Before=koth-environment-agent.service',unit);self.assertIn('RemainAfterExit=yes',unit)
        dependency=(prefix/'etc/systemd/system/koth-environment-agent.service.d/storage-recovery.conf').read_text()
        self.assertIn('Requires=msgctf-koth-storage-recover.service',dependency)
        active=prefix/'var/lib/msgctf-koth-storage/active-cutover.json';active.parent.mkdir(parents=True);active.write_text('{}')
        with self.assertRaisesRegex(ValueError,'ACTIVE_STORAGE_CUTOVER'):installer.install(fixtures.DEPLOY,'b'*40,'jenga',prefix=prefix)

    def test_terminal_retry_does_not_switch_again_and_clears_own_active_pointer(self):
        self.task.save('committed',decision='commit');c.atomic_json(self.task.active,{'operation_id':self.storage.operation_id})
        with patch.object(self.task,'rollback',side_effect=AssertionError('must not replay')):
            self.assertEqual(self.task.recover()['phase'],'committed')
        self.assertFalse(self.task.active.exists())

    def test_failed_volume_retirement_refuses_active_transactions_and_referenced_claim(self):
        self.task.save('committed')
        with self.assertRaisesRegex(s.StorageError,'ONLY_INACTIVE'):self.task.retire_failed()
        self.task.save('rolled_back',candidate_pvc_name='recovery-old')
        class Kube:
            def json(self,args):return {'items':[{'spec':{'template':{'spec':{'volumes':[{'persistentVolumeClaim':{'claimName':'recovery-old'}}]}}}}]}
            def run(self,*a,**kw):raise AssertionError('must not delete')
        self.task.kube=Kube()
        with self.assertRaisesRegex(s.StorageError,'STILL_REFERENCED'):self.task.retire_failed()


@unittest.skipUnless(sys.platform=='linux','real Pod-context SQLite and process handles')
class OfflineSessionTests(unittest.TestCase):
    def setUp(self):self.fixture=fixtures.RealWalTests('runTest');self.fixture.setUp()
    def tearDown(self):self.fixture.tearDown()

    def test_python_and_node_rollback_clear_old_sessions_keep_business_and_latest_retirements(self):
        for game in ['jenga','card-battle-arena','swanopoly']:
            with self.subTest(game=game):
                request,env,paths,writers=self.fixture.fixture(game)
                for spec,writer in zip(request['store_specs'],writers):
                    if spec['auth_key_table']:
                        self.fixture.sql(writer,f'UPDATE "{spec["auth_key_table"]}" SET retired_at=456;INSERT INTO "{spec["auth_key_table"]}" VALUES(\'latest\',NULL);')
                frame=self.fixture.call(request,env,'backup').stdout
                header,_=self.fixture.frames(frame)
                blocked=self.fixture.call(request,env,'revoke_sessions',frame,ok=False)
                self.assertIn(b'RESTORE_TARGET_IN_USE',blocked.stderr)
                for writer in writers:
                    writer.stdin.close();writer.wait(timeout=5)
                inode=[v.stat().st_ino for v in paths]
                proof=json.loads(self.fixture.call(request,env,'revoke_sessions',frame).stdout)
                self.assertEqual(proof['restored_session_row_count'],0)
                self.assertEqual(inode,[v.stat().st_ino for v in paths])
                for spec,before,after in zip(request['store_specs'],header['stores'],proof['stores']):
                    self.assertEqual(before['business_sha256'],after['business_sha256'])
                    self.assertEqual(before['auth_history_sha256'],after['auth_history_sha256'])
                    self.assertTrue(all(after['table_row_counts'][t]==0 for t in spec['session_tables']))
                self.fixture.call(request,env,'revoke_sessions',frame)  # idempotent recovery


@unittest.skipUnless(os.environ.get('KOTH_STORAGE_PG_CONTAINER'),'real PostgreSQL 18 service required')
class ProductionPostgresSwapTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.RealPostgresTests('runTest');self.fixture.setUp()
        self.kube=self.fixture.kube;self.operation=str(uuid.uuid4());self.task=c.Cutover(s.Storage('dependency-hell',self.operation,'test',root=self.fixture.root,kube=self.kube))
        self.role='cutover_reader_'+uuid.uuid4().hex[:10]
        c.pg_control(self.kube,f'CREATE ROLE {self.role}; REVOKE CONNECT ON DATABASE {s.PG_DATABASE} FROM PUBLIC; GRANT CONNECT ON DATABASE {s.PG_DATABASE} TO {self.role}; ALTER DATABASE {s.PG_DATABASE} CONNECTION LIMIT 41; ALTER DATABASE {s.PG_DATABASE} SET search_path TO public,pg_catalog;')
        folder=self.fixture.root/'backup';folder.mkdir();self.dump,self.meta=s.postgres_backup(self.kube,folder,str(uuid.uuid4()))
        self.header={'stores':[self.meta]};self.ranges={'postgres':(0,self.dump.stat().st_size)}
        result=s.postgres_restore_check(self.kube,self.dump,self.header,self.ranges,self.dump,self.header,self.ranges,self.fixture.root,self.operation,retain=True)
        self.candidate=result['restored_database_name'];self.previous='msgctf_previous_'+uuid.UUID(self.operation).hex
        dbs=c.pg_databases(self.kube)
        self.task.state={'postgres':dbs[s.PG_DATABASE],'postgres_original_oid':dbs[s.PG_DATABASE]['database_oid'],
                         'postgres_candidate_oid':dbs[self.candidate]['database_oid'],'postgres_candidate_database':self.candidate,'postgres_previous_database':self.previous}

    def tearDown(self):
        try:
            if c.pg_databases(self.kube).get(s.PG_DATABASE,{}).get('database_oid')==self.task.state['postgres_candidate_oid']:self.task.postgres_switch(False)
            self.fixture.raw(['sh','-c','dropdb --if-exists --force -U "$POSTGRES_USER" "$1"','sh',self.candidate])
            c.pg_control(self.kube,f'REVOKE ALL ON DATABASE {s.PG_DATABASE} FROM {self.role}; DROP ROLE {self.role};')
        finally:self.fixture.tearDown()

    def test_real_forward_and_reverse_swap_preserve_oids_acl_settings_scores_and_private_retained_database(self):
        self.assertEqual(c.pg_control(self.kube,f"SELECT has_database_privilege('{self.role}','{self.candidate}','CONNECT');").strip(),b'f')
        self.task.postgres_switch(True);self.task.postgres_switch(True)
        dbs=c.pg_databases(self.kube)
        self.assertEqual(dbs[s.PG_DATABASE]['database_oid'],self.task.state['postgres_candidate_oid'])
        self.assertFalse(dbs[self.previous]['allow_connections'])
        self.assertEqual(dbs[s.PG_DATABASE]['connection_limit'],41)
        self.assertEqual(dbs[s.PG_DATABASE]['settings'],self.task.state['postgres']['settings'])
        self.assertEqual(c.pg_control(self.kube,f"SELECT has_database_privilege('{self.role}','{s.PG_DATABASE}','CONNECT');").strip(),b't')
        self.assertEqual(s.pg_metadata(self.kube,s.PG_DATABASE)['business_sha256'],self.meta['business_sha256'])
        self.assertEqual(s.pg_metadata(self.kube,s.PG_DATABASE)['table_row_counts']['sessions'],0)
        self.task.postgres_switch(False);self.task.postgres_switch(False)
        dbs=c.pg_databases(self.kube);self.assertEqual(dbs[s.PG_DATABASE]['database_oid'],self.task.state['postgres_original_oid'])
        self.assertFalse(dbs[self.candidate]['allow_connections'])
        self.assertEqual(s.pg_metadata(self.kube,s.PG_DATABASE)['business_sha256'],self.meta['business_sha256'])

    def test_transaction_error_after_both_renames_rolls_back_entire_database_switch(self):
        sql=c.pg_swap_sql(s.PG_DATABASE,self.candidate,self.previous).replace('COMMIT;','SELECT 1/0; COMMIT;')
        with self.assertRaises(s.StorageError):c.pg_control(self.kube,sql)
        dbs=c.pg_databases(self.kube)
        self.assertEqual(dbs[s.PG_DATABASE]['database_oid'],self.task.state['postgres_original_oid'])
        self.assertEqual(dbs[self.candidate]['database_oid'],self.task.state['postgres_candidate_oid'])
        self.assertTrue(dbs[s.PG_DATABASE]['allow_connections']);self.assertNotIn(self.previous,dbs)

    def test_foreign_database_oid_is_rejected_before_any_rename(self):
        real=self.task.state['postgres_candidate_oid'];self.task.state['postgres_candidate_oid']='not-the-pinned-oid'
        try:
            with self.assertRaisesRegex(s.StorageError,'SWAP_CONFLICT'):self.task.postgres_switch(True)
            self.assertEqual(c.pg_databases(self.kube)[s.PG_DATABASE]['database_oid'],self.task.state['postgres_original_oid'])
        finally:self.task.state['postgres_candidate_oid']=real


if __name__=='__main__':unittest.main()
