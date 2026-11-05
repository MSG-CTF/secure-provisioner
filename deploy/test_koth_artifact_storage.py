"""Real file/SQLite/PostgreSQL regressions for DB-bound artifact archives."""
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
import unittest
from unittest.mock import patch
import uuid
import zlib

import koth_storage as controller
import koth_storage_artifacts as artifacts
import test_koth_storage as old_fixtures

LINUX = sys.platform == 'linux'
DEPLOY = Path(__file__).resolve().parent


@unittest.skipUnless(LINUX, 'Pod file-descriptor operations require Linux')
class ArtifactFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.payload = (b'known harmless test artifact\n' * 100000)
        self.sha = hashlib.sha256(self.payload).hexdigest()
        (self.source / self.sha).write_bytes(self.payload)
        self.refs = artifacts.dependency_references([{'artifact_path': str(self.source / self.sha), 'sha256': self.sha, 'size_bytes': len(self.payload)}], self.source)
        self.roots = {'artifacts': str(self.source)}
        self.pack = self.root / 'snapshot.pack'

    def tearDown(self):
        self.temp.cleanup()

    def test_nonempty_compressed_round_trip_preserves_bytes_hash_mode_and_database_binding(self):
        metadata = artifacts.pack(self.pack, self.refs, self.roots)
        self.assertLess(metadata['database_bytes'], len(self.payload))
        proof = artifacts.check_pack(self.pack, self.refs, self.roots, check_live=True)
        artifacts.check_metadata(metadata, self.refs, proof)
        target = self.root / 'restored'
        proof = artifacts.check_pack(self.pack, self.refs, {'artifacts': str(target)}, restore=True)
        self.assertTrue(proof['database_file_consistency_verified'])
        self.assertEqual((target / self.sha).read_bytes(), self.payload)
        self.assertEqual((target / self.sha).stat().st_mode & 0o777, 0o400)
        artifacts.check_sources(self.refs, {'artifacts': str(target)})

    def test_missing_changed_size_wrong_hash_symlink_hardlink_and_fifo_fail_closed(self):
        path = self.source / self.sha
        for kind in ['missing', 'size', 'hash', 'symlink', 'hardlink', 'fifo']:
            with self.subTest(kind=kind):
                path.unlink()
                if kind == 'size': path.write_bytes(b'too short')
                elif kind == 'hash': path.write_bytes(b'X' * len(self.payload))
                elif kind == 'symlink': path.symlink_to(self.root / 'outside')
                elif kind == 'hardlink':
                    (self.root / 'outside').write_bytes(self.payload);os.link(self.root / 'outside', path)
                elif kind == 'fifo': os.mkfifo(path)
                with self.assertRaises((artifacts.ArtifactError, OSError)):
                    artifacts.pack(self.pack, self.refs, self.roots)
                self.pack.unlink(missing_ok=True)
                path.unlink(missing_ok=True)
                (self.root / 'outside').unlink(missing_ok=True)
                path.write_bytes(self.payload)

    def test_mutation_during_copy_and_parent_symlink_cannot_publish_a_success(self):
        original = artifacts.source_chunks
        def mutate(file, size):
            for block in original(file, size):
                with (self.source / self.sha).open('r+b') as changed:
                    changed.seek(size-1);changed.write(b'X')
                yield block
        with patch.object(artifacts, 'source_chunks', side_effect=mutate):
            with self.assertRaises(artifacts.ArtifactError): artifacts.pack(self.pack, self.refs, self.roots)
        self.pack.unlink()
        nested = self.source / 'nested';nested.symlink_to(self.root, target_is_directory=True)
        ref = {'root':'sources','path':'nested/outside','sha256':self.sha,'size_bytes':len(self.payload)}
        (self.root / 'outside').write_bytes(self.payload)
        with self.assertRaises(OSError): artifacts.pack(self.pack, [ref], {'sources':str(self.source)})

    def test_paths_conflicting_references_and_limits_are_rejected(self):
        for name in ['/etc/passwd','../outside','a/../../outside','a//b','a\\b','./b']:
            with self.subTest(name=name), self.assertRaises(artifacts.ArtifactError):
                artifacts.references([{'root':'sources','path':name,'sha256':self.sha,'size_bytes':1}], {'sources'})
        conflict = {**self.refs[0], 'size_bytes': 1}
        with self.assertRaisesRegex(artifacts.ArtifactError, 'CONFLICT'): artifacts.references(self.refs+[conflict], self.roots)
        with patch.object(artifacts, 'MAX_RAW', len(self.payload)-1):
            with self.assertRaises(artifacts.ArtifactError): artifacts.pack(self.pack, self.refs, self.roots)
        self.pack.unlink(missing_ok=True)
        with patch.object(artifacts, 'MAX_FILES', 0):
            with self.assertRaises(artifacts.ArtifactError): artifacts.references(self.refs, self.roots)

    def test_wrong_database_manifest_truncation_trailing_bytes_and_size_lie_fail(self):
        metadata = artifacts.pack(self.pack, self.refs, self.roots)
        original = self.pack.read_bytes()
        wrong = [{**self.refs[0], 'sha256':'0'*64, 'path':'0'*64}]
        with self.assertRaisesRegex(artifacts.ArtifactError, 'REFERENCES_MISMATCH'): artifacts.check_pack(self.pack, wrong, self.roots)
        for data in [original[:-1], original+b'X']:
            self.pack.write_bytes(data)
            with self.assertRaises(artifacts.ArtifactError): artifacts.check_pack(self.pack, self.refs, self.roots)
        self.pack.write_bytes(original)
        proof = artifacts.check_pack(self.pack, self.refs, self.roots)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'METADATA_MISMATCH'):
            artifacts.check_metadata({**metadata,'uncompressed_bytes':0}, self.refs, proof)

    def test_decompression_bomb_and_existing_restore_target_are_rejected(self):
        ref = {'root':'artifacts','path':hashlib.sha256(b'A').hexdigest(),'sha256':hashlib.sha256(b'A').hexdigest(),'size_bytes':1}
        body = zlib.compress(b'A' * 1024 * 1024)
        self.pack.write_bytes(artifacts.canonical({'format_version':1,'reference_count':1,'references_sha256':artifacts.reference_hash([ref])})+b'\n'+artifacts.canonical({**ref,'compressed_bytes':len(body)})+b'\n'+body)
        with self.assertRaises(artifacts.ArtifactError): artifacts.check_pack(self.pack, [ref], self.roots)
        self.pack.unlink()
        artifacts.pack(self.pack, self.refs, self.roots)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'TARGET_NOT_EMPTY'):
            artifacts.check_pack(self.pack, self.refs, self.roots, restore=True)
        self.assertEqual((self.source/self.sha).read_bytes(), self.payload)

    def test_empty_reference_set_is_an_explicit_valid_snapshot(self):
        metadata = artifacts.pack(self.pack, [], self.roots)
        target = self.root/'empty'
        proof = artifacts.check_pack(self.pack, [], {'artifacts':str(target)}, restore=True)
        self.assertEqual(proof['file_count'], 0)
        self.assertEqual(list(target.iterdir()), [])
        artifacts.check_metadata(metadata, [], proof)


@unittest.skipUnless(LINUX, 'real Pod-context SQLite fixture requires Linux')
class GrandArtifactWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/data');self.root = Path(self.temp.name)
        self.env = {**os.environ,'KUBERNETES_SERVICE_HOST':'private-regression-fixture','KOTH_DATABASE_PATH':str(self.root/'state.sqlite'), 'KOTH_SUBMISSIONS_DIR':str(self.root/'sources'), 'KOTH_REPLAYS_DIR':str(self.root/'replays')}
        self.request = {'format_version':1,'action':'backup','game':'grand-tour-duel','operation_id':str(uuid.uuid4()),'expected_pod_name':socket.gethostname(),'data_root':'/data','store_specs':copy.deepcopy(controller.PROFILES['grand-tour-duel']['stores']),'artifact_bundle':True}
        self.source = b'def choose_action(state): return {"type":"pass"}\n'
        self.source_hash = hashlib.sha256(self.source).hexdigest()
        self.rel = str(uuid.uuid4())+'/'+str(uuid.uuid4())+'/bot.py'
        path = Path(self.env['KOTH_SUBMISSIONS_DIR'])/self.rel;path.parent.mkdir(parents=True);path.write_bytes(self.source)
        replay = b'{"events":[],"test":"fixture"}'
        root = Path(self.env['KOTH_REPLAYS_DIR']);root.mkdir();(root/'owner.json').write_bytes(replay);(root/'public.json').write_bytes(replay)
        h = hashlib.sha256(replay).hexdigest()
        db = sqlite3.connect(self.env['KOTH_DATABASE_PATH'])
        db.executescript('CREATE TABLE submissions(id TEXT PRIMARY KEY,team_id TEXT,source_relpath TEXT,sha256 TEXT,source_size_bytes INTEGER);CREATE TABLE duel_tick_entries(source_relpath TEXT,source_sha256 TEXT,source_size_bytes INTEGER);CREATE TABLE practice_games(status TEXT,replay_relpath TEXT,replay_sha256 TEXT);CREATE TABLE replays(id TEXT PRIMARY KEY,artifact_relpath TEXT,sha256 TEXT);CREATE TABLE score_period_results(id TEXT PRIMARY KEY,value INTEGER);CREATE TABLE sessions(id TEXT PRIMARY KEY);')
        team,identifier,_ = self.rel.split('/')
        db.execute('INSERT INTO submissions VALUES(?,?,?,?,?)',(identifier,team,self.rel,self.source_hash,len(self.source)))
        db.execute('INSERT INTO duel_tick_entries VALUES(?,?,?)',(self.rel,self.source_hash,len(self.source)))
        db.execute('INSERT INTO practice_games VALUES(?,?,?)',('COMPLETE','owner.json',h))
        db.execute('INSERT INTO replays VALUES(?,?,?)',('sealed','public.json',h))
        db.execute("INSERT INTO score_period_results VALUES('sealed',42)");db.execute("INSERT INTO sessions VALUES('old')");db.commit();db.close()
        db = sqlite3.connect(self.env['KOTH_DATABASE_PATH']+'.auth.sqlite3');db.executescript("CREATE TABLE session_keys(key_id TEXT PRIMARY KEY,retired_at INTEGER);CREATE TABLE session_bindings(id TEXT);INSERT INTO session_keys VALUES('old',NULL);INSERT INTO session_bindings VALUES('old');");db.close()

    def tearDown(self): self.temp.cleanup()

    def call(self, action, payload=b'', env=None, request=None, success=True):
        req={**(request or self.request),'operation_id':str(uuid.uuid4()),'action':action}
        command=controller.worker_command('grand-tour-duel',req);command[0]=sys.executable
        p=subprocess.run(command,input=payload,capture_output=True,env=env or self.env,timeout=30)
        self.assertEqual(p.returncode==0,success,p.stderr.decode())
        return p

    def unpack(self, frame):
        stream=io.BytesIO(frame);header=json.loads(stream.readline());parts=[stream.read(row['database_bytes']) for row in header['stores']];self.assertFalse(stream.read(1));return header,parts

    def test_real_sqlite_and_all_referenced_source_practice_duel_files_restore_with_current_keys(self):
        old=self.call('backup').stdout;header,parts=self.unpack(old)
        self.assertEqual(header['stores'][-1]['reference_count'],3)
        self.call('verify',old)
        db=sqlite3.connect(self.env['KOTH_DATABASE_PATH']+'.auth.sqlite3');db.executescript("UPDATE session_keys SET retired_at=1;INSERT INTO session_keys VALUES('current',NULL);");db.close()
        authority=self.call('backup',request={**self.request,'artifact_bundle':False}).stdout
        target=dict(self.env);target.update(KOTH_DATABASE_PATH=str(self.root/'target'/'state.sqlite'),KOTH_SUBMISSIONS_DIR=str(self.root/'target'/'sources'),KOTH_REPLAYS_DIR=str(self.root/'target'/'replays'))
        # Simulate identical absolute mount paths in a separate restore namespace.
        header['stores'][-1]['artifact_roots']={'sources':target['KOTH_SUBMISSIONS_DIR'],'replays':target['KOTH_REPLAYS_DIR']}
        frame=artifacts.canonical(header)+b'\n'+b''.join(parts)
        proof=json.loads(self.call('restore',frame+authority,env=target).stdout)
        self.assertEqual(proof['artifacts']['file_count'],3);self.assertEqual(proof['restored_session_row_count'],0)
        self.assertEqual((Path(target['KOTH_SUBMISSIONS_DIR'])/self.rel).read_bytes(),self.source)
        db=sqlite3.connect(target['KOTH_DATABASE_PATH']);self.assertEqual(db.execute('SELECT value FROM score_period_results').fetchone()[0],42);db.close()
        db=sqlite3.connect(target['KOTH_DATABASE_PATH']+'.auth.sqlite3');self.assertEqual(db.execute('SELECT * FROM session_keys ORDER BY key_id').fetchall(),[('current',None),('old',1)]);db.close()

    def test_missing_or_mutated_source_file_fails_before_any_backup_frame(self):
        path=Path(self.env['KOTH_SUBMISSIONS_DIR'])/self.rel
        path.write_bytes(b'X'*len(self.source))
        p=self.call('backup',success=False);self.assertEqual(p.stdout,b'');self.assertIn(b'ARTIFACT_FILE_HASH_MISMATCH',p.stderr)
        path.unlink();p=self.call('backup',success=False);self.assertEqual(p.stdout,b'')
        self.assertFalse(list(Path('/data/.msgctf-storage').iterdir()))

    def test_verify_detects_changed_live_file_and_mixed_database_file_snapshot(self):
        old=self.call('backup').stdout
        (Path(self.env['KOTH_REPLAYS_DIR'])/'owner.json').write_bytes(b'changed')
        self.call('verify',old,success=False)
        header,parts=self.unpack(old)
        snapshot=self.root/'mixed.sqlite';snapshot.write_bytes(parts[0])
        db=sqlite3.connect(snapshot);db.execute("UPDATE submissions SET sha256=?",('0'*64,));db.execute("UPDATE duel_tick_entries SET source_sha256=?",('0'*64,));db.commit();db.close()
        parts[0]=snapshot.read_bytes();header['stores'][0]['database_bytes']=len(parts[0]);header['stores'][0]['database_sha256']=hashlib.sha256(parts[0]).hexdigest()
        p=self.call('verify',artifacts.canonical(header)+b'\n'+b''.join(parts),success=False)
        self.assertIn(b'REFERENCES_MISMATCH',p.stderr)

    def test_old_database_only_archive_cannot_be_presented_as_a_complete_restore(self):
        frame=self.call('backup',request={**self.request,'artifact_bundle':False}).stdout;header,_=self.unpack(frame)
        with self.assertRaisesRegex(controller.StorageError,'COMPLETE_ARTIFACT_BACKUP_REQUIRED'):
            controller.require_artifacts(header)
        self.assertLess(len(controller.worker_command('grand-tour-duel',self.request)[3].encode()),131072)


class ArtifactControllerTests(unittest.TestCase):
    def test_restore_capacity_accounts_for_uncompressed_files_and_staging(self):
        header={'stores':[{'engine':'sqlite','database_bytes':60*1024**2},{'engine':'file_bundle','database_bytes':400*1024**2,'uncompressed_bytes':4500*1024**2}]}
        self.assertEqual(controller.restore_capacity(header),'8Gi')
        with self.assertRaises(controller.StorageError): controller.restore_capacity({'stores':[{'database_bytes':40*1024**3}]})


@unittest.skipUnless(LINUX, 'real service Pod-context file worker requires Linux')
class DependencyArtifactWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/data');self.root=Path(self.temp.name)
        self.payload=b'nonexecuted isolated artifact fixture\n'*10000;self.sha=hashlib.sha256(self.payload).hexdigest()
        self.artifact_root=self.root/'artifacts';self.artifact_root.mkdir();(self.artifact_root/self.sha).write_bytes(self.payload)
        db=sqlite3.connect(self.root/'session-bindings.sqlite3');db.execute('CREATE TABLE guard(id INTEGER)');db.commit();db.close()
        self.env={**os.environ,'DATA_DIR':str(self.root),'KUBERNETES_SERVICE_HOST':'isolated-file-fixture'}
        self.request={'format_version':1,'game':'dependency-hell','action':'artifact_backup','operation_id':str(uuid.uuid4()),'expected_pod_name':socket.gethostname(),'data_root':'/data','store_specs':copy.deepcopy(controller.PROFILES['dependency-hell']['stores'])}
        self.rows=[{'artifact_path':str(self.artifact_root/self.sha),'sha256':self.sha,'size_bytes':len(self.payload)}]

    def tearDown(self): self.temp.cleanup()

    def call(self,action,rows=None,body=b'',success=True):
        command=controller.worker_command('dependency-hell',{**self.request,'action':action,'operation_id':str(uuid.uuid4())});command[0]=sys.executable
        payload=artifacts.canonical({'references':self.rows if rows is None else rows})+b'\n'+body
        result=subprocess.run(command,input=payload,capture_output=True,env=self.env,timeout=30)
        self.assertEqual(result.returncode==0,success,result.stderr.decode());return result

    def test_nonempty_postgres_reference_frame_round_trip_and_auth_file_unchanged(self):
        original=artifacts.digest_file(self.root/'session-bindings.sqlite3')
        frame=self.call('artifact_backup').stdout
        header=json.loads(frame.split(b'\n',1)[0]);self.assertEqual(header['stores'][0]['database_references_sha256'],hashlib.sha256(artifacts.canonical(self.rows)).hexdigest())
        self.call('artifact_verify',body=frame);self.call('artifact_check')
        self.artifact_root.rename(self.root/'saved-artifacts')
        proof=json.loads(self.call('artifact_restore',body=frame).stdout)
        self.assertEqual(proof['file_count'],1);self.assertEqual((self.artifact_root/self.sha).read_bytes(),self.payload)
        self.assertEqual(original,artifacts.digest_file(self.root/'session-bindings.sqlite3'))

    def test_mixed_reference_manifest_and_missing_current_artifact_are_rejected(self):
        frame=self.call('artifact_backup').stdout
        wrong=[{**self.rows[0],'artifact_path':str(self.artifact_root/('0'*64)),'sha256':'0'*64}]
        p=self.call('artifact_verify',rows=wrong,body=frame,success=False);self.assertIn(b'REFERENCES_MISMATCH',p.stderr)
        (self.artifact_root/self.sha).unlink();self.call('artifact_check',success=False)


@unittest.skipUnless(os.environ.get('KOTH_STORAGE_PG_CONTAINER'), 'real PostgreSQL 18 fixture required')
class DependencyArtifactPostgresTests(unittest.TestCase):
    def setUp(self):
        self.fixture=old_fixtures.RealPostgresTests('runTest');self.fixture.setUp();self.root=self.fixture.root;self.kube=self.fixture.kube
        controller.pg_command(self.kube,'sql',data=b'ALTER TABLE submissions ADD COLUMN artifact_path text;ALTER TABLE submissions ADD COLUMN sha256 text;ALTER TABLE submissions ADD COLUMN size_bytes bigint;')

    def tearDown(self): self.fixture.tearDown()

    def test_real_pg_dump_binds_files_restore_rechecks_cloned_database_and_preserves_authority(self):
        payload=b'private canary artifact bytes\n'*10000;h=hashlib.sha256(payload).hexdigest();source=self.root/'artifacts';source.mkdir();(source/h).write_bytes(payload)
        sql="INSERT INTO submissions(id,verdict,value,artifact_path,sha256,size_bytes) VALUES('artifact','PENDING','fixture','"+str(source/h)+"','"+h+"',"+str(len(payload))+");"
        controller.pg_command(self.kube,'sql',data=sql.encode())
        folder=self.root/'snapshot';folder.mkdir();dump,meta=controller.postgres_backup(self.kube,folder,str(uuid.uuid4()),include_references=True)
        refs=artifacts.dependency_references(meta.pop('_artifact_references'),source);pack=self.root/'files.pack';artifacts.pack(pack,refs,{'artifacts':str(source)})
        target=self.root/'restored'
        def restore(rows):
            derived=artifacts.dependency_references(rows,source)
            return artifacts.check_pack(pack,derived,{'artifacts':str(target)},restore=True)
        ranges={'postgres':(0,dump.stat().st_size)};header={'stores':[meta]}
        proof=controller.postgres_restore_check(self.kube,dump,header,ranges,dump,header,ranges,self.root,str(uuid.uuid4()),artifact_callback=restore)
        self.assertTrue(proof['artifacts']['database_file_consistency_verified']);self.assertEqual((target/h).read_bytes(),payload)
        self.assertTrue(proof['temporary_database_removed']);self.assertEqual(proof['restored_session_row_count'],0)

    def test_failed_file_check_cleans_pg_clone_and_legal_reference_release_is_not_score_corruption(self):
        controller.pg_command(self.kube,'sql',data=b"UPDATE submissions SET artifact_path='/data/artifacts/old',sha256=repeat('a',64),size_bytes=1;")
        folder=self.root/'snapshot';folder.mkdir();dump,meta=controller.postgres_backup(self.kube,folder,str(uuid.uuid4()),include_references=True)
        header={'stores':[meta]};ranges={'postgres':(0,dump.stat().st_size)}
        controller.pg_command(self.kube,'sql',data=b'UPDATE submissions SET artifact_path=NULL;')
        controller.postgres_verify(self.kube,dump,header,ranges,self.root,str(uuid.uuid4()))
        def fail(_rows): raise controller.StorageError('ARTIFACT_FILE_HASH_MISMATCH')
        with self.assertRaisesRegex(controller.StorageError,'ARTIFACT_FILE_HASH_MISMATCH'):
            controller.postgres_restore_check(self.kube,dump,header,ranges,dump,header,ranges,self.root,str(uuid.uuid4()),artifact_callback=fail)


if __name__ == '__main__': unittest.main()
