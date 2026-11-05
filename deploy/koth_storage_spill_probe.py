"""Run real Python/Node SQLite EXCEPT checks in an isolated 16 MiB tmpfs mount."""
import json,os,shutil,sqlite3,subprocess,sys,tempfile
from pathlib import Path
import test_koth_storage as fixtures

def run():
    assert os.geteuid()==0
    deploy=Path(__file__).resolve().parent
    node=sys.argv[1];os.environ['PATH']=str(Path(node).parent)+':'+str(Path(sys.executable).parent)+':'+os.environ['PATH']
    data=Path('/data');created=not data.exists()
    if created:data.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix='sqlite-spill-') as folder:
        root=Path(folder);volume=root/'volume';tiny=root/'tiny';volume.mkdir();tiny.mkdir()
        subprocess.run(['mount','--bind',str(volume),str(data)],check=True)
        subprocess.run(['mount','-t','tmpfs','-o','size=16m,mode=1777','tmpfs',str(tiny)],check=True)
        results=[]
        try:
            for game in ['jenga','swanopoly']:
                fixture=fixtures.RealWalTests('runTest');fixture.setUp()
                try:
                    request,env,paths,writers=fixture.fixture(game)
                    table=request['store_specs'][0]['immutable_tables'][0]
                    fixture.sql(writers[0],f"WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1024) INSERT INTO {table} SELECT printf('large-%08d',x),zeroblob(32768) FROM n;")
                    env.update(SQLITE_TMPDIR=str(tiny),TMPDIR=str(tiny))
                    backup=fixture.call(request,env,'backup').stdout
                    _,files=fixture.frames(backup);snapshot=fixture.root/'closed.sqlite';snapshot.write_bytes(files['game'])
                    baseline=r'''
import sqlite3,sys
db=sqlite3.connect(sys.argv[1]);db.execute('PRAGMA temp_store=FILE');db.execute("PRAGMA temp_store_directory='"+sys.argv[4]+"'")
db.execute('ATTACH DATABASE ? AS snapshot',(sys.argv[2],))
try:db.execute('SELECT count(*) FROM(SELECT * FROM main."'+sys.argv[3]+'" EXCEPT SELECT * FROM snapshot."'+sys.argv[3]+'")').fetchone()
except sqlite3.OperationalError as error:
 assert str(error)=='database or disk is full';print('EXPECTED_DISK_FULL')
else:raise AssertionError('Large EXCEPT unexpectedly fit in 16 MiB')
finally:db.close()
'''
                    command=[sys.executable,'-c',baseline,str(paths[0]),str(snapshot),table,str(tiny)]
                    if game=='swanopoly':
                        baseline_node=r'''
const {DatabaseSync}=require('node:sqlite'),a=process.argv.slice(1),db=new DatabaseSync(a[0]);
const literal=s=>"'"+s.replaceAll("'","''")+"'";
db.exec('PRAGMA temp_store=FILE;PRAGMA temp_store_directory='+literal(a[3]));
db.exec('ATTACH DATABASE '+literal(a[1])+' AS snapshot');
try{db.prepare('SELECT count(*) FROM(SELECT * FROM main."'+a[2]+'" EXCEPT SELECT * FROM snapshot."'+a[2]+'")').get();console.log('BASELINE_COMPLETED');}
catch(error){if(!String(error.message).includes('database or disk is full'))throw error;console.log('EXPECTED_DISK_FULL');}
finally{db.close();}
'''
                        command=[node,'-e',baseline_node,str(paths[0]),str(snapshot),table,str(tiny)]
                    p=subprocess.run(command,capture_output=True,text=True,env=env,timeout=60)
                    assert p.returncode==0 and p.stdout.strip() in {'EXPECTED_DISK_FULL','BASELINE_COMPLETED'},p.stderr
                    if game=='jenga':assert p.stdout.strip()=='EXPECTED_DISK_FULL'
                    verified=json.loads(fixture.call(request,env,'verify',backup).stdout)
                    assert all(all(v==0 for v in store['missing_or_changed_row_counts'].values()) for store in verified['stores'])
                    assert not list((Path('/data')/('.msgctf-storage-'+str(os.geteuid()))).iterdir())
                    results.append({'game':game,'small_tmp_bytes':16*1024*1024,'immutable_payload_bytes':32*1024*1024,
                                    'default_sqlite_spill_failed':p.stdout.strip()=='EXPECTED_DISK_FULL','private_pvc_stage_verify_passed':True,'scratch_cleaned':True})
                finally:fixture.tearDown()
        finally:
            subprocess.run(['umount',str(tiny)],check=True);subprocess.run(['umount',str(data)],check=True)
    if created:data.rmdir()
    print(json.dumps({'actual_python_and_node_small_tmp_regressions':results}))

if __name__=='__main__':run()
