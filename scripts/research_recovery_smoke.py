"""Read-only production checkpoint restore and reconciliation in disposable storage."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sqlite3
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('secopsai_checkpoint_supervisor', root/'cloudflare/secopsai-research-runner/container/supervisor.py')
    supervisor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(supervisor)
    store = supervisor.LedgerStore(os.environ['LEDGER_STORE_URL'],os.environ['LEDGER_STORE_TOKEN'])
    manifest = json.loads(store._request('GET','/checkpoint-manifest',deadline=time.monotonic()+60))
    if not supervisor.valid_manifest(manifest):
        raise ValueError('invalid recovery manifest')
    start = time.monotonic()
    if shutil.disk_usage(tempfile.gettempdir()).free < manifest['size_bytes'] * 3 + 1024**3:
        raise ValueError('insufficient isolated recovery capacity')
    os.environ['SECOPSAI_INCREMENTAL_CHECKPOINTS']='1'
    with tempfile.TemporaryDirectory(prefix='secopsai-recovery-') as directory:
        os.chmod(directory,0o700)
        destination = Path(directory)/'recovered.db'
        store.download_chunked(destination,manifest)
        restore_seconds = time.monotonic()-start
        with sqlite3.connect(f'file:{destination}?mode=ro',uri=True) as conn:
            if conn.execute('PRAGMA foreign_key_check').fetchone():
                raise ValueError('recovered foreign key inconsistency')
            names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            counts = {}
            for name in names:
                if not name.replace('_','').isalnum():
                    raise ValueError('invalid recovered table identity')
                counts[name] = conn.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
            verified_sources = 0
            if 'research_source_snapshots' in names:
                for content,digest in conn.execute('SELECT content,sha256 FROM research_source_snapshots'):
                    if hashlib.sha256(content).hexdigest() != digest:
                        raise ValueError('recovered source archive checksum mismatch')
                    verified_sources += 1
        # An independent crash drill writes only a private copy and a separate
        # checkpoint namespace; the production LATEST pointer is never touched.
        with sqlite3.connect(destination) as conn:
            conn.execute('CREATE TABLE secopsai_recovery_drill_marker (seq INTEGER PRIMARY KEY, committed_ns INTEGER NOT NULL)')
            conn.execute('INSERT INTO secopsai_recovery_drill_marker VALUES (0,?)',(time.time_ns(),))
        store.checkpoint_scope='drill'
        supervisor.checkpoint(destination,store,Path(directory))
        isolated_manifest=json.loads(store._request('GET','/checkpoint-manifest',deadline=time.monotonic()+60))
        writer_code="import sqlite3,time,sys; c=sqlite3.connect(sys.argv[1]); i=1\nwhile True:\n c.execute('INSERT INTO secopsai_recovery_drill_marker VALUES (?,?)',(i,time.time_ns())); c.commit(); i+=1; time.sleep(.05)"
        writer=subprocess.Popen([sys.executable,'-c',writer_code,str(destination)],env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':directory})
        failed_commit_verified=False
        request=store._request
        def interrupted(method,path,*a,**kw):
            if method=='POST' and path=='/checkpoints':
                raise ConnectionError('synthetic lost checkpoint before manifest commit')
            return request(method,path,*a,**kw)
        try:
            time.sleep(1)
            store._request=interrupted
            try:
                supervisor.checkpoint(destination,store,Path(directory))
            except ConnectionError:
                failed_commit_verified=True
        finally:
            store._request=request
            writer.kill()
            writer.wait(timeout=10)
        crash_ns=time.time_ns()
        unchanged=json.loads(store._request('GET','/checkpoint-manifest',deadline=time.monotonic()+60))
        if not failed_commit_verified or unchanged!=isolated_manifest:
            raise ValueError('failed isolated checkpoint advanced the durable pointer')
        with sqlite3.connect(destination) as conn:
            committed_rows=conn.execute('SELECT count(*) FROM secopsai_recovery_drill_marker').fetchone()[0]
        recovered=Path(directory)/'crash-restored.db'
        store.download_chunked(recovered,isolated_manifest)
        with sqlite3.connect(recovered) as conn:
            retained_rows,last_ns=conn.execute('SELECT count(*),max(committed_ns) FROM secopsai_recovery_drill_marker').fetchone()
        loss_seconds=max(0,(crash_ns-last_ns)/1e9)
        total_seconds = time.monotonic()-start
        result = {'status':'passed','scope':'isolated_restore_of_exact_production_checkpoint',
                  'production_modified':False,'model_jobs_created':0,'package_execution_performed':False,'synthetic_writer_executed':True,
                  'sha256':manifest['sha256'],'captured_at':manifest['captured_at'],'restored_bytes':manifest['size_bytes'],
                  'restore_seconds':round(restore_seconds,3),'reconciliation_seconds':round(total_seconds-restore_seconds,3),
                  'rto_target_met':total_seconds<=3600,'source_archives_hash_verified':verified_sources,
                  'tables':counts,'rpo_target_proven':False,'rpo_drill_target_met':loss_seconds<=300,'maximum_committed_loss_seconds':round(loss_seconds,3),
                  'isolated_committed_rows':committed_rows,'isolated_restored_rows':retained_rows,
                  'failed_commit_preserved_previous_checkpoint':failed_commit_verified,
                  'limitations':['This production-size isolated crash drill proves the measured scenario; sustained production guarantees require continued capture/commit monitoring.']}
    if not result['rto_target_met'] or not result['rpo_drill_target_met']:
        result['status']='failed'
    output=Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2))
    print(json.dumps({k:v for k,v in result.items() if k!='tables'}))
    return 0 if result['status']=='passed' else 1


if __name__=='__main__':
    raise SystemExit(main())
