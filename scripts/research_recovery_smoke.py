"""Read-only production checkpoint restore and reconciliation in disposable storage."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
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
    if shutil.disk_usage(tempfile.gettempdir()).free < manifest['size_bytes'] + 1024**3:
        raise ValueError('insufficient isolated recovery capacity')
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
        total_seconds = time.monotonic()-start
        result = {'status':'passed','scope':'isolated_restore_of_exact_production_checkpoint',
                  'production_modified':False,'model_jobs_created':0,'execution_performed':False,
                  'sha256':manifest['sha256'],'captured_at':manifest['captured_at'],'restored_bytes':manifest['size_bytes'],
                  'restore_seconds':round(restore_seconds,3),'reconciliation_seconds':round(total_seconds-restore_seconds,3),
                  'rto_target_met':total_seconds<=3600,'source_archives_hash_verified':verified_sources,
                  'tables':counts,'rpo_target_proven':False,
                  'limitations':['An exact restore proves this checkpoint; live committed-loss bounds require repeated capture/commit timing and crash drills.']}
    if not result['rto_target_met']:
        result['status']='failed'
    output=Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2))
    print(json.dumps({k:v for k,v in result.items() if k!='tables'}))
    return 0 if result['status']=='passed' else 1


if __name__=='__main__':
    raise SystemExit(main())
