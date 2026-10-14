"""Disposable deterministic fuzzing of SecOpsAI-owned source parsers only.

No package code, arbitrary commands, provider credentials or network calls enter
this harness. Results are reproducible software checks, not original discoveries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

from secopsai.research_primary_intel import parse_source

TARGETS = {
    'rss': b'<rss version="2.0"><channel><title>Fixture</title><link>https://example.org/</link><description>Fixture</description><item><guid>one</guid><title>Notice</title><link>https://example.org/notice</link><description>Fixture</description></item></channel></rss>',
    'normalized_json': b'{"events":[{"external_id":"one","title":"Notice","url":"https://example.org/notice","excerpt":"Fixture"}]}',
    'github_advisories': b'[{"ghsa_id":"GHSA-abcd-1234-5678","html_url":"https://github.com/advisories/GHSA-abcd-1234-5678","summary":"Fixture","description":"Fixture"}]',
    'openvsx_index': b'{"extensions":[{"namespace":"fixture","name":"tool","version":"1","url":"https://open-vsx.org/api/fixture/tool","description":"Fixture"}]}',
    'jfrog_index': b'<a href="/vulnerabilities/fixture/">Fixture vulnerability</a>',
    'socket_index': b'<a href="/blog/fixture">Fixture article</a>',
}


def _mutate(body, rng):
    value = bytearray(body)
    for _ in range(rng.randint(1, 5)):
        operation = rng.randrange(3)
        offset = rng.randrange(len(value) + 1)
        if operation == 0 and offset < len(value):
            del value[offset:offset + rng.randint(1, 8)]
        elif operation == 1:
            value[offset:offset] = bytes([rng.randrange(256)])
        elif offset < len(value):
            value[offset] ^= 1 << rng.randrange(8)
    return bytes(value)


def _exercise(seed, cases):
    rng = random.Random(seed)
    accepted, rejected, failures = 0, 0, []
    corpus = hashlib.sha256()
    for index in range(cases):
        parser = sorted(TARGETS)[index % len(TARGETS)]
        body = TARGETS[parser] if index < len(TARGETS) else _mutate(TARGETS[parser], rng)
        corpus.update(parser.encode() + b'\0' + len(body).to_bytes(4,'big') + body)
        url = 'https://research.jfrog.com/' if parser=='jfrog_index' else 'https://socket.dev/blog' if parser=='socket_index' else 'https://example.org/'
        try:
            result = parse_source({'parser':parser,'url':url},body)
            if not isinstance(result,list) or any(r.get('assessment')!='source_reported' or r.get('observed_exploitation_by_secopsai') is not False for r in result):
                raise AssertionError('parser result violated the evidence boundary')
            accepted += 1
        except (ValueError, KeyError, TypeError, UnicodeError):
            rejected += 1
        except Exception as error:
            failures.append({'index':index,'parser':parser,'input_sha256':hashlib.sha256(body).hexdigest(),'error_category':type(error).__name__})
    return {'status':'passed' if not failures else 'failed','seed':seed,'cases':cases,'accepted':accepted,'rejected':rejected,
            'failures':failures[:25],'failure_count':len(failures),'corpus_sha256':corpus.hexdigest(),
            'targets':sorted(TARGETS),'scope':'SecOpsAI-owned parser software with synthetic fixtures',
            'network_performed':False,'package_execution_performed':False,'model_jobs_created':0,
            'limitations':['A bounded deterministic mutation run does not establish absence of vulnerabilities or independently reproduced incident findings.']}


def run_lab(*, seed=1, cases=1000, seconds=30):
    if type(seed) is not int or not 0<=seed<=2**32-1 or type(cases) is not int or not 6<=cases<=2000 or type(seconds) is not int or not 1<=seconds<=60:
        raise ValueError('invalid bounded parser-lab configuration')
    with tempfile.TemporaryDirectory(prefix='secopsai-parser-lab-') as directory:
        environment = {'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':directory,'TMPDIR':directory,
                       'PYTHONHASHSEED':'0','PYTHONDONTWRITEBYTECODE':'1'}
        try:
            result = subprocess.run([sys.executable,'-m','secopsai.research_parser_lab','--child','--seed',str(seed),'--cases',str(cases)],
                                    cwd=Path(__file__).resolve().parents[1],env=environment,capture_output=True,text=True,timeout=seconds,check=False)
        except subprocess.TimeoutExpired:
            return {'status':'failed','reason':'laboratory_deadline','seed':seed,'cases':cases,'network_performed':False,'package_execution_performed':False}
        if result.returncode or len(result.stdout.encode())>65536:
            return {'status':'failed','reason':'laboratory_process_failure','seed':seed,'cases':cases,'network_performed':False,'package_execution_performed':False}
        report=json.loads(result.stdout)
        return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=int,default=1)
    parser.add_argument('--cases',type=int,default=1000)
    parser.add_argument('--output')
    parser.add_argument('--child',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.child:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU,(30,30))
        if sys.platform!='darwin': resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
        import socket
        def denied(*a,**kw): raise RuntimeError('network is disabled in the parser lab')
        socket.socket=denied
        if type(args.seed) is not int or not 0<=args.seed<=2**32-1 or not 6<=args.cases<=2000:
            raise ValueError('invalid lab bounds')
        report=_exercise(args.seed,args.cases)
    else:
        report=run_lab(seed=args.seed,cases=args.cases)
    if args.output and not args.child:
        destination=Path(args.output)
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_text(json.dumps(report,indent=2))
    print(json.dumps(report))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':
    raise SystemExit(main())
