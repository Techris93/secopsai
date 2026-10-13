#!/usr/bin/env python3
"""Read-only audit of historical decision failures. Does not requeue or relabel."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote


def audit(path: Path, limit: int = 10000) -> dict:
    connection = sqlite3.connect('file:' + quote(str(path.resolve()), safe='/') + '?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    candidates = []
    scanned = {}
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'intelligence_jobs' in tables:
            rows = connection.execute("SELECT job_id, action, provider, input_json, result_json FROM intelligence_jobs WHERE status='succeeded' ORDER BY updated_at DESC LIMIT ?", (limit,))
            scanned['intelligence_jobs'] = 0
            for row in rows:
                scanned['intelligence_jobs'] += 1
                try:
                    raw = json.loads(row['result_json'])
                    result = raw.get('data', raw)
                    reasons = []
                    model = str(json.loads(row['input_json']).get('selected_model', ''))
                    typed = 'typesafe' in row['provider'] or 'jev' in row['provider'] or 'clef' in row['provider'] or model.startswith(('typesafe/', 'typesafe-ai/', 'cloudflare/clef'))
                    if typed and row['action'] not in {'triage_artifact', 'triage_finding'}: reasons.append('unsupported_typed_action')
                    if typed and result.get('verdict_recommendation') == 'credible' and result.get('verdict_confidence') == 85: reasons.append('historical_generic_verdict')
                    if row['action'] == 'triage_artifact' and any(key not in result for key in ('finding_verdict', 'finding_confidence', 'malicious_probability')): reasons.append('missing_artifact_decision')
                    if reasons: candidates.append({'record_id': row['job_id'], 'reasons': reasons})
                except (ValueError, TypeError, AttributeError):
                    candidates.append({'record_id': row['job_id'], 'reasons': ['invalid_saved_result']})
        if 'research_alerts' in tables:
            rows = connection.execute("SELECT alert_id, evidence_json FROM research_alerts WHERE owner='clef' AND status='resolved' ORDER BY updated_at DESC LIMIT ?", (limit,))
            scanned['clef_resolved_alerts'] = 0
            for row in rows:
                scanned['clef_resolved_alerts'] += 1
                try:
                    clef = json.loads(row['evidence_json']).get('clef', {})
                    if clef.get('choice') is None or 'evidence_coverage' not in clef:
                        candidates.append({'record_id': row['alert_id'], 'reasons': ['unvalidated_clef_closure']})
                except (ValueError, TypeError, AttributeError):
                    candidates.append({'record_id': row['alert_id'], 'reasons': ['invalid_saved_result']})
    finally:
        connection.close()
    return {'read_only': True, 'limit_per_table': limit, 'scanned': scanned, 'candidate_count': len(candidates), 'candidates': candidates,
            'note': 'Candidates require review; this audit does not establish that their original verdict was wrong.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True, type=Path)
    parser.add_argument('--limit', type=int, default=10000)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    output = json.dumps(audit(args.db, max(1, min(args.limit, 100000))), indent=2) + '\n'
    if args.out: args.out.write_text(output)
    else: print(output, end='')


if __name__ == '__main__':
    main()
