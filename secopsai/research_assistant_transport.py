"""Authenticated hosted delivery; the canonical ledger owns assistant results."""
from __future__ import annotations

import json
import re

import soc_store
from secopsai.research_operation_store import append, canonical, digest, records, read_connection, transaction
from secopsai.sqlite_writer_lock import sqlite_writer_lock


def sync_hosted(client, *, db_path=None) -> dict:
    if not getattr(client, 'enabled', False):
        return {'status': 'disabled', 'publication_performed': False}
    from secopsai.research_assistant_team import advance_due, get_team
    from secopsai.specialist_orchestrator import get_policy, get_run, cancel_run, record_primary_result, record_review_result
    from secopsai.intelligence import prepare_bridge_request, validate_bridge_result
    from secopsai.core_edge_client import CoreEdgeHTTPError

    get_policy(db_path=db_path)
    advanced = advance_due(db_path=db_path)
    delivered, applied, canceled, rejected = 0, 0, 0, 0
    with sqlite_writer_lock(db_path):
        with read_connection(db_path) as conn:
            rows = conn.execute("""SELECT j.job_id,j.action,j.target_id,j.status,j.input_json
              FROM intelligence_jobs j JOIN specialist_runs s ON s.run_id=j.target_id
              WHERE json_extract(s.contract_json, '$.task.research_team_transport')='hosted'
                AND j.status IN ('queued','awaiting_provider','canceled')
                AND NOT EXISTS (SELECT 1 FROM research_operation_records r WHERE r.kind='assistant_transport_terminal' AND r.case_id=j.job_id)
              ORDER BY j.queued_at,j.job_id LIMIT 10""").fetchall()
        pending = {}
        for row in rows:
            job = dict(row)
            run = get_run(job['target_id'], db_path=db_path)
            team = get_team(run['contract']['task']['research_team_id'], db_path=db_path)
            receipt = records('assistant_delivery', case_id=job['job_id'], db_path=db_path, limit=1)
            stop = team['status'] in {'stale', 'canceled', 'cancel_requested', 'failed'} or job['status'] == 'canceled'
            if stop:
                cancel_run(run['run_id'], actor=team['actor'], db_path=db_path)
                if receipt:
                    remote_id = receipt[0]['payload']['remote_job_id']
                    response = client.cancel_assistant_jobs([remote_id])
                    if remote_id not in response.get('canceled', []):
                        continue  # A missing acknowledgement is retried.
                append('assistant_transport_terminal', {'status': 'canceled'}, actor=team['actor'], case_id=job['job_id'], db_path=db_path)
                canceled += 1
                continue
            if not receipt:
                outbox = records('assistant_outbox', case_id=job['job_id'], db_path=db_path, limit=1)
                if not outbox:
                    request = prepare_bridge_request(job['action'], {'specialist_run_id': run['run_id']}, db_path=db_path)
                    request['instructions'] += ' Return no more than 48 KB of structured output. If evidence is incomplete, name missing evidence and preserve limitations.'
                    inputs = json.loads(job['input_json'])
                    inputs.update({'assistant_request': request, 'target_id': run['run_id']})
                    payload = {'action': job['action'], 'target_id': run['run_id'], 'inputs': inputs, 'idempotency_key': 'assistant:' + job['job_id']}
                    if len(canonical(payload).encode()) > 60000:
                        _terminal(job, team, status='failed', reason='assistant_context_exceeds_budget', db_path=db_path)
                        rejected += 1
                        continue
                    # Persist before sending: even a lost HTTP response must
                    # retry the same evidence, prompt and requested_at value.
                    outbox = [append('assistant_outbox', payload, actor=team['actor'], case_id=job['job_id'], db_path=db_path)]
                try:
                    response = client.queue_assistant_job(outbox[0]['payload'])
                except CoreEdgeHTTPError as error:
                    if error.status not in {400, 401, 403, 409, 413, 422}:
                        raise
                    _terminal(job, team, status='failed', reason='assistant_delivery_rejected', db_path=db_path)
                    rejected += 1
                    continue
                remote_id = (response.get('job') or {}).get('job_id')
                if not isinstance(remote_id, str) or not re.fullmatch(r'AIJ-[A-F0-9]{16}', remote_id):
                    raise ValueError('hosted assistant queue did not return a job identity')
                receipt = [append('assistant_delivery', {'remote_job_id': remote_id, 'payload_hash': digest(outbox[0]['payload'])}, actor=team['actor'], case_id=job['job_id'], db_path=db_path)]
                delivered += 1
            pending[receipt[0]['payload']['remote_job_id']] = (job, run, team)
        if pending:
            response = client.assistant_results(list(pending))
            for item in response.get('results', []):
                if not isinstance(item, dict) or item.get('job_id') not in pending:
                    continue
                job, run, team = pending[item['job_id']]
                if item.get('status') not in {'succeeded', 'failed', 'canceled'}:
                    continue
                if item['status'] != 'succeeded':
                    _terminal(job, team, status='failed' if item['status'] == 'failed' else 'canceled', reason='hosted_assistant_provider_failed', db_path=db_path)
                    rejected += 1
                    continue
                try:
                    model = item.get('model')
                    allowed = [run['selected_model']] + (run['fallback_models'] if run['fallback_mode'] != 'disabled' else [])
                    if item.get('action') != job['action'] or item.get('target_id') != run['run_id'] or model not in allowed:
                        raise ValueError('assistant result identity or captured model mismatch')
                    validated = validate_bridge_result(job['action'], item.get('result'), provider=item.get('provider') or 'hosted_core_bridge')
                    output = validated['data']
                    if any(not output.get(key) for key in ('summary', 'risk_assessment', 'evidence', 'recommended_actions', 'limitations')):
                        raise ValueError('incomplete assistant result')
                    prior = run['result' if job['action'] == 'execute_specialist_work' else 'review']
                    if prior:
                        if prior.get('output') != output or prior.get('model') != model:
                            raise ValueError('conflicting assistant result delivery')
                    else:
                        handler = record_primary_result if job['action'] == 'execute_specialist_work' else record_review_result
                        handler(run['run_id'], output, model=model, actor='hosted-assistant-reconciliation', db_path=db_path)
                    _terminal(job, team, status='succeeded', result=validated, db_path=db_path)
                    applied += 1
                except (ValueError, TypeError, KeyError):
                    _terminal(job, team, status='failed', reason='invalid_hosted_assistant_result', db_path=db_path)
                    rejected += 1
    return {'status': 'ok', 'advanced': len(advanced['processed']), 'delivered': delivered, 'applied': applied, 'canceled': canceled, 'rejected': rejected, 'publication_performed': False}


def _terminal(job, team, *, status, reason='', result=None, db_path=None):
    with transaction(db_path) as conn:
        # Canonical hosted jobs are never claimed by a local model process.
        # Keep local lease fencing intact; refuse to replace a local running job.
        changed = conn.execute("""UPDATE intelligence_jobs SET status=?,result_json=?,error_code=?,error_message=?,completed_at=?,updated_at=?
          WHERE job_id=? AND status IN ('queued','awaiting_provider','canceled')""",
          (status, canonical(result or {}), reason or None, reason or None, soc_store.utc_now(), soc_store.utc_now(), job['job_id'])).rowcount
        if not changed:
            raise ValueError('hosted assistant reconciliation cannot replace a locally owned job')
        append('assistant_transport_terminal', {'status': status, 'reason': reason, 'result_hash': digest(result or {})}, actor=team['actor'], case_id=job['job_id'], connection=conn)
