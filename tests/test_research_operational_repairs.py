import hashlib
import io
import json
from email.message import Message

import pytest

from secopsai.research_intake import IntakeError
from secopsai.research_primary_intel import parse_source
from secopsai.research_source_transport import fetch_source


RSS = b'<rss version="2.0"><channel><title>CISA</title><link>https://www.cisa.gov/</link><description>Fixture</description><item><guid>notice</guid><title>Notice</title><link>https://www.cisa.gov/notice</link><description>Fixture</description></item></channel></rss>'


def test_relay_uses_fixed_original_source_and_checks_provenance(monkeypatch):
    url = 'https://www.cisa.gov/news.xml'
    monkeypatch.setenv('LEDGER_STORE_URL', 'https://ledger.secopsai.dev')
    monkeypatch.setenv('LEDGER_STORE_TOKEN', 'synthetic-private-token')
    class Denied:
        def get(self, *a, **kw):
            raise IntakeError('registry returned HTTP 403')
    class Relay:
        def open(self, request, timeout):
            assert request.full_url == 'https://ledger.secopsai.dev/public-sources/cisa-news'
            assert request.get_header('Authorization') == 'Bearer synthetic-private-token'
            response = io.BytesIO(RSS)
            response.headers = Message()
            response.headers['x-secopsai-source-url'] = url
            response.headers['x-secopsai-source-sha256'] = hashlib.sha256(RSS).hexdigest()
            return response
    monkeypatch.setattr('urllib.request.build_opener', lambda *a: Relay())
    final, headers, body = fetch_source(url, headers={}, max_bytes=4096, fetcher=Denied())
    assert final == url and body == RSS and headers['secopsai-transport'] == 'cloudflare-fixed-source-relay'
    class Corrupt(Relay):
        def open(self, *a, **kw):
            response = super().open(*a, **kw)
            response.headers.replace_header('x-secopsai-source-sha256', '0'*64)
            return response
    monkeypatch.setattr('urllib.request.build_opener', lambda *a: Corrupt())
    with pytest.raises(IntakeError, match='provenance'):
        fetch_source(url, headers={}, max_bytes=4096, fetcher=Denied())


def test_no_relay_or_credentials_for_arbitrary_urls(monkeypatch):
    monkeypatch.setenv('LEDGER_STORE_URL','https://attacker.example')
    monkeypatch.setenv('LEDGER_STORE_TOKEN','synthetic-private-token')
    monkeypatch.setattr('urllib.request.build_opener', lambda *a: pytest.fail('credentials escaped'))
    class Denied:
        def get(self, *a, **kw): raise IntakeError('registry returned HTTP 403')
    for url in ['https://www.cisa.gov/news.xml','https://attacker.example/feed']:
        with pytest.raises(IntakeError, match='403'):
            fetch_source(url, headers={}, max_bytes=4096, fetcher=Denied())


@pytest.mark.parametrize('parser,url,body,count', [
 ('github_advisories','https://api.github.com/advisories',json.dumps([{'ghsa_id':'GHSA-1234-abcd-5678','html_url':'https://github.com/advisories/GHSA-1234-abcd-5678','summary':'Fixture','description':'Known source report','published_at':'2026-10-14T00:00:00Z','vulnerabilities':[]}]).encode(),1),
 ('openvsx_index','https://open-vsx.org/api/-/search',json.dumps({'extensions':[{'namespace':'fixture','name':'tool','version':'1','description':'New release','url':'https://open-vsx.org/api/fixture/tool','timestamp':'2026-10-14T00:00:00Z'}]}).encode(),1),
 ('jfrog_index','https://research.jfrog.com/',b'<a href="/vulnerabilities/fixture/">Fixture vulnerability</a><a href="/vulnerabilities/">Navigation</a><a href="https://attacker.example/vulnerabilities/fake/">Wrong host</a>',1),
])
def test_reviewed_source_indexes_are_scoped_leads(parser,url,body,count):
    items = parse_source({'parser':parser,'url':url},body)
    assert len(items) == count and all(x['assessment']=='source_reported' and not x['observed_exploitation_by_secopsai'] for x in items)
    assert all(x['collection_scope'].startswith('bounded_') for x in items)


@pytest.mark.parametrize('parser,body',[('jfrog_index',b'<html>challenge page</html>'),('github_advisories',b'{"message":"API denied"}'),('openvsx_index',b'{}')])
def test_malformed_or_challenged_indexes_cannot_advance(parser,body):
    with pytest.raises(ValueError): parse_source({'parser':parser,'url':'https://vendor.example/'},body)


def test_interrupted_advisory_processing_cannot_starve_backups_or_primary_intake(tmp_path,monkeypatch):
    from secopsai import research_worker
    from secopsai.worker_control import WorkerShutdown
    events=[]
    monkeypatch.setenv('SECOPSAI_PRIMARY_INTEL','1')
    monkeypatch.setattr(research_worker,'maintain_research_storage',lambda **kw:{})
    monkeypatch.setattr(research_worker,'_record_storage_capacity_alert',lambda *a,**kw:None)
    monkeypatch.setattr('secopsai.research_artifact_vault.backup_public_artifacts',lambda **kw:events.append('backup') or {'status':'succeeded'})
    monkeypatch.setattr('secopsai.research_primary_intel.collect_due',lambda **kw:events.append('primary') or {'status':'succeeded'})
    monkeypatch.setattr('secopsai.research_editorial.scheduled_brief',lambda **kw:events.append('brief') or {'status':'blocked'})
    def expensive(**kw):
        events.append('external')
        assert kw['sync_limit']==100
        raise WorkerShutdown('synthetic budget stop')
    monkeypatch.setattr(research_worker,'refresh_and_sync',expensive)
    with pytest.raises(WorkerShutdown):
        research_worker._run_worker_cycle_unlocked(db_path=str(tmp_path/'worker.db'))
    assert events==['backup','primary','external']


CSAF_OT = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/'


def _rolie(*entries):
    return json.dumps({'feed': {'id': 'cisa-csaf-ot-feed-tlp-white', 'entry': [
        {'id': advisory, 'title': title, 'published': updated, 'updated': updated,
         'content': {'src': CSAF_OT + '2026/' + advisory.lower() + '.json', 'type': 'application/json'}}
        for advisory, title, updated in entries]}}).encode()


def test_cisa_csaf_feed_keeps_recent_advisories_and_counts_the_rest_as_historical():
    from secopsai.research_primary_intel import parse_source_report, source_byte_limit, MAX_SOURCE_BYTES
    body = _rolie(('ICSA-26-307-01', 'Subnet Solutions PowerSYSTEM Center', '2026-11-03T06:00:00.000000Z'),
                  ('ICSA-25-160-01', 'Old advisory', '2025-06-09T06:00:00.000000Z'))
    report = parse_source_report({'parser': 'cisa_csaf_rolie', 'url': CSAF_OT + 'cisa-csaf-ot-feed-tlp-white.json'}, body,
                                 now='2026-11-04T20:00:00Z')
    assert (report['events_total'], report['events_in_scope'], report['historical_excluded']) == (2, 1, 1)
    assert report['window_start'] == '2026-10-21T20:00:00Z'
    [item] = report['items']
    assert item['external_id'] == 'ICSA-26-307-01' and item['title'] == 'ICSA-26-307-01: Subnet Solutions PowerSYSTEM Center'
    assert item['url'] == CSAF_OT + '2026/icsa-26-307-01.json' and item['published_at'] == '2026-11-03T06:00:00Z'
    assert item['assessment'] == 'source_reported' and item['observed_exploitation_by_secopsai'] is False
    # The complete ICS catalogue is larger than the general source budget.
    assert source_byte_limit('cisa_csaf_rolie') > 4_500_000 and source_byte_limit('rss') == MAX_SOURCE_BYTES


@pytest.mark.parametrize('body', [b'{}', b'<html>Access Denied</html>', json.dumps({'feed': {'entry': []}}).encode(),
                                  _rolie(('ICSA-26-307-01', 'Undated', ''))])
def test_malformed_cisa_csaf_feed_cannot_advance(body):
    with pytest.raises(ValueError):
        parse_source({'parser': 'cisa_csaf_rolie', 'url': CSAF_OT}, body)


def test_ics_advisory_links_point_readers_to_cisa_pages():
    from secopsai.research_editorial import _reader_url
    assert _reader_url(CSAF_OT + '2026/icsa-26-307-01.json', []) == 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01'
    it = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-294-01.json'
    assert _reader_url(it, []) == it
    assert _reader_url('https://attacker.example/icsa-26-307-01.json', []) == 'https://attacker.example/icsa-26-307-01.json'
