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
 ('socket_index','https://socket.dev/blog',b'<script><a href="/blog/fake">Fake</a></script><a href="/blog/category/security">Navigation</a><a href="/blog/fixture">Fixture</a>',1),
])
def test_reviewed_source_indexes_are_scoped_leads(parser,url,body,count):
    items = parse_source({'parser':parser,'url':url},body)
    assert len(items) == count and all(x['assessment']=='source_reported' and not x['observed_exploitation_by_secopsai'] for x in items)
    assert all(x['collection_scope'].startswith('bounded_') for x in items)


@pytest.mark.parametrize('parser,body',[('jfrog_index',b'<html>challenge page</html>'),('socket_index',b'<html>no articles</html>'),('github_advisories',b'{"message":"API denied"}'),('openvsx_index',b'{}')])
def test_malformed_or_challenged_indexes_cannot_advance(parser,body):
    with pytest.raises(ValueError): parse_source({'parser':parser,'url':'https://vendor.example/'},body)
