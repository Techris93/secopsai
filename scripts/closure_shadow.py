#!/usr/bin/env python3
"""Shadow test of automatic closure on production verdicts (read-only).

Closure is off (SECOPSAI_DECISION_MODE=observe) and stays off until a
held-out evaluation passes and the user approves the manifest. This report
adds the production side: it restores a copy of the research ledger, applies
the frozen closure rules (decision_policy.closure_candidate: benign verdict,
probability <= 10, confidence >= 70, complete evidence) to every stored model
verdict, and checks each release the rules WOULD have closed against what
became known later:

- an OSV ``MAL-`` record for that exact version (a wrong closure), and
- whether the registry still serves the version (removed releases are listed
  for a person to look at; authors also remove releases, so a removal is not
  proof of malware).

Only verdicts at least ``--settle-days`` old count, so outside reporters have
had time to publish. Nothing is closed, changed or written back.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sqlite3
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cloudflare" / "secopsai-research-runner" / "container"))

from secopsai.decision_policy import closure_candidate  # noqa: E402

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}
EVALUATED = set(OSV_ECOSYSTEMS)
# Gate for reporting the shadow as clean (closure still needs the held-out
# evaluation and the user's approval of the manifest).
MIN_SETTLED_CLOSES = 200


def _parse(stamp: str) -> Optional[dt.datetime]:
    try:
        value = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def classify(rows: Iterable[Dict[str, Any]], *, now: dt.datetime, settle_days: float) -> List[Dict[str, Any]]:
    """One record per triaged verdict: would the frozen rules close it, and is it settled?"""
    out = []
    for row in rows:
        try:
            result = json.loads(row.get("result_json") or "{}")
        except ValueError:
            continue
        if not isinstance(result, dict) or "malicious_probability" not in result:
            continue
        would, reason = closure_candidate(result)
        when = _parse(row.get("updated_at") or "")
        out.append({
            "ecosystem": row["ecosystem"], "package": row["package"], "version": row["version"],
            "would_close": bool(would), "reason": reason,
            "settled": bool(when and (now - when).total_seconds() >= settle_days * 86400),
            "evaluated_ecosystem": row["ecosystem"] in EVALUATED,
            "verdict": result.get("finding_verdict"), "probability": result.get("malicious_probability"),
            "confidence": result.get("finding_confidence"), "model": f"{result.get('provider', '')}:{result.get('model_version', '')}",
            "evidence_contract": ((result.get("evidence_coverage") or {}).get("contract") or ""), "updated_at": row.get("updated_at", ""),
        })
    return out


def osv_malicious(items: List[Dict[str, Any]], *, post=None, batch: int = 500) -> Dict[int, List[str]]:
    """Index -> MAL- ids for the exact versions in ``items``. Raises when OSV
    cannot answer: an unchecked release must never count as clean."""
    if post is None:
        import requests

        def post(body):
            response = requests.post(OSV_BATCH_URL, json=body, timeout=60)
            response.raise_for_status()
            return response.json()
    found: Dict[int, List[str]] = {}
    for start in range(0, len(items), batch):
        chunk = items[start:start + batch]
        queries = [{"package": {"name": item["package"], "ecosystem": OSV_ECOSYSTEMS[item["ecosystem"]]}, "version": item["version"]} for item in chunk]
        answers = post({"queries": queries}).get("results") or []
        if len(answers) != len(chunk):
            raise ValueError("OSV returned a different number of answers")
        for offset, answer in enumerate(answers):
            ids = [str(v.get("id")) for v in answer.get("vulns") or [] if str(v.get("id", "")).startswith("MAL-")]
            if ids:
                found[start + offset] = ids
    return found


def registry_status(item: Dict[str, Any], *, get=None) -> str:
    """listed / removed / unknown for the exact version."""
    if get is None:
        import requests

        def get(url):
            return requests.get(url, timeout=30, headers={"Accept": "application/json"})
    try:
        if item["ecosystem"] == "pypi":
            response = get(f"https://pypi.org/pypi/{item['package']}/{item['version']}/json")
            if response.status_code == 404:
                return "removed"
            files = response.json().get("urls") or []
            return "removed" if files and all(f.get("yanked") for f in files) else "listed"
        response = get("https://registry.npmjs.org/" + item["package"].replace("/", "%2F"))
        if response.status_code == 404:
            return "removed"
        return "listed" if item["version"] in (response.json().get("versions") or {}) else "removed"
    except Exception:
        return "unknown"


def report(records: List[Dict[str, Any]], malicious: Dict[int, List[str]], removed: Dict[int, str], *, settle_days: float) -> Dict[str, Any]:
    closes = [r for r in records if r["would_close"] and r["evaluated_ecosystem"]]
    settled = [r for r in closes if r["settled"]]
    wrong = [{**settled[i], "mal_ids": ids} for i, ids in sorted(malicious.items())]
    gone = [{**settled[i], "registry": status} for i, status in sorted(removed.items()) if status == "removed"]
    unknown = sum(1 for status in removed.values() if status == "unknown")
    by_model: Dict[str, Counter] = defaultdict(Counter)
    for r in records:
        if r["evaluated_ecosystem"]:
            by_model[r["model"]]["verdicts"] += 1
            by_model[r["model"]]["would_close"] += r["would_close"]
    passed = len(settled) >= MIN_SETTLED_CLOSES and not wrong
    return {
        "schema_version": "secopsai.closure-shadow.v1",
        "rules": "decision_policy.closure_candidate (benign verdict, p<=10, confidence>=70, complete evidence)",
        "settle_days": settle_days,
        "verdicts": sum(1 for r in records if r["evaluated_ecosystem"]),
        "would_close": len(closes), "would_close_settled": len(settled),
        "would_close_rate": round(len(closes) / max(1, sum(1 for r in records if r["evaluated_ecosystem"])), 4),
        "wrong_closures": wrong, "removed_from_registry": gone, "registry_unknown": unknown,
        "blocked_reasons": dict(Counter(r["reason"] for r in records if r["evaluated_ecosystem"] and not r["would_close"]).most_common()),
        "by_model": {model: dict(counts) for model, counts in sorted(by_model.items())},
        "shadow_clean": passed,
        "verdict": ("clean: no settled closure later marked malicious" if passed else
                    "failed: a closure would have hidden a release later marked malicious" if wrong else
                    f"insufficient: {len(settled)} settled closures (need {MIN_SETTLED_CLOSES})"),
        "limits": ["OSV coverage is not complete: malware nobody reported is invisible here.",
                   "A removed release is not proof of malware; each needs a person to look.",
                   "Shadow results never enable closure: the held-out evaluation and your approval of the manifest are still required."],
    }


def markdown(summary: Dict[str, Any]) -> str:
    lines = ["## Automatic closure: shadow test", "",
             f"**{summary['verdict']}**", "",
             f"- Verdicts on npm/PyPI: {summary['verdicts']}",
             f"- Would close under the frozen rules: {summary['would_close']} ({100 * summary['would_close_rate']:.1f}%)",
             f"- Of those, settled (at least {summary['settle_days']:g} days old): {summary['would_close_settled']}",
             f"- Later marked malicious (OSV MAL-, exact version): **{len(summary['wrong_closures'])}**",
             f"- Since removed from the registry: {len(summary['removed_from_registry'])} (registry unknown: {summary['registry_unknown']})", ""]
    if summary["wrong_closures"]:
        lines += ["Wrong closures:", ""] + [f"- {r['ecosystem']}:{r['package']}@{r['version']} {', '.join(r['mal_ids'])} (p{r['probability']}, c{r['confidence']}, {r['model']})"
                                             for r in summary["wrong_closures"]] + [""]
    if summary["removed_from_registry"]:
        lines += ["Removed since (look at each):", ""] + [f"- {r['ecosystem']}:{r['package']}@{r['version']} (p{r['probability']}, c{r['confidence']})"
                                                           for r in summary["removed_from_registry"][:30]] + [""]
    lines += ["By model:", "", "| Model | Verdicts | Would close |", "| --- | --- | --- |"]
    lines += [f"| {model} | {c.get('verdicts', 0)} | {c.get('would_close', 0)} |" for model, c in summary["by_model"].items()]
    lines += ["", "Why the rest would not close:", ""] + [f"- {reason}: {n}" for reason, n in list(summary["blocked_reasons"].items())[:8]]
    lines += ["", *[f"> {item}" for item in summary["limits"]]]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--settle-days", type=float, default=14)
    parser.add_argument("--ledger", type=Path, help="use this ledger copy instead of downloading one")
    parser.add_argument("--out", type=Path, default=Path(os.environ.get("RUNNER_TEMP", ".")) / "closure-shadow.json")
    args = parser.parse_args()
    db = args.ledger
    if db is None:
        from supervisor import LedgerStore

        db = Path(tempfile.mkdtemp(prefix="closure-shadow-")) / "ledger.db"
        if not LedgerStore(os.environ["LEDGER_STORE_URL"], os.environ["LEDGER_STORE_TOKEN"]).download(db):
            raise SystemExit("no ledger snapshot")
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    rows = [dict(row) for row in connection.execute(
        "SELECT ecosystem, package, version, result_json, updated_at FROM research_ai_triage WHERE status='triaged'")]
    records = classify(rows, now=dt.datetime.now(dt.timezone.utc), settle_days=args.settle_days)
    settled = [r for r in records if r["would_close"] and r["evaluated_ecosystem"] and r["settled"]]
    malicious = osv_malicious(settled)
    with ThreadPoolExecutor(max_workers=8) as pool:
        removed = dict(enumerate(pool.map(registry_status, settled)))
    summary = report(records, malicious, removed, settle_days=args.settle_days)
    args.out.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    text = markdown(summary)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
