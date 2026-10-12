#!/usr/bin/env python3
"""Replay a fixed triage set through the production context builder and the model bridge.

Three sets, each built with the exact production path (fetch, scan, then
``research_ai_triage.triage_context``):

- production: a seeded sample of recent real hits (scripts/data/triage_replay_production.json),
  re-fetched from their registries;
- malware: known malware from the dataset that our rules flag (label 1);
- clean: latest releases of popular npm/PyPI packages that our rules flag (label 0).

Jobs go to Core with opaque ids (no label in them) and the operator's bridge
triages them.  The report measures what the plan's acceptance gates need:
how often the model can decide, how probabilities fall per set, and whether
decided verdicts cite files that exist.  ``--contexts-only`` writes the
contexts without queueing, to inspect the evidence offline.

Samples are decrypted and scanned in memory on a disposable runner and never
executed.  Run it from the "Triage Replay" workflow.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from secopsai import research_ai_triage, research_content_funnel, yara_engine  # noqa: E402
from secopsai.research_intake import SafeFetcher  # noqa: E402

PRODUCTION_SET = ROOT / "scripts" / "data" / "triage_replay_production.json"
MCP_VERSION_URL = "https://registry.modelcontextprotocol.io/v0/servers/{name}/versions/{version}"
MCP_REGISTRIES = {"npm": "npm", "pypi": "pypi"}
DECIDED = {"true_positive", "false_positive", "benign_expected", "policy_noise"}
GATES = {
    "needs_more_evidence share (production) <= 35%": lambda m: m["production"]["undecided_pct"] <= 35,
    "known malware at <= 10%: 0": lambda m: m["malware"]["bands"].get("<=10", 0) == 0,
    "known malware at <= 30%: <= 5%": lambda m: m["malware"]["le30_pct"] <= 5,
    "flagged clean at >= 70%: <= 5%": lambda m: m["clean"]["ge70_pct"] <= 5,
    "decided verdicts citing a real file: 100%": lambda m: all(m[s]["grounded_pct"] >= 100 for s in m if m[s]["decided"]),
}


def parse_artifact(artifact_id: str) -> Tuple[str, str, str]:
    ecosystem, rest = artifact_id.split(":", 1)
    package, _, version = rest.rpartition("@")
    return ecosystem, package, version


def build(fetcher: Optional[SafeFetcher], ecosystem: str, package: str, version: str, members: List[Tuple[str, bytes]],
          rules_ecosystem: str = "") -> Optional[Dict[str, Any]]:
    """Production scan and context for unpacked files; None when the rules do not flag them."""
    result = research_content_funnel.scan_members(fetcher, ecosystem, package, version, members, rules_ecosystem=rules_ecosystem)
    if result["status"] != "hit":
        return None
    context = research_ai_triage.triage_context(ecosystem=ecosystem, package=package, version=version, prescan=result,
                                                metadata_signals=research_content_funnel.behaviour_signals(result))
    return {"context": context, "paths": sorted({path for path, _data in members}), "score": result["score"], "level": result["level"]}


def production_rows(fetcher: SafeFetcher, count: int, seed: int) -> List[Dict[str, Any]]:
    artifacts = [row["artifact_id"] for row in json.loads(PRODUCTION_SET.read_text())["artifacts"]
                 if row["artifact_id"].split(":", 1)[0] in {"npm", "pypi", "open-vsx", "crates", "vscode-marketplace", "mcp-registry"}]
    # Oversample: some releases are gone or no longer flagged by today's rules.
    chosen = random.Random(seed).sample(sorted(artifacts), min(count * 2, len(artifacts)))

    def one(artifact_id: str) -> Optional[Dict[str, Any]]:
        ecosystem, package, version = parse_artifact(artifact_id)
        try:
            scan_eco, scan_pkg, scan_ver, rules = ecosystem, package, version, ""
            if ecosystem == "mcp-registry":
                url = MCP_VERSION_URL.format(name=urllib.parse.quote(package, safe=""), version=urllib.parse.quote(version, safe=""))
                server = json.loads(fetcher.get(url, allowed_hosts=("registry.modelcontextprotocol.io",), max_bytes=1 << 20)[2]).get("server") or {}
                ref = next((p for p in server.get("packages") or [] if MCP_REGISTRIES.get(str(p.get("registryType")).lower()) and p.get("identifier") and p.get("version")), None)
                if ref is None:
                    return None
                scan_eco, scan_pkg, scan_ver, rules = MCP_REGISTRIES[str(ref["registryType"]).lower()], ref["identifier"], ref["version"], "mcp-registry"
            members, _size = research_content_funnel.fetch_release(fetcher, scan_eco, scan_pkg, scan_ver)
            built = build(fetcher, scan_eco, scan_pkg, scan_ver, members, rules)
        except Exception as exc:
            print(f"skip {artifact_id}: {type(exc).__name__}", flush=True)
            return None
        return {"set": "production", "label": None, "artifact": artifact_id, **built} if built else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        return [row for row in pool.map(one, chosen) if row][:count]


def malware_rows(dataset: Path, count: int, seed: int) -> List[Dict[str, Any]]:
    from recall_benchmark import checkout, sample_members, sample_paths

    paths = sample_paths(dataset, {"npm": count * 2, "pypi": count}, seed)
    checkout(dataset, paths)

    def one(path: str) -> Optional[Dict[str, Any]]:
        parts = path.split("/")
        ecosystem, package, version = parts[1], "/".join(parts[3:-2]) or parts[3], parts[-2]
        try:
            built = build(None, ecosystem, package, version, sample_members((dataset / path).read_bytes()))
        except Exception:
            return None
        return {"set": "malware", "label": 1, "artifact": f"{ecosystem}:{package}@{version}", "category": parts[2], **built} if built else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = [row for row in pool.map(one, paths) if row]
    return random.Random(seed).sample(rows, min(count, len(rows)))


def clean_rows(fetcher: SafeFetcher, count: int) -> List[Dict[str, Any]]:
    from recall_benchmark import clean_targets

    def one(target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ecosystem, package = target["ecosystem"], target["package"]
        try:
            if ecosystem == "npm":
                version = json.loads(fetcher.get(f"https://registry.npmjs.org/{package.replace('/', '%2F')}/latest", allowed_hosts=("registry.npmjs.org",), max_bytes=4 << 20)[2])["version"]
            else:
                version = json.loads(fetcher.get(f"https://pypi.org/pypi/{package}/json", allowed_hosts=("pypi.org",), max_bytes=16 << 20)[2])["info"]["version"]
            members, _size = research_content_funnel.fetch_release(fetcher, ecosystem, package, version)
            built = build(fetcher, ecosystem, package, version, members)
        except Exception:
            return None
        return {"set": "clean", "label": 0, "artifact": f"{ecosystem}:{package}@{version}", **built} if built else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        return [row for row in pool.map(one, clean_targets(600, 300)) if row][:count]


def queue_and_wait(rows: List[Dict[str, Any]], run_tag: str, wait_minutes: int) -> None:
    from secopsai.core_edge_client import CoreEdgeClient

    client = CoreEdgeClient()
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
    for index, row in enumerate(rows):
        row["job_artifact"] = f"{row['artifact']}#x{run_tag}{index}"
        row["context"]["artifact_id"] = row["job_artifact"]
    # Small batches: contexts are near the 56 KB cap.  Stable idempotency keys
    # make a resend after a timeout safe.
    for start in range(0, len(rows), 5):
        batch = [{"artifact_id": row["job_artifact"], "idempotency_key": f"replay:{row['job_artifact']}",
                  "inputs": {"artifact_triage": row["context"]}} for row in rows[start:start + 5]]
        for attempt in range(4):
            try:
                client.queue_triage_jobs(batch)
                break
            except Exception as exc:
                if attempt == 3:
                    raise
                print(f"queue batch {start // 5}: {type(exc).__name__}, retrying", flush=True)
                time.sleep(10 * (attempt + 1))
    print(f"queued {len(rows)} replay jobs", flush=True)
    wanted = {row["job_artifact"]: row for row in rows}
    deadline = time.time() + wait_minutes * 60
    cursor = started
    while time.time() < deadline and any("verdict" not in row for row in rows):
        time.sleep(60)
        while True:
            try:
                page = client.triage_results(since=cursor, limit=25).get("results") or []
            except RuntimeError:  # response over the client's size limit
                page = client.triage_results(since=cursor, limit=5).get("results") or []
            for item in page:
                row = wanted.get(item.get("artifact_id"))
                if row is not None and item.get("status") in {"succeeded", "failed"}:
                    result = item.get("result") or {}
                    row["verdict"] = result.get("finding_verdict") if item["status"] == "succeeded" else "job_failed"
                    probability = result.get("malicious_probability")
                    row["probability"] = int(probability) if isinstance(probability, (int, float)) else None
                    row["summary"] = str(result.get("summary") or "")[:300]
                    row["missing_evidence"] = result.get("missing_evidence") or []
                    row["refs"] = [str(ref) for ref in (result.get("decision_evidence_refs") or []) + (result.get("verdict_evidence_refs") or [])][:30]
            if len(page) < 5 or page[-1]["updated_at"] == cursor:
                break
            cursor = page[-1]["updated_at"]
        print(f"{sum('verdict' in row for row in rows)}/{len(rows)} verdicts back", flush=True)


PATHLIKE = re.compile(r"[\w@.\-]+(?:/[\w@.\-]+)+")


def grounded(row: Dict[str, Any]) -> bool:
    """A decided verdict must cite at least one file that exists in the package."""
    paths = set(row.get("paths") or [])
    cited = {match for ref in row.get("refs") or [] for match in PATHLIKE.findall(ref)}
    return any(path in paths or any(p.endswith("/" + path) or path.endswith("/" + p) for p in paths) for path in cited)


def band(probability: Optional[int]) -> str:
    if probability is None:
        return "missing"
    return "<=10" if probability <= 10 else "11-30" if probability <= 30 else "31-69" if probability < 70 else ">=70"


def metrics(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for name in ("production", "malware", "clean"):
        done = [row for row in rows if row["set"] == name and row.get("verdict") and row["verdict"] != "job_failed"]
        decided = [row for row in done if row["verdict"] in DECIDED]
        probabilities = [row["probability"] for row in done if row.get("probability") is not None]
        n = max(1, len(done))
        out[name] = {
            "n": len(done), "queued": sum(row["set"] == name for row in rows),
            "verdicts": dict(Counter(row["verdict"] for row in done).most_common()),
            "undecided_pct": round(100 * (len(done) - len(decided)) / n, 1),
            "bands": dict(Counter(band(row.get("probability")) for row in done)),
            "le30_pct": round(100 * sum(p <= 30 for p in probabilities) / n, 1),
            "ge70_pct": round(100 * sum(p >= 70 for p in probabilities) / n, 1),
            "decided": len(decided),
            "grounded_pct": round(100 * sum(grounded(row) for row in decided) / max(1, len(decided)), 1),
            "context_kb_median": round(sorted(row["context"].get("context_bytes", 0) for row in rows if row["set"] == name)[sum(row["set"] == name for row in rows) // 2] / 1024, 1) if any(row["set"] == name for row in rows) else 0,
        }
    return out


def report(rows: List[Dict[str, Any]], label: str) -> Tuple[str, bool]:
    m = metrics(rows)
    lines = [f"## Triage replay: {label}", "",
             "| Set | Triaged | Undecided (needs_more_evidence) | <=10 | 11-30 | 31-69 | >=70 | No probability | Decided & cites a real file | Median context |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for name, item in m.items():
        b = item["bands"]
        lines.append(f"| {name} | {item['n']}/{item['queued']} | {item['undecided_pct']}% | {b.get('<=10', 0)} | {b.get('11-30', 0)} | {b.get('31-69', 0)} | "
                     f"{b.get('>=70', 0)} | {b.get('missing', 0)} | {item['grounded_pct']}% of {item['decided']} | {item['context_kb_median']} KB |")
    lines += ["", "### Acceptance gates", ""]
    passed = True
    for gate, check in GATES.items():
        ok = check(m)
        passed &= ok
        lines.append(f"- {'PASS' if ok else 'FAIL'}: {gate}")
    lines += ["", "### Verdicts", ""] + [f"- {name}: {item['verdicts']}" for name, item in m.items()]
    low = sorted((row for row in rows if row["set"] == "malware" and row.get("probability") is not None), key=lambda row: row["probability"])[:6]
    lines += ["", "Lowest-rated known malware:", ""] + [f"- {row['probability']}% {row['artifact']} ({row.get('category')}): {row.get('summary', '')[:150]}" for row in low]
    high = sorted((row for row in rows if row["set"] == "clean" and row.get("probability") is not None), key=lambda row: -row["probability"])[:6]
    lines += ["", "Highest-rated clean packages:", ""] + [f"- {row['probability']}% {row['artifact']}: {row.get('summary', '')[:150]}" for row in high]
    missing = Counter(str(item)[:90] for row in rows if row.get("verdict") == "needs_more_evidence" for item in row.get("missing_evidence") or [])
    lines += ["", "Most common missing evidence:", ""] + [f"- {count}x {text}" for text, count in missing.most_common(8)]
    return "\n".join(lines), passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--dataset", type=Path, help="malware dataset clone (omit to skip the malware set)")
    parser.add_argument("--production", type=int, default=100)
    parser.add_argument("--malware", type=int, default=40)
    parser.add_argument("--clean", type=int, default=40)
    parser.add_argument("--seed", type=int, default=20261012)
    parser.add_argument("--label", default=os.environ.get("GITHUB_SHA", "local")[:12])
    parser.add_argument("--wait-minutes", type=int, default=150)
    parser.add_argument("--contexts-only", action="store_true", help="build and save contexts; do not queue")
    parser.add_argument("--out", type=Path, default=Path("triage-replay.json"))
    args = parser.parse_args()
    if not yara_engine.load().get("available"):
        raise SystemExit("YARA rules unavailable")
    fetcher = SafeFetcher(timeout=60)
    rows = production_rows(fetcher, args.production, args.seed)
    print(f"{len(rows)} production hits rebuilt", flush=True)
    if args.dataset and args.malware:
        rows += malware_rows(args.dataset, args.malware, args.seed)
    if args.clean:
        rows += clean_rows(fetcher, args.clean)
    print("contexts: " + ", ".join(f"{k} {v}" for k, v in Counter(row["set"] for row in rows).items()), flush=True)
    if not args.contexts_only:
        queue_and_wait(rows, os.environ.get("GITHUB_RUN_ID", str(int(time.time())))[-6:], args.wait_minutes)
    args.out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    if args.contexts_only:
        return 0
    text, passed = report(rows, args.label)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n", encoding="utf-8")
    return 0 if passed else 2


if __name__ == "__main__":
    sys.exit(main())
