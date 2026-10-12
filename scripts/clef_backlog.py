#!/usr/bin/env python3
"""Score the production triage backlog with Clef (read-only) and compare with the chat model.

Restores a copy of the research ledger, sends every stored triage context to
Clef, and reports Clef's probability distribution on real flagged packages
(mostly benign), its agreement with the chat model's verdicts and
probabilities, and the packages it rates highest. Nothing is written back.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cloudflare" / "secopsai-research-runner" / "container"))

import requests  # noqa: E402

from secopsai import clef_triage  # noqa: E402


def band(p: int) -> str:
    return "<=10" if p <= 10 else "11-30" if p <= 30 else "31-69" if p < 70 else "70-89" if p < 90 else ">=90"


def main() -> int:
    from supervisor import LedgerStore

    db = Path(tempfile.mkdtemp(prefix="clef-backlog-")) / "ledger.db"
    if not LedgerStore(os.environ["LEDGER_STORE_URL"], os.environ["LEDGER_STORE_TOKEN"]).download(db):
        raise SystemExit("no ledger snapshot")
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    rows = [dict(row) for row in connection.execute("SELECT artifact_key, status, verdict, score, context_json, result_json FROM research_ai_triage")]
    session = requests.Session()

    def one(row):
        try:
            row.update(clef_triage.classify(json.loads(row["context_json"] or "{}"), session=session))
        except Exception as exc:
            row["error"] = type(exc).__name__
        return row

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(one, rows))
    done = [r for r in rows if "probability" in r]
    tokens = sum(r.get("input_tokens", 0) for r in done)
    lines = ["## Clef on the production triage backlog", "",
             f"{len(done)} of {len(rows)} stored hits scored; {tokens:,} tokens, about ${tokens * 0.24 / 1e6:.2f}.", "",
             "| Clef probability | Hits |", "| --- | --- |"]
    counts = Counter(band(r["probability"]) for r in done)
    for name in ("<=10", "11-30", "31-69", "70-89", ">=90"):
        lines.append(f"| {name} | {counts.get(name, 0)} ({100 * counts.get(name, 0) / max(1, len(done)):.0f}%) |")
    chat = []
    for r in done:
        try:
            p = int(json.loads(r.get("result_json") or "{}").get("malicious_probability", -1))
        except (TypeError, ValueError):
            p = -1
        if p >= 0:
            chat.append((p, r["probability"], r["artifact_key"]))
    if chat:
        agree = sum((a <= 30) == (b <= 30) for a, b, _ in chat)
        lines += ["", f"Compared with the chat model on {len(chat)} hits that have its probability: same side of 30% in {agree} ({100 * agree / len(chat):.0f}%).",
                  "", "Largest disagreements (chat%, Clef%):", ""]
        lines += [f"- {a}% / {b}% {k}" for a, b, k in sorted(chat, key=lambda t: -abs(t[0] - t[1]))[:10]]
    lines += ["", "Chat-model verdicts by Clef band:", ""]
    lines += [f"- {name}: " + ", ".join(f"{v or 'none'} {n}" for v, n in Counter(r["verdict"] for r in done if band(r["probability"]) == name).most_common())
              for name in ("<=10", "11-30", "31-69", "70-89", ">=90") if counts.get(name)]
    lines += ["", "Highest-rated hits by Clef:", ""] + [f"- {r['probability']}% {r['artifact_key']} (chat verdict: {r['verdict'] or 'none'}, rule score {r['score']})"
                                                       for r in sorted(done, key=lambda r: -r["probability"])[:15]]
    text = "\n".join(lines)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n", encoding="utf-8")
    Path(os.environ.get("RUNNER_TEMP", "."), "clef-backlog.json").write_text(json.dumps([{k: r.get(k) for k in ("artifact_key", "verdict", "score", "probability", "choice")} for r in rows], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
