#!/usr/bin/env python3
"""Count research-pipeline failures by workflow and root-cause category.

Every fix to the research pipeline must name the category it removes, and that
category's count must fall to zero over the following 48 hours.  This report
makes that measurable: it lists every failed run of the pipeline workflows in
the window, classifies each from its failed-job log into one root-cause
category, and counts checkpoint retry events in recent Research Worker runs
(retries that recovered are healthy, but a rising count is an early warning).

Uses only the GitHub API through the ``gh`` CLI and GITHUB_TOKEN.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

WORKFLOWS = ("research-worker.yml", "research-operation-watchdog.yml", "fast-lane.yml")
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "Techris93/secopsai")

# (category, pattern) in priority order; the first match names the root cause.
SIGNATURES = (
    ("ledger_restore_chunk_corrupt", r"checkpoint (decompressed )?chunk (checksum )?mismatch"),
    ("ledger_request_failed", r'"event": "checkpoint_failed"|ledger \w+ [\w-]+ failed after'),
    ("module_import_error", r"ModuleNotFoundError|ImportError"),
    ("fast_lane_completion_unacknowledged", r"completion could not be acknowledged"),
    ("fast_lane_unanalyzed_target", r'"status": "error"'),
    # The watchdog prints "root_cause" (and, in older runs, only "blockers");
    # the first blocker is the root cause.
    ("watchdog_worker_failed", r'"(?:root_cause": |blockers": \[)"Research Worker run \d+ concluded'),
    ("watchdog_sources_stale", r'"(?:root_cause": |blockers": \[)"enabled research sources are outside'),
    ("watchdog_delivery", r'"(?:root_cause": |blockers": \[)"[^"]*semantic'),
    ("watchdog_snapshot", r'"(?:root_cause": |blockers": \[)"(?:research operation snapshot|Research Worker completion)'),
    ("watchdog_other", r'"(?:root_cause": |blockers": \[)"[^"]+"'),
    ("timeout", r"exceeded the maximum execution time|The job running on runner .* has exceeded"),
    ("runner_lost", r"The runner has received a shutdown signal|lost communication with the server"),
)
RETRY_EVENTS = ("checkpoint_chunk_retry", "ledger_request_retry")


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def runs(workflow: str, since: datetime) -> list[dict]:
    items, page = [], 1
    while page <= 10:
        data = json.loads(gh("api", f"repos/{REPOSITORY}/actions/workflows/{workflow}/runs?branch=main&per_page=100&page={page}"))
        batch = data.get("workflow_runs") or []
        items.extend(run for run in batch if datetime.fromisoformat(run["created_at"].replace("Z", "+00:00")) >= since)
        if not batch or datetime.fromisoformat(batch[-1]["created_at"].replace("Z", "+00:00")) < since:
            break
        page += 1
    return items


def failed_log(run_id: int) -> str:
    try:
        return gh("run", "view", str(run_id), "--repo", REPOSITORY, "--log-failed")
    except subprocess.CalledProcessError:
        return ""


def classify(log: str) -> tuple[str, str]:
    for category, pattern in SIGNATURES:
        match = re.search(pattern, log)
        if match:
            detail = ""
            if category == "fast_lane_unanalyzed_target":
                details = re.findall(r'"failure_detail": "([^"]{0,120})', log)
                targets = re.findall(r'\{"target": "([^"]+)"[^{}]*?"status": "error"', log)
                detail = ", ".join(sorted(set(details or targets)))[:300]
            elif category.startswith("watchdog_"):
                detail = re.sub(r'^"(?:root_cause": |blockers": \[)', "", match.group(0)).strip('"')[:200]
            return category, detail
    errors = [line for line in log.splitlines() if "##[error]" in line or "Error" in line]
    return "unclassified", (errors[-1].split("Z ", 1)[-1][:200] if errors else "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--hours", type=int, default=48)
    parser.add_argument("--retry-sample", type=int, default=12, help="recent Research Worker runs scanned for retry events")
    parser.add_argument("--output", type=Path, default=Path("reports/research/pipeline-health.json"))
    args = parser.parse_args(argv)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=args.hours)

    totals: dict[str, Counter] = {}
    failures: list[dict] = []
    categories: Counter = Counter()
    worker_runs: list[dict] = []
    for workflow in WORKFLOWS:
        items = runs(workflow, since)
        totals[workflow] = Counter(run.get("conclusion") or run.get("status") for run in items)
        if workflow == "research-worker.yml":
            worker_runs = [run for run in items if run.get("status") == "completed"]
        for run in items:
            if run.get("conclusion") not in {"failure", "timed_out"}:
                continue
            category, detail = classify(failed_log(run["id"]))
            categories[f"{workflow}:{category}"] += 1
            failures.append({"workflow": workflow, "run_id": run["id"], "created_at": run["created_at"],
                             "head_sha": run["head_sha"][:7], "category": category, "detail": detail})

    retries: Counter = Counter()
    for run in worker_runs[: args.retry_sample]:
        try:
            log = gh("run", "view", str(run["id"]), "--repo", REPOSITORY, "--log")
        except subprocess.CalledProcessError:
            continue
        for event in RETRY_EVENTS:
            retries[event] += log.count(f'"{event}"')
    report = {"schema_version": "secopsai.pipeline-health.v1", "generated_at": now.isoformat(), "window_hours": args.hours,
              "runs": {workflow: dict(counter) for workflow, counter in totals.items()},
              "failures_by_category": dict(categories.most_common()), "failures": failures,
              "checkpoint_retry_events_recent_worker_runs": dict(retries), "retry_sample_runs": min(len(worker_runs), args.retry_sample)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [f"## Research pipeline health (last {args.hours} h)", "", "| Workflow | Runs | Failed |", "| --- | --- | --- |"]
    for workflow, counter in totals.items():
        lines.append(f"| {workflow} | {sum(counter.values())} | {counter.get('failure', 0) + counter.get('timed_out', 0)} |")
    lines += ["", "### Failures by root cause", ""]
    lines += [f"- {count} x {name}" for name, count in categories.most_common()] or ["- none"]
    by_category = defaultdict(list)
    for item in failures:
        by_category[item["category"]].append(item)
    for category, items in by_category.items():
        lines += ["", f"**{category}**", ""] + [f"- run {item['run_id']} ({item['created_at']}, {item['head_sha']}): {item['detail']}" for item in items[:10]]
    lines += ["", f"Checkpoint retry events in the last {report['retry_sample_runs']} Research Worker runs: "
              + (", ".join(f"{k} {v}" for k, v in retries.items()) or "none")]
    text = "\n".join(lines)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
