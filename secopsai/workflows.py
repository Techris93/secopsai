from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List


Workflow = Dict[str, Any]


_WORKFLOWS: Dict[str, Workflow] = {
    "plan": {
        "role": "Engineering manager",
        "purpose": "Turn a request or incident into scoped work before implementation.",
        "phases": [
            "Gather current product, repo, freshness, and triage context.",
            "Identify blockers, affected surfaces, and required approvals.",
            "Choose the smallest safe implementation path.",
            "Write down verification commands before editing.",
        ],
        "commands": [
            "secopsai status --json",
            "secopsai research preflight --json",
            "secopsai triage summary --json",
            "git status --short",
        ],
        "gates": [
            "No implementation before the failing behavior or requested outcome is clear.",
            "Do not mix unrelated repo changes into the plan.",
        ],
    },
    "review": {
        "role": "Production reviewer",
        "purpose": "Find regressions beyond CI before changes ship.",
        "phases": [
            "Inspect diffs for behavior, security, and operator-experience risk.",
            "Check changed commands and docs examples still line up.",
            "Verify generated reports and public surfaces still render safely.",
            "Record residual risks instead of hiding uncertainty.",
        ],
        "commands": [
            "git diff --check",
            "python3 scripts/verify_docs_examples.py",
            "python3 scripts/verify_blog.py",
            ".venv/bin/python -m pytest -q",
        ],
        "gates": [
            "Do not approve changes that require secrets to pass local verification.",
            "Do not loosen checks to make the review green.",
        ],
    },
    "qa": {
        "role": "QA lead",
        "purpose": "Exercise operator paths, generated pages, and browser-facing assets.",
        "phases": [
            "Run deterministic verifiers first.",
            "Check JavaScript syntax for Cloudflare Pages assets.",
            "Smoke-test key CLI commands and public-page build outputs.",
            "Capture gaps as follow-up tests when manual QA finds issues.",
        ],
        "commands": [
            "python3 scripts/verify_blog.py",
            "python3 scripts/verify_docs_examples.py",
            "node --check blog/_worker.js",
            "node --check blog/functions/api/comments.js",
            "node --check blog/assets/blog.js",
            "node --check blog/assets/comments.js",
        ],
        "gates": [
            "External-news drafts remain unpublished unless reviewed.",
            "Comments must keep approved-only GET and pending-only POST behavior.",
        ],
    },
    "cso": {
        "role": "Security officer",
        "purpose": "Run a safe OWASP/STRIDE-style security pass without destructive tests.",
        "phases": [
            "Map entry points, trust boundaries, secrets, and write paths.",
            "Review supply-chain advisories, blog comments, and publishing gates.",
            "Look for auth, injection, XSS, CSRF, CSP, and dependency risks.",
            "Write exploit scenarios and concrete fixes for confirmed issues.",
        ],
        "commands": [
            "secopsai supply-chain advisory list --json",
            "secopsai status --json",
            "git diff --check",
            ".venv/bin/python -m pytest -q",
        ],
        "gates": [
            "Use safe checks only; no brute force, spam, or destructive probing.",
            "Never print or commit Cloudflare, GitHub, Supabase, or API secrets.",
        ],
    },
    "ship": {
        "role": "Release engineer",
        "purpose": "Prepare a change for commit, push, and deployment verification.",
        "phases": [
            "Confirm the worktree only contains intentional changes.",
            "Run project CI-equivalent checks locally.",
            "Commit with a concise behavior-focused message.",
            "Push and record post-deploy verification commands.",
        ],
        "commands": [
            "git status --short",
            "python3 scripts/verify_blog.py",
            "python3 scripts/verify_docs_examples.py",
            ".venv/bin/python -m pytest -q",
            "git diff --check",
        ],
        "gates": [
            "Do not commit generated caches, secrets, private telemetry, or local artifacts.",
            "Do not deploy if local verification is red unless the failure is documented and unrelated.",
        ],
    },
    "canary": {
        "role": "Canary operator",
        "purpose": "Verify production health after deploy with narrow, reversible checks.",
        "phases": [
            "Check public routes and security-sensitive endpoints.",
            "Confirm feeds, docs, dashboard links, and comments health still work.",
            "Compare expected freshness/status fields to live behavior.",
            "Escalate rollback only when a real user-facing or security regression is confirmed.",
        ],
        "commands": [
            "curl -sS -I https://secopsai.dev/",
            "curl -sS -I https://docs.secopsai.dev/",
            "curl -sS -I https://blog.secopsai.dev/",
            "curl -sS 'https://blog.secopsai.dev/api/comments?health=1'",
        ],
        "gates": [
            "Do not run high-volume probes against production.",
            "Prefer read-only health checks and targeted smoke tests.",
        ],
    },
    "retro": {
        "role": "Retro facilitator",
        "purpose": "Turn recent work into shipping analytics and next improvements.",
        "phases": [
            "Summarize shipped commits, failed checks, and manual fixes.",
            "Identify repeated failure modes and missing automation.",
            "Choose one or two follow-up improvements with owners.",
            "Keep the retro factual, blameless, and small enough to act on.",
        ],
        "commands": [
            "git log --since='7 days ago' --oneline",
            "git status --short",
            "secopsai status --json",
            "secopsai blog news-review list --json",
        ],
        "gates": [
            "Do not turn retro into a rewrite plan without evidence.",
            "Prefer automation for repeated manual operator steps.",
        ],
    },
    "investigate": {
        "role": "Incident investigator",
        "purpose": "Apply no-fix-without-investigation discipline to findings or broken CI.",
        "phases": [
            "Reproduce the failure or inspect the original evidence first.",
            "Trace the dependency chain across workflows, imports, paths, and env assumptions.",
            "Form the smallest root-cause hypothesis that explains the evidence.",
            "Patch the root cause and add focused regression coverage when useful.",
        ],
        "commands": [
            "secopsai research preflight --json",
            "secopsai triage summary --json",
            "git log --oneline -5",
            "git diff --check",
        ],
        "gates": [
            "Do not patch commit titles or symptoms before reading logs/evidence.",
            "Preserve existing behavior unless dead code is clearly proven.",
        ],
    },
}


def workflow_names() -> List[str]:
    return sorted(_WORKFLOWS)


def list_workflows() -> List[Workflow]:
    return [
        {
            "name": name,
            "role": workflow["role"],
            "purpose": workflow["purpose"],
        }
        for name, workflow in sorted(_WORKFLOWS.items())
    ]


def get_workflow(name: str) -> Workflow:
    key = name.strip().lower()
    if key not in _WORKFLOWS:
        valid = ", ".join(workflow_names())
        raise KeyError(f"unknown workflow '{name}'. Valid workflows: {valid}")
    workflow = deepcopy(_WORKFLOWS[key])
    workflow["name"] = key
    return workflow


def render_workflow(workflow: Workflow) -> str:
    lines = [
        f"{workflow['name']} workflow",
        f"role: {workflow['role']}",
        f"purpose: {workflow['purpose']}",
        "",
        "Phases:",
    ]
    lines.extend(f"- {item}" for item in workflow.get("phases", []))
    lines.append("")
    lines.append("Suggested commands:")
    lines.extend(f"- {item}" for item in workflow.get("commands", []))
    lines.append("")
    lines.append("Safety gates:")
    lines.extend(f"- {item}" for item in workflow.get("gates", []))
    return "\n".join(lines)
