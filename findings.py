"""
SecOps Autoresearch — Findings Protocol
Publish/read experiment findings for multi-agent collaboration.

Each "finding" is a structured JSON record of what an agent tried,
what score it achieved, and what it learned. Agents read each other's
findings before starting to avoid repeating failed approaches and
build on winning ideas.

Supports:
  - Local mode: findings stored in data/findings/ (single machine)
    - GitHub mode: findings posted as Issues by default (distributed)

Usage:
    from findings import publish_finding, read_findings, get_leaderboard
"""

import json
import os
import subprocess  # nosec B404
import shutil
import re
from datetime import datetime
from typing import Dict, List, Any, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
FINDINGS_DIR = os.path.join(DATA_DIR, "findings")
REPO_DIR = os.path.dirname(os.path.abspath(__file__))
GIT_EXECUTABLE = shutil.which("git")
REPO_SLUG_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def resolve_gh_executable() -> str:
    """Return GH CLI path if available, else default command name for graceful handling."""
    return shutil.which("gh") or "gh"


# ═══ Data Structure ══════════════════════════════════════════════════════════

def create_finding(
    agent_id: str,
    branch: str,
    direction: str,
    f1_score: float,
    approach: str,
    changes: List[str],
    insights: List[str],
    failed_ideas: Optional[List[str]] = None,
    metrics: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Create a structured finding (an agent's 'paper')."""
    return {
        "agent_id": agent_id,
        "branch": branch,
        "direction": direction,
        "f1_score": f1_score,
        "approach": approach,
        "changes": changes,
        "insights": insights,
        "failed_ideas": failed_ideas or [],
        "metrics": metrics or {},
        "timestamp": datetime.now().isoformat(),
        "version": 1,
    }


# ═══ Local Storage ═══════════════════════════════════════════════════════════

def publish_finding(finding: Dict[str, Any]) -> str:
    """Save a finding to local storage. Returns the file path."""
    os.makedirs(FINDINGS_DIR, exist_ok=True)

    # Filename: agent_id-timestamp-score.json
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    score = finding.get("f1_score", 0)
    agent = finding.get("agent_id", "unknown")
    filename = f"{agent}-{ts}-{score:.4f}.json"
    filepath = os.path.join(FINDINGS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(finding, handle, indent=2)

    print(f"  📄 Finding published: {filename}")
    return filepath


def read_findings(limit: int = 50) -> List[Dict[str, Any]]:
    """Read all published findings, sorted by score (best first)."""
    if not os.path.exists(FINDINGS_DIR):
        return []

    loaded_findings = []
    for filename in os.listdir(FINDINGS_DIR):
        if filename.endswith(".json"):
            filepath = os.path.join(FINDINGS_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as handle:
                    loaded_findings.append(json.load(handle))
            except (json.JSONDecodeError, IOError):
                continue

    # Sort by score, best first
    loaded_findings.sort(key=lambda x: x.get("f1_score", 0), reverse=True)
    return loaded_findings[:limit]


def get_leaderboard(top_n: int = 10) -> List[Dict]:
    """Get the top findings across all agents and branches."""
    top_findings = read_findings(limit=top_n)
    return [
        {
            "rank": i + 1,
            "agent": finding.get("agent_id"),
            "branch": finding.get("branch"),
            "direction": finding.get("direction"),
            "f1_score": finding.get("f1_score"),
            "approach": finding.get("approach", "")[:80],
            "timestamp": finding.get("timestamp"),
        }
        for i, finding in enumerate(top_findings)
    ]


def get_unexplored_directions(existing_findings: List[Dict]) -> List[str]:
    """Suggest research directions not yet tried."""
    all_directions = {
        "threshold-tuning",
        "new-rules",
        "cross-correlation",
        "ensemble-signals",
        "statistical-methods",
        "pattern-matching",
        "temporal-analysis",
        "ip-reputation",
        "entropy-detection",
        "behavioral-profiling",
    }

    tried = {finding.get("direction", "") for finding in existing_findings}
    return sorted(all_directions - tried)


def summarize_for_agent(limit: int = 10) -> str:
    """Generate a text summary an agent can read before starting."""
    recent_findings = read_findings(limit=limit)

    if not recent_findings:
        return "No previous findings. You are the first agent — explore freely."

    lines = [
        f"=== Research Community Status: {len(recent_findings)} findings ===\n",
        f"Best F1 score so far: {recent_findings[0]['f1_score']:.4f} "
        f"(by {recent_findings[0].get('agent_id', '?')} on {recent_findings[0].get('branch', '?')})\n",
    ]

    # Top findings
    lines.append("Top approaches:")
    for i, finding in enumerate(recent_findings[:5]):
        lines.append(
            f"  {i+1}. F1={finding['f1_score']:.4f} [{finding.get('direction', '?')}] "
            f"— {finding.get('approach', 'no description')[:100]}"
        )

    # Insights from best
    best = recent_findings[0]
    if best.get("insights"):
        lines.append("\nKey insights from best agent:")
        for insight in best["insights"][:5]:
            lines.append(f"  • {insight}")

    # Failed ideas to avoid
    all_failed = []
    for finding in recent_findings:
        all_failed.extend(finding.get("failed_ideas", []))
    if all_failed:
        lines.append(f"\nFailed ideas to avoid ({len(all_failed)} total):")
        for idea in list(set(all_failed))[:8]:
            lines.append(f"  ✗ {idea}")

    # Unexplored
    unexplored = get_unexplored_directions(recent_findings)
    if unexplored:
        lines.append("\nUnexplored directions to try:")
        for d in unexplored[:5]:
            lines.append(f"  → {d}")

    return "\n".join(lines)


# ═══ GitHub Integration (Optional) ═══════════════════════════════════════════

def detect_github_repo() -> str:
    """Infer owner/repo from the current origin remote."""
    if not GIT_EXECUTABLE:
        return ""

    try:
        result = subprocess.run(
            [GIT_EXECUTABLE, "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            cwd=REPO_DIR,
            check=False,
            timeout=10,
        )  # nosec B603
    except (OSError, subprocess.SubprocessError):
        return ""

    remote = result.stdout.strip()
    if "github.com" not in remote:
        return ""
    return remote.split("github.com")[-1].strip("/:").replace(":", "/").replace(".git", "")


def build_github_body(finding: Dict[str, Any]) -> str:
    """Render a finding as markdown for a GitHub issue or discussion."""
    body_lines = [
        f"## Agent: `{finding.get('agent_id', '?')}`",
        f"**Branch:** `{finding.get('branch', '?')}`",
        f"**Direction:** {finding.get('direction', '?')}",
        f"**F1 Score:** `{finding['f1_score']:.6f}`",
        "",
        "### Approach",
        finding.get("approach", "No description"),
        "",
        "### Changes Made",
    ]
    for change in finding.get("changes", []):
        body_lines.append(f"- {change}")

    body_lines.append("\n### Insights")
    for insight in finding.get("insights", []):
        body_lines.append(f"- {insight}")

    if finding.get("failed_ideas"):
        body_lines.append("\n### Failed Ideas (avoid these)")
        for idea in finding["failed_ideas"]:
            body_lines.append(f"- ❌ {idea}")

    if finding.get("metrics"):
        body_lines.append("\n### Metrics")
        body_lines.append("```json")
        body_lines.append(json.dumps(finding["metrics"], indent=2))
        body_lines.append("```")

    return "\n".join(body_lines)


def publish_to_github_issue(finding: Dict[str, Any], repo: str = "") -> bool:
    """Post a finding as a GitHub issue for distributed collaboration."""
    repo = repo or detect_github_repo()
    if not repo:
        print("  ⚠️  Could not detect GitHub repo. Skipping GitHub publish.")
        return False
    if not REPO_SLUG_PATTERN.match(repo):
        print("  ⚠️  Invalid repo format. Expected owner/repo.")
        return False

    gh_executable = resolve_gh_executable()

    title = (
        f"🔬 Finding: F1={finding['f1_score']:.4f} "
        f"[{finding.get('direction', 'experiment')}] "
        f"by {finding.get('agent_id', 'agent')}"
    )
    body = build_github_body(finding)

    try:
        result = subprocess.run(
            [gh_executable, "issue", "create",
             "--repo", repo,
             "--title", title,
             "--body", body],
            capture_output=True,
            text=True,
            cwd=REPO_DIR,
            check=False,
            timeout=20,
        )  # nosec B603
        if result.returncode == 0:
            print(f"  🌐 Published to GitHub Issues: {result.stdout.strip()}")
            return True
        print(f"  ⚠️  GitHub issue publish failed: {result.stderr[:200]}")
    except FileNotFoundError:
        print("  ⚠️  GitHub CLI not found. Skipping GitHub publish.")
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  ⚠️  GitHub post error: {e}")

    return False


def publish_to_github_discussion(finding: Dict[str, Any], repo: str = "") -> bool:
    """Backward-compatible wrapper that publishes to GitHub Issues."""
    return publish_to_github_issue(finding, repo=repo)


# ═══ CLI ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Findings Manager")
    parser.add_argument("--read", action="store_true", help="Read all findings")
    parser.add_argument("--leaderboard", action="store_true", help="Show leaderboard")
    parser.add_argument("--summary", action="store_true", help="Agent-readable summary")
    parser.add_argument("--test", action="store_true", help="Test publish/read cycle")
    args = parser.parse_args()

    if args.test:
        print("Testing findings protocol...")
        f = create_finding(
            agent_id="test-agent",
            branch="experiment/test",
            direction="threshold-tuning",
            f1_score=0.85,
            approach="Lowered brute force threshold from 5 to 3",
            changes=["Threshold 5→3 in detect_brute_force"],
            insights=["Slow brute force attacks use < 5 attempts"],
            failed_ideas=["Threshold 1 causes too many FP"],
        )
        path = publish_finding(f)
        print(f"  ✅ Published to: {path}")

        findings = read_findings()
        print(f"  ✅ Read {len(findings)} findings")

        # Cleanup test
        os.remove(path)
        print("  ✅ Test passed!")

    elif args.leaderboard:
        board = get_leaderboard()
        if not board:
            print("No findings yet.")
        else:
            print(f"\n{'═' * 70}")
            print(f"  🏆 Leaderboard — Top {len(board)} Findings")
            print(f"{'═' * 70}")
            for entry in board:
                print(f"  #{entry['rank']:2d}  F1={entry['f1_score']:.4f}  "
                      f"[{entry['direction']:20s}]  {entry['agent']}")
            print(f"{'═' * 70}\n")

    elif args.summary:
        print(summarize_for_agent())

    elif args.read:
        findings = read_findings()
        for f in findings:
            print(json.dumps(f, indent=2))

    else:
        parser.print_help()
