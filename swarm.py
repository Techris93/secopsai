"""
SecOps Autoresearch — Swarm Orchestrator
Manages parallel agent experiments across git branches.

Each agent gets its own branch and research direction. Before starting,
agents read the community findings. After finishing, they publish results.

Usage:
    python swarm.py --spawn 3                  # Launch 3 parallel branches
    python swarm.py --leaderboard              # Show best scores across branches
    python swarm.py --adopt experiment/agent-1  # Copy best detect.py to main
    python swarm.py --status                   # Show all experiment branches
"""

import os
import sys
import json
import shutil
import subprocess
import argparse
from datetime import datetime
from typing import List, Dict, Optional

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(REPO_DIR, "data")

# Research directions agents can explore
RESEARCH_DIRECTIONS = [
    {
        "name": "threshold-tuning",
        "hint": "Experiment with detection thresholds. Lower thresholds catch stealthy "
                "attacks but may increase false positives. Find the optimal balance.",
    },
    {
        "name": "new-rules",
        "hint": "Add entirely new detection rules for attack types that are currently "
                "missed. Check the 'Missed attack events' output for ideas.",
    },
    {
        "name": "false-positive-reduction",
        "hint": "Focus on reducing false positives by adding smarter filters, allowlists, "
                "and contextual checks that distinguish malicious from benign activity.",
    },
    {
        "name": "cross-correlation",
        "hint": "Correlate signals across multiple rules. E.g., failed logins from the "
                "same IP that also triggers DNS exfil should be scored higher.",
    },
    {
        "name": "temporal-analysis",
        "hint": "Add time-based detection: unusual hours, burst patterns, slow-and-low "
                "attacks spread over long periods.",
    },
    {
        "name": "statistical-methods",
        "hint": "Use statistical approaches: Z-scores for outlier detection, entropy "
                "calculations for DNS queries, byte distribution analysis for C2.",
    },
    {
        "name": "behavioral-profiling",
        "hint": "Build behavioral baselines per source IP. Flag deviations from normal "
                "patterns rather than using fixed thresholds.",
    },
    {
        "name": "ensemble-signals",
        "hint": "Combine weak signals from multiple rules into a composite score. "
                "Individual signals may be benign; together they indicate an attack.",
    },
]


# ═══ Git Operations ══════════════════════════════════════════════════════════

def git(args: List[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a git command in the repo directory."""
    return subprocess.run(
        ["git"] + args,
        capture_output=True, text=True,
        cwd=REPO_DIR, check=check
    )


def get_current_branch() -> str:
    result = git(["rev-parse", "--abbrev-ref", "HEAD"])
    return result.stdout.strip()


def list_experiment_branches() -> List[str]:
    result = git(["branch", "--list", "experiment/*"])
    branches = [b.strip().lstrip("* ") for b in result.stdout.strip().split("\n") if b.strip()]
    return branches


def branch_exists(name: str) -> bool:
    result = git(["branch", "--list", name])
    return bool(result.stdout.strip())


def get_branch_score(branch: str) -> Optional[float]:
    """Get the best F1 score from a branch's commit messages."""
    result = git(["log", branch, "--oneline", "-20", "--format=%s"], check=False)
    if result.returncode != 0:
        return None

    best = 0.0
    for line in result.stdout.strip().split("\n"):
        if "F1=" in line:
            try:
                score_str = line.split("F1=")[1].split()[0].strip("()+")
                score = float(score_str)
                best = max(best, score)
            except (ValueError, IndexError):
                continue
    return best if best > 0 else None


# ═══ Swarm Operations ════════════════════════════════════════════════════════

def spawn_branches(count: int, dry_run: bool = False) -> List[Dict]:
    """Create N experiment branches, each with a different research direction."""
    original_branch = get_current_branch()
    existing = list_experiment_branches()

    # Read community findings to inform direction assignment
    try:
        from findings import read_findings, get_unexplored_directions
        findings = read_findings()
        unexplored = get_unexplored_directions(findings)
    except ImportError:
        findings = []
        unexplored = []

    # Pick directions, preferring unexplored ones
    available = [d for d in RESEARCH_DIRECTIONS
                 if d["name"] in unexplored] or RESEARCH_DIRECTIONS

    spawned = []
    agent_num = len(existing) + 1

    for i in range(count):
        direction = available[i % len(available)]
        branch_name = f"experiment/agent-{agent_num + i}"

        if branch_exists(branch_name):
            print(f"  ⚠️  Branch {branch_name} already exists, skipping")
            continue

        if dry_run:
            print(f"  [DRY RUN] Would create: {branch_name} → {direction['name']}")
            spawned.append({"branch": branch_name, "direction": direction["name"]})
            continue

        # Create branch from main
        git(["checkout", "main"], check=False)
        git(["checkout", "-b", branch_name])

        # Write a direction file so the agent knows what to focus on
        direction_file = os.path.join(REPO_DIR, ".direction")
        with open(direction_file, "w") as f:
            json.dump({
                "agent_id": f"agent-{agent_num + i}",
                "branch": branch_name,
                "direction": direction["name"],
                "hint": direction["hint"],
                "created_at": datetime.now().isoformat(),
            }, f, indent=2)

        git(["add", ".direction"])
        git(["commit", "-m",
             f"chore: assign direction [{direction['name']}] to {branch_name}"])

        print(f"  ✅ Created {branch_name} → {direction['name']}")
        spawned.append({"branch": branch_name, "direction": direction["name"]})

    # Return to original branch
    if not dry_run:
        git(["checkout", original_branch], check=False)

    return spawned


def show_status():
    """Show status of all experiment branches."""
    branches = list_experiment_branches()
    current = get_current_branch()

    print(f"\n{'═' * 65}")
    print(f"  🐝 Swarm Status — {len(branches)} experiment branches")
    print(f"  Current branch: {current}")
    print(f"{'═' * 65}\n")

    if not branches:
        print("  No experiment branches. Run: python swarm.py --spawn 3")
        print()
        return

    for branch in sorted(branches):
        # Get direction
        direction = "?"
        result = git(["show", f"{branch}:.direction"], check=False)
        if result.returncode == 0:
            try:
                info = json.loads(result.stdout)
                direction = info.get("direction", "?")
            except json.JSONDecodeError:
                pass

        # Get score
        score = get_branch_score(branch)
        score_str = f"F1={score:.4f}" if score else "no results"

        # Commit count
        result = git(["rev-list", "--count", f"main..{branch}"], check=False)
        commits = result.stdout.strip() if result.returncode == 0 else "?"

        active = " ← YOU" if branch == current else ""
        print(f"  {branch:30s}  [{direction:22s}]  {score_str:12s}  "
              f"{commits} commits{active}")

    print(f"\n{'═' * 65}\n")


def show_leaderboard():
    """Show leaderboard across all branches and local findings."""
    branches = list_experiment_branches()

    print(f"\n{'═' * 65}")
    print(f"  🏆 Leaderboard")
    print(f"{'═' * 65}\n")

    entries = []

    # From branches
    for branch in branches:
        score = get_branch_score(branch)
        direction = "?"
        result = git(["show", f"{branch}:.direction"], check=False)
        if result.returncode == 0:
            try:
                info = json.loads(result.stdout)
                direction = info.get("direction", "?")
            except json.JSONDecodeError:
                pass
        if score:
            entries.append({"source": branch, "f1": score, "direction": direction})

    # From findings
    try:
        from findings import read_findings
        for f in read_findings(limit=20):
            entries.append({
                "source": f.get("agent_id", "?"),
                "f1": f.get("f1_score", 0),
                "direction": f.get("direction", "?"),
            })
    except ImportError:
        pass

    # Deduplicate and sort
    seen = set()
    unique = []
    for e in sorted(entries, key=lambda x: x["f1"], reverse=True):
        key = (e["source"], round(e["f1"], 4))
        if key not in seen:
            seen.add(key)
            unique.append(e)

    if not unique:
        print("  No scores yet. Agents haven't run experiments.")
    else:
        for i, e in enumerate(unique[:15]):
            medal = "🥇" if i == 0 else "🥈" if i == 1 else "🥉" if i == 2 else f"#{i+1:2d}"
            print(f"  {medal}  F1={e['f1']:.4f}  [{e['direction']:22s}]  {e['source']}")

    print(f"\n{'═' * 65}\n")


def adopt_branch(branch: str, confirm: bool = False):
    """Copy detect.py from the specified branch to main.

    Security note: Only branches matching 'experiment/*' with safe name
    characters are accepted, to prevent path traversal or shell injection
    via crafted branch names.
    """
    import re as _re

    # Validate branch name to prevent path traversal, shell injection
    if not _re.match(r'^experiment/[a-zA-Z0-9_\-]+$', branch):
        print(f"  ❌ Branch name '{branch}' is invalid. "
              "Only 'experiment/<alphanumeric-and-dashes>' branches are accepted.")
        return

    if not branch_exists(branch):
        print(f"  ❌ Branch '{branch}' does not exist.")
        return

    # Get detect.py from that branch
    result = git(["show", f"{branch}:detect.py"], check=False)
    if result.returncode != 0:
        print(f"  ❌ Could not read detect.py from {branch}")
        return

    score = get_branch_score(branch)
    score_str = f"F1={score:.4f}" if score else "unknown score"

    if not confirm:
        print(f"  ⚠️  This will overwrite detect.py on main with code from {branch} ({score_str}).")
        print(f"      Review the code first: git show {branch}:detect.py")
        print(f"      To proceed, run with --confirm flag.")
        return

    # Switch to main and apply
    original = get_current_branch()
    git(["checkout", "main"])

    detect_path = os.path.join(REPO_DIR, "detect.py")
    with open(detect_path, "w") as f:
        f.write(result.stdout)

    git(["add", "detect.py"])
    git(["commit", "-m",
         f"adopt: {branch} ({score_str})\n\n"
         f"Cherry-picked detect.py from {branch}"])

    print(f"  ✅ Adopted detect.py from {branch} ({score_str}) into main")

    if original != "main":
        git(["checkout", original], check=False)


# ═══ CLI ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="🐝 Swarm — Multi-Agent Experiment Orchestrator"
    )
    parser.add_argument(
        "--spawn", type=int, metavar="N",
        help="Create N parallel experiment branches"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would happen without making changes"
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Show status of all experiment branches"
    )
    parser.add_argument(
        "--leaderboard", action="store_true",
        help="Show leaderboard across all branches"
    )
    parser.add_argument(
        "--adopt", type=str, metavar="BRANCH",
        help="Copy detect.py from a branch to main"
    )
    parser.add_argument(
        "--confirm", action="store_true",
        help="Required to confirm --adopt (prevents accidental code overwrite)"
    )
    parser.add_argument(
        "--directions", action="store_true",
        help="List available research directions"
    )

    args = parser.parse_args()

    if args.spawn:
        print(f"\n🐝 Spawning {args.spawn} experiment branches...\n")
        spawned = spawn_branches(args.spawn, dry_run=args.dry_run)
        print(f"\n  Spawned {len(spawned)} branches.")
        if not args.dry_run:
            print(f"  Next: check out a branch and start your agent.\n")

    elif args.status:
        show_status()

    elif args.leaderboard:
        show_leaderboard()

    elif args.adopt:
        adopt_branch(args.adopt, confirm=args.confirm)

    elif args.directions:
        print(f"\n{'═' * 55}")
        print(f"  📋 Available Research Directions")
        print(f"{'═' * 55}\n")
        for d in RESEARCH_DIRECTIONS:
            print(f"  → {d['name']}")
            print(f"    {d['hint']}\n")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
