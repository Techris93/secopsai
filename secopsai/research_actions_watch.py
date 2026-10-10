"""Watch popular GitHub Actions for repointed tags and malicious releases.

Actions are git tags, not registry packages, so the attack is moving a tag:
in March 2025 every tag of tj-actions/changed-files was repointed to a commit
that dumped runner memory, and every workflow pinned to ``@v35`` ran it.

Each cycle this records every watched repository's tag -> object mapping and
compares it with the last snapshot:

- a full version tag (``v1.2.3``) that moves is never legitimate: high alert;
- a floating tag (``v4``) that moves to a commit no version tag points at:
  medium alert (moving ``v4`` to the ``v4.2.1`` commit is normal);
- new version tags are content-scanned like any new release.

Moved and new commits are downloaded from codeload and scanned in memory with
the YARA and behaviour rules; hits raise alerts and queue model triage.  The
first sighting of a repository only records a baseline.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import soc_store
from secopsai import package_features, yara_engine
from secopsai.research_intake import SafeFetcher

ROOT = Path(__file__).resolve().parents[1]
WATCHLIST_FILE = ROOT / "rules" / "watchlists" / "github-actions.txt"
API = "https://api.github.com"
API_HOSTS = ("api.github.com",)
CODELOAD_HOSTS = ("codeload.github.com",)
MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_EXPANDED_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_REPO_FILES = 10_000
LIST_WORKERS = 8
FULL_VERSION = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SEVERITY = {"alert": "high", "warning": "medium", "notice": "low"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def watchlist() -> List[str]:
    names: List[str] = []
    if WATCHLIST_FILE.is_file():
        names += [line.strip() for line in WATCHLIST_FILE.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    names += [item.strip() for item in os.environ.get("SECOPSAI_ACTIONS_WATCHLIST", "").split(",") if item.strip()]
    seen: Dict[str, None] = {}
    for name in names:
        if REPO.fullmatch(name):
            seen.setdefault(name, None)
    return list(seen)


def _token() -> str:
    return os.environ.get("SECOPSAI_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""


def _ensure(connection: Any) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS actions_tag_state (
            repo TEXT NOT NULL,
            tag TEXT NOT NULL,
            object_sha TEXT NOT NULL,
            object_type TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (repo, tag)
        )"""
    )
    connection.execute("CREATE TABLE IF NOT EXISTS actions_watch_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")


def _get_json(fetcher: SafeFetcher, url: str, token: str) -> Any:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    _u, _h, body = fetcher.get(url, allowed_hosts=API_HOSTS, max_bytes=8 * 1024 * 1024, headers=headers)
    return json.loads(body)


def list_tags(fetcher: SafeFetcher, repo: str, token: str) -> Dict[str, Tuple[str, str]]:
    """tag -> (object sha, object type) for every tag in the repository."""
    tags: Dict[str, Tuple[str, str]] = {}
    for page in range(1, 21):
        refs = _get_json(fetcher, f"{API}/repos/{repo}/git/matching-refs/tags?per_page=100&page={page}", token)
        for ref in refs if isinstance(refs, list) else []:
            name = str(ref.get("ref") or "").removeprefix("refs/tags/")
            obj = ref.get("object") or {}
            if name and obj.get("sha"):
                tags[name] = (str(obj["sha"]), str(obj.get("type") or "commit"))
        if not isinstance(refs, list) or len(refs) < 100:
            break
    return tags


def _commit_sha(fetcher: SafeFetcher, repo: str, sha: str, kind: str, token: str) -> str:
    if kind != "tag":
        return sha
    doc = _get_json(fetcher, f"{API}/repos/{repo}/git/tags/{sha}", token)
    return str((doc.get("object") or {}).get("sha") or sha)


def classify(previous: Dict[str, Tuple[str, str]], current: Dict[str, Tuple[str, str]]) -> List[Dict[str, Any]]:
    """Changes worth acting on, each with a decision: alert and/or scan."""
    release_objects = {sha for tag, (sha, _kind) in current.items() if FULL_VERSION.match(tag)}
    changes: List[Dict[str, Any]] = []
    for tag, (sha, kind) in current.items():
        before = previous.get(tag)
        full = bool(FULL_VERSION.match(tag))
        if before and before[0] != sha:
            if full:
                changes.append({"tag": tag, "sha": sha, "kind": kind, "previous": before[0], "change": "version_tag_moved", "severity": "high", "scan": True})
            elif sha not in release_objects:
                changes.append({"tag": tag, "sha": sha, "kind": kind, "previous": before[0], "change": "floating_tag_moved_off_release", "severity": "medium", "scan": True})
        elif not before and full:
            changes.append({"tag": tag, "sha": sha, "kind": kind, "previous": "", "change": "new_release", "severity": "", "scan": True})
    return changes


def repository_files(raw: bytes) -> List[Tuple[str, bytes]]:
    """Regular files of a codeload tarball, read in memory.

    Unlike package archives, repositories routinely contain symlinks; they
    are skipped (never followed) rather than failing the scan.
    """
    members: List[Tuple[str, bytes]] = []
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            name = member.name.replace("\\", "/")
            if not member.isfile() or name.startswith("/") or ".." in Path(name).parts:
                continue
            if len(members) >= MAX_REPO_FILES:
                break
            handle = archive.extractfile(member)
            data = handle.read(MAX_FILE_BYTES) if handle else b""
            total += len(data)
            if total > MAX_EXPANDED_BYTES:
                break
            members.append((name, data))
    return members


def scan_commit(fetcher: SafeFetcher, repo: str, commit: str) -> Dict[str, Any]:
    try:
        _u, _h, raw = fetcher.get(f"https://codeload.github.com/{repo}/tar.gz/{commit}", allowed_hosts=CODELOAD_HOSTS, max_bytes=MAX_ARCHIVE_BYTES)
        members = repository_files(raw)
        flags = package_features.profile(members)
        scanned = package_features.combine(yara_engine.scan_files(members), flags, "github-actions", members)
    except Exception as exc:
        return {"status": "error", "reason": str(exc)[:200]}
    level = str(scanned.get("level") or "none")
    findings = [item for item in scanned.get("findings") or [] if item.get("rule_id") != "YARA-SCAN-ERROR"]
    return {"status": "hit" if level in {"notice", "warning", "alert"} else "clean", "score": int(scanned.get("score") or 0), "level": level,
            "rules_matched": scanned.get("rules_matched") or [], "findings": findings[:20], "features": flags, "files": len(members)}


def _alert(repo: str, change: Dict[str, Any], scan: Optional[Dict[str, Any]], db_path: Optional[str]) -> None:
    now = _now()
    severity = change.get("severity") or SEVERITY.get(str((scan or {}).get("level")), "low")
    if scan and scan.get("status") == "hit" and SEVERITY.get(scan["level"]) == "high":
        severity = "high"
    what = {"version_tag_moved": "version tag was repointed", "floating_tag_moved_off_release": "floating tag moved to a commit no release points at",
            "new_release": "new release matched detection rules"}[change["change"]]
    evidence = {"source": "actions_watch", "ecosystem": "github-actions", "package": repo, "version": change["tag"], "change": change["change"],
                "object_sha": change["sha"], "previous_object_sha": change.get("previous"), "commit": change.get("commit"),
                "scan": {key: (scan or {}).get(key) for key in ("status", "score", "level", "rules_matched", "features")}}
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_alerts (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key,
                   reason, evidence_json, status, owner, created_at, updated_at)
               VALUES (?, 'registry_release_anomaly', ?, NULL, NULL, NULL, ?, ?, ?, 'open', '', ?, ?)
               ON CONFLICT(dedupe_key) DO NOTHING""",
            (f"RAL-{secrets.token_hex(8).upper()}", severity, f"actions-watch:{repo}@{change['tag']}:{change['sha']}",
             f"GitHub Action {repo}@{change['tag']}: {what}", json.dumps(evidence, sort_keys=True), now, now),
        )
        connection.commit()


def run(*, db_path: Optional[str] = None, fetcher: Optional[SafeFetcher] = None, scan_limit: int = 10, repos: Optional[List[str]] = None) -> Dict[str, Any]:
    """Compare tag snapshots for the watchlist; scan and alert on changes."""
    from secopsai import research_ai_triage

    token = _token()
    if not token:
        return {"enabled": False, "reason": "no GitHub token (GITHUB_TOKEN or SECOPSAI_GITHUB_TOKEN)"}
    # One pass is ~100 API calls; the worker runs several cycles per run, so
    # watch at most every 15 minutes to stay well inside the token's hourly limit.
    interval = int(os.environ.get("SECOPSAI_ACTIONS_WATCH_INTERVAL_SECONDS", "900") or 0)
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        row = connection.execute("SELECT value FROM actions_watch_meta WHERE key = 'last_run'").fetchone()
        connection.commit()
    if repos is None and row and interval > 0:
        elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(str(row["value"]).replace("Z", "+00:00"))).total_seconds()
        if elapsed < interval:
            return {"enabled": True, "skipped": f"last pass {int(elapsed)} s ago"}
    fetcher = fetcher or SafeFetcher(timeout=30)
    stats: Dict[str, Any] = {"enabled": True, "repos": 0, "baselined": 0, "changes": 0, "alerts": 0, "scanned": 0, "hits": 0, "errors": 0}
    scans_left = max(0, scan_limit)
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        connection.commit()
    names = repos if repos is not None else watchlist()

    def listing(repo: str) -> Optional[Dict[str, Tuple[str, str]]]:
        try:
            return list_tags(fetcher, repo, token)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=LIST_WORKERS) as pool:
        listings = list(pool.map(listing, names))
    for repo, current in zip(names, listings):
        if current is None:
            stats["errors"] += 1
            continue
        stats["repos"] += 1
        with closing(soc_store.connect(db_path)) as connection:
            previous = {row["tag"]: (row["object_sha"], row["object_type"]) for row in connection.execute("SELECT tag, object_sha, object_type FROM actions_tag_state WHERE repo = ?", (repo,))}
        changes = classify(previous, current) if previous else []
        if not previous:
            stats["baselined"] += 1
        stats["changes"] += len(changes)
        for change in changes:
            scan = None
            if change["scan"] and scans_left > 0:
                scans_left -= 1
                try:
                    change["commit"] = _commit_sha(fetcher, repo, change["sha"], change["kind"], token)
                    scan = scan_commit(fetcher, repo, change["commit"])
                except Exception as exc:
                    scan = {"status": "error", "reason": str(exc)[:200]}
                stats["scanned"] += 1
                stats["errors"] += int(scan.get("status") == "error")
            hit = bool(scan and scan.get("status") == "hit")
            stats["hits"] += int(hit)
            if change["severity"] or hit:
                _alert(repo, change, scan, db_path)
                stats["alerts"] += 1
            if hit:
                research_ai_triage.record_hit(ecosystem="github-actions", package=repo, version=change["tag"], prescan=scan,
                                              metadata_signals=[{"id": change["change"], "previous_object_sha": change.get("previous")}], db_path=db_path)
        now = _now()
        with closing(soc_store.connect(db_path)) as connection:
            for tag, (sha, kind) in current.items():
                connection.execute(
                    """INSERT INTO actions_tag_state (repo, tag, object_sha, object_type, first_seen, updated_at) VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(repo, tag) DO UPDATE SET object_sha = excluded.object_sha, object_type = excluded.object_type, updated_at = excluded.updated_at""",
                    (repo, tag, sha, kind, now, now),
                )
            connection.commit()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("INSERT INTO actions_watch_meta (key, value) VALUES ('last_run', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (_now(),))
        connection.commit()
    return stats
