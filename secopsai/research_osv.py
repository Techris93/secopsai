"""Advisories for confirmed malicious packages: our pages and OSV reports.

Two outputs per confirmed case:

1. A SecOpsAI advisory (``SECOPSAI-YYYY-NNNN``) published on the blog as an
   HTML page plus an OSV-format JSON document, so scanners and researchers
   can cite and consume it.
2. OSV reports for the OpenSSF malicious-packages database, which feeds
   OSV.dev and the scanners built on it.  One ``MAL-0000-*.json`` file per
   package, following that repository's contribution rules (single
   ``affected`` entry, no ``id``/``summary``, credits and IOCs).

Submitting to OpenSSF opens a public pull request, so it only happens when an
operator runs ``submit_osv(..., confirm=True)``.  Everything else is local.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import shutil
import subprocess
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import soc_store
from secopsai import research_post

OSV_SCHEMA_VERSION = "1.5.0"
UPSTREAM_REPO = "ossf/malicious-packages"
CREDIT = {"name": "SecOpsAI Research", "type": "FINDER", "contact": ["https://secopsai.dev", "https://blog.secopsai.dev/advisories/"]}
CWE_506 = {"cweId": "CWE-506", "description": "The product contains code that appears to be malicious in nature.", "name": "Embedded Malicious Code"}
OSV_ECOSYSTEMS = {
    "npm": "npm", "pypi": "PyPI", "crates.io": "crates.io", "cargo": "crates.io", "go": "Go", "maven": "Maven",
    "nuget": "NuGet", "rubygems": "RubyGems", "composer": "Packagist", "packagist": "Packagist",
}
# OSV reports claim a package is malicious, so only the strongest verdict qualifies.
ELIGIBLE_VERDICTS = {"credible"}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ensure(connection: Any) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS research_advisories (
            advisory_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            osv_ids_json TEXT NOT NULL DEFAULT '[]',
            submission_json TEXT NOT NULL DEFAULT '{}',
            published_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
    )


def _advisory_row(case_id: str, db_path: Optional[str]) -> Optional[Dict[str, Any]]:
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        row = connection.execute("SELECT * FROM research_advisories WHERE case_id = ?", (case_id,)).fetchone()
        connection.commit()
    if not row:
        return None
    value = dict(row)
    value["osv_ids"] = json.loads(value.pop("osv_ids_json") or "[]")
    value["submission"] = json.loads(value.pop("submission_json") or "{}")
    return value


def eligibility(case: Dict[str, Any], *, now: Optional[_dt.datetime] = None) -> List[str]:
    """Reasons the case cannot be published as an advisory (empty when it can)."""
    blockers: List[str] = []
    verdict = str(research_post.latest_verdict(case).get("verdict") or "")
    if verdict not in ELIGIBLE_VERDICTS:
        blockers.append(f"latest verdict is '{verdict or 'none'}'; advisories need 'credible'")
    if not research_post.packages(case):
        blockers.append("no affected package recorded")
    elif any(str(item.get("ecosystem") or "").lower() not in OSV_ECOSYSTEMS for item in research_post.packages(case)):
        blockers.append("an affected package's ecosystem has no OSV name")
    reviews = case.get("publication_reviews") or []
    if not reviews or reviews[0].get("status") != "approved":
        blockers.append("latest publication safety review is not approved")
    embargo = str(case.get("embargo_until") or "")
    if embargo:
        try:
            until = _dt.datetime.fromisoformat(embargo.replace("Z", "+00:00"))
            if until.tzinfo is None:
                until = until.replace(tzinfo=_dt.timezone.utc)
            if until > (now or _dt.datetime.now(_dt.timezone.utc)):
                blockers.append(f"embargoed until {embargo}")
        except ValueError:
            blockers.append("embargo date is not readable")
    return blockers


def assign_advisory_id(case_id: str, *, db_path: Optional[str] = None, year: Optional[int] = None) -> str:
    """Stable advisory id for a case; the first call allocates the next number."""
    existing = _advisory_row(case_id, db_path)
    if existing:
        return str(existing["advisory_id"])
    year = year or _dt.datetime.now(_dt.timezone.utc).year
    prefix = f"SECOPSAI-{year}-"
    now = _now()
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        rows = connection.execute("SELECT advisory_id FROM research_advisories WHERE advisory_id LIKE ?", (prefix + "%",)).fetchall()
        number = max((int(str(row["advisory_id"]).rsplit("-", 1)[-1]) for row in rows), default=0) + 1
        advisory_id = f"{prefix}{number:04d}"
        connection.execute(
            "INSERT INTO research_advisories (advisory_id, case_id, status, created_at, updated_at) VALUES (?, ?, 'draft', ?, ?)",
            (advisory_id, case_id, now, now),
        )
        connection.commit()
    return advisory_id


# ------------------------------------------------------------------ content
def _grouped_packages(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    grouped: Dict[tuple, List[str]] = {}
    for item in research_post.packages(case):
        key = (OSV_ECOSYSTEMS[str(item.get("ecosystem") or "").lower()], str(item.get("name")))
        version = str(item.get("version") or "")
        grouped.setdefault(key, [])
        if version and version not in grouped[key]:
            grouped[key].append(version)
    return [{"ecosystem": eco, "name": name, "versions": versions} for (eco, name), versions in grouped.items()]


def _affected(package: Dict[str, Any]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"package": {"ecosystem": package["ecosystem"], "name": package["name"]}, "database_specific": {"cwes": [CWE_506]}}
    if package["versions"]:
        entry["versions"] = package["versions"]
    else:  # every version is malicious (a package published to deliver malware)
        entry["ranges"] = [{"type": "SEMVER" if package["ecosystem"] in {"npm", "crates.io", "Go"} else "ECOSYSTEM", "events": [{"introduced": "0"}]}]
    return entry


def _iocs(case: Dict[str, Any]) -> Dict[str, Any]:
    domains, urls, ips, files = [], [], [], []
    for item in case.get("iocs") or []:
        if not isinstance(item, dict) or item.get("status", "active") != "active" or not item.get("value"):
            continue
        kind, value = str(item.get("ioc_type") or "").lower(), str(item["value"]).strip()
        if kind in {"domain", "hostname"}:
            domains.append(value.encode("idna").decode("ascii") if not value.isascii() else value)
        elif kind == "url":
            urls.append(value)
        elif kind in {"ip", "ipv4", "ipv6", "cidr"}:
            ips.append(value)
        elif kind in {"sha256", "sha1", "md5"}:
            note = ", ".join(str(tag) for tag in item.get("tags") or [])[:512]
            files.append({"digests": {kind: value.lower()}, "source": "package", **({"note": note} if note else {})})
    iocs: Dict[str, Any] = {}
    for key, values in (("domains", domains), ("urls", urls), ("ips", ips)):
        if values:
            iocs[key] = sorted(set(values))
    if files:
        iocs["files"] = files
    return iocs


def details(case: Dict[str, Any]) -> str:
    """OSV ``details``: why it is malicious, what it does, how it triggers."""
    verdict = research_post.latest_verdict(case)
    mapping = research_post.attack_mapping(case)
    behaviours = [item["name"] for item in mapping if item["technique"] != "T1195.002"]
    install_time = any(item["technique"] in {"T1059.007", "T1059.006"} for item in mapping) and re.search(
        r"postinstall|preinstall|install script|setup\.py|cmdclass", " ".join(f"{e.get('title')} {e.get('notes')}" for e in case.get("evidence") or [] if isinstance(e, dict)) + str(case.get("summary") or ""), re.I)
    parts = [str(case.get("summary") or "").strip()]
    if verdict.get("rationale"):
        parts.append(f"Why it is malicious: {str(verdict['rationale']).strip()}")
    if behaviours:
        parts.append("Observed behaviour: " + "; ".join(behaviours) + ".")
    parts.append("Trigger: runs automatically when the package is installed." if install_time else "Trigger: runs when the package is imported or executed.")
    parts.append("Any machine that installed an affected version should be treated as compromised: remove the package and rotate credentials reachable from it.")
    return "\n\n".join(part for part in parts if part)


def build_advisory(case: Dict[str, Any], advisory_id: str, *, post_url: str = "", advisory_url: str = "", osv_ids: Optional[List[str]] = None, now: Optional[str] = None) -> Dict[str, Any]:
    """Our OSV-format advisory (all affected packages in one document)."""
    now = now or _now()
    packages = _grouped_packages(case)
    names = ", ".join(f"{item['name']} ({item['ecosystem']})" for item in packages[:3]) + (" and others" if len(packages) > 3 else "")
    references = [{"type": "ADVISORY", "url": advisory_url}] if advisory_url else []
    if post_url:
        references.append({"type": "REPORT", "url": post_url})
    database_specific: Dict[str, Any] = {
        "secopsai": {"case_id": case.get("case_id"), "confidence": research_post.confidence_grade(case)["label"],
                     "attack_techniques": [item["technique"] for item in research_post.attack_mapping(case)],
                     "registry_status": {f"{item.get('name')}@{item.get('version')}": item.get("registry_state") or "unknown" for item in research_post.packages(case)}},
    }
    iocs = _iocs(case)
    if iocs:
        database_specific["iocs"] = iocs
    doc: Dict[str, Any] = {
        "schema_version": OSV_SCHEMA_VERSION, "id": advisory_id, "modified": now, "published": now,
        "summary": f"Malicious code in {names}"[:120], "details": details(case),
        "affected": [_affected(item) for item in packages], "references": references, "credits": [CREDIT],
        "database_specific": database_specific,
    }
    if osv_ids:
        doc["aliases"] = sorted(set(osv_ids))
    return doc


def build_mal_reports(case: Dict[str, Any], advisory_id: str, *, advisory_url: str = "", post_url: str = "", now: Optional[str] = None) -> List[Dict[str, Any]]:
    """One report per package for ossf/malicious-packages (no id or summary)."""
    now = now or _now()
    references = ([{"type": "ADVISORY", "url": advisory_url}] if advisory_url else []) + ([{"type": "REPORT", "url": post_url}] if post_url else [])
    iocs = _iocs(case)
    reports = []
    for package in _grouped_packages(case):
        report: Dict[str, Any] = {"schema_version": OSV_SCHEMA_VERSION, "modified": now, "published": now, "aliases": [advisory_id],
                                  "details": details(case), "affected": [_affected(package)], "references": references, "credits": [CREDIT]}
        if iocs:
            report["database_specific"] = {"iocs": iocs}
        reports.append(report)
    return reports


def validate_mal_report(report: Dict[str, Any]) -> List[str]:
    """The repository's contribution rules, checked before anything is submitted."""
    problems = []
    if "id" in report or "summary" in report:
        problems.append("id and summary must not be set")
    affected = report.get("affected") or []
    if len(affected) != 1:
        problems.append("affected must have exactly one entry")
    elif not (affected[0].get("package") or {}).get("ecosystem") or not (affected[0].get("package") or {}).get("name"):
        problems.append("affected[0].package needs ecosystem and name")
    elif not affected[0].get("versions") and not affected[0].get("ranges"):
        problems.append("affected[0] needs versions or ranges")
    if not report.get("credits") and not report.get("references"):
        problems.append("credits or references are required")
    if len(str(report.get("details") or "")) < 40:
        problems.append("details should explain why the package is malicious")
    return problems


def mal_report_path(report: Dict[str, Any], advisory_id: str) -> str:
    package = report["affected"][0]["package"]
    slug = re.sub(r"[^a-z0-9]+", "-", f"secopsai-{advisory_id}".lower()).strip("-")
    return f"osv/malicious/{package['ecosystem']}/{package['name']}/MAL-0000-{slug}.json"


# ---------------------------------------------------------------- workflow
def _case(case_id: str, db_path: Optional[str]) -> Dict[str, Any]:
    from secopsai.research_cases import get_case

    return get_case(case_id, db_path=db_path)


def _urls(advisory_id: str, case: Dict[str, Any]) -> Dict[str, str]:
    from secopsai.blog import BASE_URL, _post_url, slugify

    return {"advisory_url": f"{BASE_URL}/advisories/{advisory_id}.html",
            "post_url": _post_url(slugify(f"{case.get('case_id')}-{case.get('title') or case.get('case_id')}"))}


def _record(case_id: str, event: str, message: str, data: Dict[str, Any], db_path: Optional[str], actor: str) -> None:
    from secopsai.research_cases import _record_event

    with closing(soc_store.connect(db_path)) as connection:
        _record_event(connection, case_id, event, message, actor=actor, data=data)
        connection.commit()


def publish_advisory(case_id: str, *, db_path: Optional[str] = None, paths: Any = None, actor: str = "secopsai") -> Dict[str, Any]:
    """Write the advisory JSON to the blog and rebuild its pages."""
    from secopsai import blog

    case = _case(case_id, db_path)
    blockers = eligibility(case)
    if blockers:
        raise ValueError("case is not eligible for an advisory: " + "; ".join(blockers))
    advisory_id = assign_advisory_id(case["case_id"], db_path=db_path)
    row = _advisory_row(case["case_id"], db_path) or {}
    urls = _urls(advisory_id, case)
    paths = paths or blog.BlogPaths()
    target = paths.root / "advisories" / f"{advisory_id}.json"
    previous = json.loads(target.read_text(encoding="utf-8")) if target.is_file() else {}
    doc = build_advisory(case, advisory_id, osv_ids=row.get("osv_ids"), **urls)
    if previous.get("published"):
        doc["published"] = previous["published"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths.posts.mkdir(parents=True, exist_ok=True)
    blog.rebuild(paths=paths)
    now = _now()
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        connection.execute("UPDATE research_advisories SET status = CASE WHEN status = 'submitted' THEN status ELSE 'published' END, published_at = COALESCE(published_at, ?), updated_at = ? WHERE advisory_id = ?",
                           (now, now, advisory_id))
        connection.commit()
    _record(case["case_id"], "advisory_published", f"Published advisory {advisory_id}.", {"advisory_id": advisory_id, "url": urls["advisory_url"]}, db_path, actor)
    return {"advisory_id": advisory_id, "path": str(target), "url": urls["advisory_url"]}


def prepare_osv_submission(case_id: str, *, db_path: Optional[str] = None, out_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Write validated MAL-0000 reports to a local folder laid out like the upstream repo."""
    case = _case(case_id, db_path)
    blockers = eligibility(case)
    if blockers:
        raise ValueError("case is not eligible for OSV submission: " + "; ".join(blockers))
    advisory_id = assign_advisory_id(case["case_id"], db_path=db_path)
    urls = _urls(advisory_id, case)
    out_dir = Path(out_dir or Path("out") / "osv-submissions" / advisory_id)
    files = []
    for report in build_mal_reports(case, advisory_id, **urls):
        problems = validate_mal_report(report)
        if problems:
            raise ValueError(f"report for {report['affected'][0]['package']['name']} is invalid: " + "; ".join(problems))
        relative = mal_report_path(report, advisory_id)
        target = out_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        files.append(relative)
    return {"advisory_id": advisory_id, "out_dir": str(out_dir), "files": files}


def submit_osv(case_id: str, *, confirm: bool = False, db_path: Optional[str] = None, runner: Optional[Callable[..., Any]] = None, actor: str = "secopsai") -> Dict[str, Any]:
    """Open a pull request to ossf/malicious-packages.  Dry run unless confirm=True."""
    prepared = prepare_osv_submission(case_id, db_path=db_path)
    advisory_id = prepared["advisory_id"]
    branch = f"secopsai-{advisory_id.lower()}"
    title = f"Add malicious package report{'s' if len(prepared['files']) > 1 else ''} from SecOpsAI ({advisory_id})"
    body = (f"Reports from SecOpsAI Research advisory {advisory_id}.\n\n"
            + "\n".join(f"- `{path}`" for path in prepared["files"])
            + f"\n\nAdvisory: {_urls(advisory_id, _case(case_id, db_path))['advisory_url']}\n")
    plan = {"advisory_id": advisory_id, "repo": UPSTREAM_REPO, "branch": branch, "title": title, "files": prepared["files"], "submitted": False}
    if not confirm:
        return {**plan, "message": "dry run: rerun with confirm=True (CLI: research osv submit --confirm) to fork, push and open the pull request"}
    run = runner or (lambda args, **kwargs: subprocess.run(args, check=True, capture_output=True, text=True, **kwargs))
    workdir = Path(tempfile.mkdtemp(prefix="secopsai-osv-"))
    try:
        run(["gh", "repo", "fork", UPSTREAM_REPO, "--clone=false"])
        login = run(["gh", "api", "user", "--jq", ".login"]).stdout.strip()
        clone = workdir / "repo"
        run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", f"https://github.com/{login}/malicious-packages.git", str(clone)])
        run(["git", "-C", str(clone), "remote", "add", "upstream", f"https://github.com/{UPSTREAM_REPO}.git"])
        run(["git", "-C", str(clone), "fetch", "--depth", "1", "upstream", "main"])
        run(["git", "-C", str(clone), "checkout", "-b", branch, "upstream/main"])
        for relative in prepared["files"]:
            run(["git", "-C", str(clone), "sparse-checkout", "add", str(Path(relative).parent)])
            target = clone / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(Path(prepared["out_dir"]) / relative, target)
            run(["git", "-C", str(clone), "add", relative])
        # ossf/malicious-packages requires a DCO sign-off on every commit.
        run(["git", "-C", str(clone), "commit", "-s", "-m", title])
        run(["git", "-C", str(clone), "push", "origin", branch])
        url = run(["gh", "pr", "create", "--repo", UPSTREAM_REPO, "--head", f"{login}:{branch}", "--title", title, "--body", body]).stdout.strip()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    now = _now()
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        connection.execute("UPDATE research_advisories SET status = 'submitted', submission_json = ?, updated_at = ? WHERE advisory_id = ?",
                           (json.dumps({"pull_request": url, "files": prepared["files"], "submitted_at": now}), now, advisory_id))
        connection.commit()
    _record(case_id, "osv_submitted", f"Submitted {advisory_id} to {UPSTREAM_REPO}.", {"pull_request": url}, db_path, actor)
    return {**plan, "submitted": True, "pull_request": url}


def record_osv_ids(case_id: str, osv_ids: List[str], *, db_path: Optional[str] = None, actor: str = "secopsai") -> Dict[str, Any]:
    """Store the MAL- ids OpenSSF assigned; they become advisory aliases and appear in the post's tracker."""
    ids = sorted({value.strip() for value in osv_ids if re.fullmatch(r"MAL-\d{4}-\d+", value.strip())})
    if not ids:
        raise ValueError("expected ids like MAL-2026-1234")
    row = _advisory_row(case_id, db_path)
    if not row:
        raise ValueError("case has no advisory yet")
    merged = sorted(set(row["osv_ids"]) | set(ids))
    now = _now()
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        connection.execute("UPDATE research_advisories SET osv_ids_json = ?, updated_at = ? WHERE advisory_id = ?", (json.dumps(merged), now, row["advisory_id"]))
        payload = connection.execute("SELECT payload_json FROM research_cases WHERE case_id = ?", (case_id,)).fetchone()
        metadata = json.loads(payload["payload_json"] or "{}") if payload else {}
        metadata.update({"osv_id": ", ".join(merged), "osv_published_at": metadata.get("osv_published_at") or now})
        connection.execute("UPDATE research_cases SET payload_json = ?, updated_at = ? WHERE case_id = ?", (json.dumps(metadata, sort_keys=True), now, case_id))
        connection.commit()
    _record(case_id, "osv_ids_recorded", "Recorded OSV ids " + ", ".join(merged) + ".", {"osv_ids": merged}, db_path, actor)
    return {"advisory_id": row["advisory_id"], "osv_ids": merged}
