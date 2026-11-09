"""Vulnerable-version checks for package advisories named in the daily brief.

A check is the advisory's own OSV record: which package versions are
affected and which release fixes them.  SecOpsAI tests each record before the
brief names it (an affected version must be flagged and the fixed release must
not), and ``secopsai supply-chain advisory-check`` applies it to a project's
manifests and lockfiles.  Nothing is installed, imported or executed.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility.
    import tomli as tomllib

OSV_URL = "https://api.osv.dev/v1/vulns/{advisory}"
OSV_HOSTS = ("api.osv.dev",)
CHECKS_KIND = "advisory_version_check"
CHECK_TTL_DAYS = 7
ECOSYSTEMS = {"PyPI": "pypi", "npm": "npm", "Go": "go"}
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "vendor", "dist", "build"}
MAX_FILE_BYTES = 8 << 20


def advisory_id(url: str) -> str:
    """The GitHub advisory ID in an advisory URL, or ""."""
    match = GHSA_RE.search(url or "")
    return match.group(0) if match else ""


# --- version ordering ------------------------------------------------------

_PEP440 = re.compile(r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?"
                     r"(?:[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+.*)?$", re.IGNORECASE)
_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def _pep440_key(version: str) -> tuple:
    match = _PEP440.match(version.strip().lower())
    if not match:
        raise ValueError(f"not a PEP 440 version: {version}")
    epoch, release, pre, pre_n, post, post_n, dev, dev_n = match.groups()
    numbers = [int(part) for part in release.split(".")]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    phase = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
    # dev < pre-release < final < post-release
    if pre:
        stage = (1, phase[pre], int(pre_n or 0))
    elif dev and not post:
        stage = (0, 0, 0)
    else:
        stage = (2, 0, 0)
    return (int(epoch or 0), tuple(numbers), stage, (1, int(post_n or 0)) if post else (0, 0),
            (0, int(dev_n or 0)) if dev else (1, 0))


def _semver_key(version: str) -> tuple:
    match = _SEMVER.match(version.strip())
    if not match:
        raise ValueError(f"not a semantic version: {version}")
    major, minor, patch, pre = match.groups()
    core = (int(major), int(minor or 0), int(patch or 0))
    if not pre:
        return core + ((1,),)
    # A pre-release sorts before its release; identifiers compare numerically
    # when numeric, and numeric identifiers sort before alphanumeric ones.
    parts = tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split("."))
    return core + ((0,) + parts,)


def version_key(ecosystem: str, version: str) -> tuple:
    return _pep440_key(version) if ecosystem == "pypi" else _semver_key(version)


def _normal_name(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name


# --- OSV records -----------------------------------------------------------

def packages(record: dict) -> list[dict]:
    """Affected packages in an OSV record that SecOpsAI can check."""
    found = []
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = ECOSYSTEMS.get(str(package.get("ecosystem") or ""))
        name = str(package.get("name") or "")
        if not ecosystem or not name:
            continue
        ranges = [r for r in affected.get("ranges") or [] if r.get("type") in {"ECOSYSTEM", "SEMVER"}]
        versions = [str(v) for v in affected.get("versions") or []]
        if not ranges and not versions:
            continue
        fixed = [str(event["fixed"]) for r in ranges for event in r.get("events") or [] if event.get("fixed")]
        found.append({"ecosystem": ecosystem, "name": _normal_name(ecosystem, name), "ranges": ranges,
                      "versions": versions, "fixed": fixed})
    return found


def _in_ranges(ecosystem: str, version: str, ranges: list[dict]) -> bool:
    key = version_key(ecosystem, version)
    for entry in ranges:
        events = []
        for event in entry.get("events") or []:
            for kind in ("introduced", "fixed", "last_affected"):
                if kind in event:
                    value = str(event[kind])
                    bound = (0,) if value == "0" else version_key(ecosystem, value)
                    events.append((bound, kind))
        events.sort(key=lambda item: item[0])
        affected = False
        for bound, kind in events:
            if kind == "introduced" and key >= bound:
                affected = True
            elif kind == "fixed" and key >= bound:
                affected = False
            elif kind == "last_affected" and key > bound:
                affected = False
        if affected:
            return True
    return False


def is_affected(package: dict, version: str) -> bool:
    if version in package["versions"]:
        return True
    try:
        return _in_ranges(package["ecosystem"], version, package["ranges"])
    except ValueError:
        return False


def _affected_sample(package: dict) -> Optional[str]:
    if package["versions"]:
        return package["versions"][-1]
    for entry in package["ranges"]:
        for event in entry.get("events") or []:
            value = str(event.get("introduced") or "")
            if value and value != "0":
                return value
    # "Affected from the first release": the lowest version the ecosystem allows.
    return {"pypi": "0.0.1", "npm": "0.0.0-0", "go": "0.0.0-0"}[package["ecosystem"]]


def self_test(record: dict) -> dict:
    """Test a record before the brief names it: every package must flag an
    affected version, leave each fixed release alone, and agree with the
    record's own list of affected versions."""
    tested = []
    for package in packages(record):
        if not package["fixed"]:
            return {"ok": False, "reason": f"{package['name']}: the record names no fixed release"}
        sample = _affected_sample(package)
        try:
            ranged = {version: _in_ranges(package["ecosystem"], version, package["ranges"]) for version in package["versions"]}
            sample_hit = is_affected(package, sample)
            fixed_hits = [fixed for fixed in package["fixed"] if is_affected(package, fixed)]
        except ValueError as exc:
            return {"ok": False, "reason": f"{package['name']}: {exc}"}
        if not sample_hit:
            return {"ok": False, "reason": f"{package['name']}: affected version {sample} was not flagged"}
        if fixed_hits:
            return {"ok": False, "reason": f"{package['name']}: fixed release {fixed_hits[0]} was flagged"}
        if package["ranges"] and package["versions"] and not all(ranged.values()):
            missed = next(version for version, hit in ranged.items() if not hit)
            return {"ok": False, "reason": f"{package['name']}: listed version {missed} falls outside the record's ranges"}
        tested.append({"ecosystem": package["ecosystem"], "name": package["name"], "fixed": package["fixed"]})
    if not tested:
        return {"ok": False, "reason": "no PyPI, npm or Go package in the record"}
    return {"ok": True, "packages": tested}


def _fetch_record(advisory: str, fetch: Callable[[str], Any]) -> dict:
    body = fetch(OSV_URL.format(advisory=advisory))
    record = json.loads(body)
    if not isinstance(record, dict) or record.get("id") != advisory and advisory not in (record.get("aliases") or []):
        raise ValueError("OSV returned a different advisory")
    return record


# --- brief stage -----------------------------------------------------------

def latest_checks(*, db_path=None) -> dict[str, dict]:
    from secopsai.research_operation_store import records

    latest: dict[str, dict] = {}
    for row in records(CHECKS_KIND, db_path=db_path, limit=2000):
        latest.setdefault(row["payload"]["advisory"], {**row["payload"], "checked_at": row["created_at"]})
    return latest


def run_checks(fetch: Callable[[str], Any], advisories: Iterable[str], *, db_path=None,
               now: Optional[datetime] = None, limit: int = 5) -> dict:
    """Test the OSV record of each advisory that has no recent result."""
    from secopsai.research_operation_store import append

    now = now or datetime.now(timezone.utc)
    previous = latest_checks(db_path=db_path)
    checked = []
    for advisory in dict.fromkeys(a for a in advisories if a):
        prior = previous.get(advisory)
        if prior:
            age = now - datetime.fromisoformat(prior["checked_at"].replace("Z", "+00:00"))
            if age < timedelta(days=CHECK_TTL_DAYS) and not prior.get("unavailable"):
                continue
        if len(checked) >= limit:
            break
        try:
            result = {"advisory": advisory, **self_test(_fetch_record(advisory, fetch))}
        except Exception as exc:  # a missing record is retried, never published
            result = {"advisory": advisory, "ok": False, "unavailable": True, "reason": type(exc).__name__}
        append(CHECKS_KIND, result, actor="secopsai-automated-research-desk", db_path=db_path)
        checked.append(advisory)
    return {"checked": checked}


def recent_brief_advisories(*, db_path=None, days: int = 7) -> list[str]:
    """GitHub advisories named by items in the briefs of the last ``days`` days.

    Read from the brief drafts themselves: the verification log is dominated
    by automated rejections, so its newest rows rarely reach a brief item.
    """
    import soc_store
    from secopsai.research_operation_store import read_connection

    since = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
    soc_store.init_db(db_path)
    with read_connection(db_path) as conn:
        rows = conn.execute("SELECT draft_json FROM research_editorial_editions WHERE edition_date>=? ORDER BY edition_date DESC",
                            (since,)).fetchall()
    found = []
    for row in rows:
        try:
            items = json.loads(row["draft_json"]).get("items") or []
        except (TypeError, ValueError):
            continue
        found.extend(advisory_id(str(item.get("url") or "")) for item in items)
    return [a for a in dict.fromkeys(found) if a]


def _range_text(package: dict) -> str:
    fixed = sorted(package["fixed"], key=lambda v: version_key(package["ecosystem"], v))
    return f"{package['name']} before {' or '.join(fixed)}" if len(fixed) == 1 else f"{package['name']} below the fixed releases {', '.join(fixed)}"


def brief_line(url: str, *, db_path=None, checks: Optional[dict] = None) -> list[str]:
    """The brief's detection line for an item whose check passed its test."""
    advisory = advisory_id(url)
    check = (checks if checks is not None else latest_checks(db_path=db_path)).get(advisory) if advisory else None
    if not check or not check.get("ok"):
        return []
    flagged = "; ".join(_range_text({**package, "fixed": package["fixed"]}) for package in check["packages"])
    return [f"SecOpsAI detection: `secopsai supply-chain advisory-check --advisory {advisory} PATH` "
            f"flags {flagged} in a project's manifests and lockfiles."]


# --- project scan ----------------------------------------------------------

def _files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.is_file() and path.stat().st_size <= MAX_FILE_BYTES:
            yield path


def installed_versions(root: str | Path) -> list[dict]:
    """Exact package versions pinned in manifests and lockfiles under ``root``."""
    root = Path(root)
    found = []

    def add(ecosystem, name, version, path):
        version = str(version or "").strip()
        if name and version:
            found.append({"ecosystem": ecosystem, "name": _normal_name(ecosystem, str(name)), "version": version,
                          "file": str(path.relative_to(root) if root.is_dir() else path.name)})

    for path in _files(root):
        name = path.name
        try:
            if name == "package-lock.json":
                data = json.loads(path.read_text(encoding="utf-8"))
                for key, entry in (data.get("packages") or {}).items():
                    if key and isinstance(entry, dict):
                        add("npm", entry.get("name") or key.rsplit("node_modules/", 1)[-1], entry.get("version"), path)
                if not data.get("packages"):
                    for package, entry in (data.get("dependencies") or {}).items():
                        add("npm", package, (entry or {}).get("version"), path)
            elif re.fullmatch(r"requirements[\w.-]*\.txt", name):
                for line in path.read_text(encoding="utf-8").splitlines():
                    match = re.match(r"^\s*([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)", line)
                    if match:
                        add("pypi", match.group(1), match.group(2), path)
            elif name in {"poetry.lock", "uv.lock", "pdm.lock"}:
                for entry in tomllib.loads(path.read_text(encoding="utf-8")).get("package") or []:
                    add("pypi", entry.get("name"), entry.get("version"), path)
            elif name == "Pipfile.lock":
                data = json.loads(path.read_text(encoding="utf-8"))
                for section in ("default", "develop"):
                    for package, entry in (data.get(section) or {}).items():
                        add("pypi", package, str((entry or {}).get("version") or "").lstrip("="), path)
            elif name == "go.mod":
                text = path.read_text(encoding="utf-8")
                for module, version in re.findall(r"^\s*(?:require\s+)?([\w.~-]+(?:/[\w.~-]+)+)\s+(v[\w.+-]+)", text, re.M):
                    add("go", module, version.lstrip("v"), path)
        except (OSError, ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            continue
    return found


def scan(root: str | Path, advisories: list[str], fetch: Callable[[str], Any]) -> dict:
    """Which pinned versions under ``root`` the named advisories affect."""
    tested, findings = [], []
    installed = installed_versions(root)
    for advisory in advisories:
        record = _fetch_record(advisory, fetch)
        result = self_test(record)
        tested.append({"advisory": advisory, **result})
        if not result["ok"]:
            continue
        for package in packages(record):
            for item in installed:
                if (item["ecosystem"], item["name"]) == (package["ecosystem"], package["name"]) and is_affected(package, item["version"]):
                    findings.append({"advisory": advisory, **item, "fixed": package["fixed"]})
    return {"advisories": tested, "packages_read": len(installed), "findings": findings}
