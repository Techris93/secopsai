"""Stream scan: prescan every new npm and PyPI release within minutes.

Frontier phase 1. The hourly research worker can prescan about 150 releases a
cycle; the registries publish tens of thousands a day. This scanner reads the
full change streams from saved cursors (npm's CouchDB changes feed, PyPI's
changelog) and gives every new release the same static prescan the worker's
content funnel uses (archive members, YARA, behaviour rules; nothing is
installed or executed). Releases at warning level or above get the Fast Lane
diff against their previous version and a signed alert when the delta is risky.

State (cursors and a bounded backlog) and per-hour coverage statistics are
kept in the ledger store, one write each per run. Releases not reached within
the run's time budget stay in the backlog for the next run, so a burst delays
verdicts but never drops releases silently: the statistics count every
published release, scanned or not.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from secopsai import takeover_signals

NPM_CHANGES = "https://replicate.npmjs.com/_changes"
NPM_REGISTRY = "https://registry.npmjs.org/"
NPM_HOSTS = ("replicate.npmjs.com", "registry.npmjs.org")
PYPI_XMLRPC = "https://pypi.org/pypi"
MCP_REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
MCP_HOSTS = ("registry.modelcontextprotocol.io",)
MCP_PAGES = 20
# Package types the content scan can read; remote-only and OCI servers are counted, not scanned.
MCP_SCANNABLE = {"npm": "npm", "pypi": "pypi"}
NPM_PAGE = 1000
MAX_NPM_PAGES = 30
MAX_BACKLOG = 20000
MAX_SEEN = 20000
STATS_HOURS = 48
MAX_LATENCIES_PER_BUCKET = 3000
ESCALATE_LEVELS = {"warning", "alert"}
SCANNED = {"hit", "clean"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(value: Any) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def key(target: Dict[str, Any]) -> str:
    return f"{target['ecosystem']}:{str(target['package']).lower()}@{target['version']}"


# --- discovery ----------------------------------------------------------------

def npm_changes(fetch_json: Callable[[str], Dict[str, Any]], since: Optional[str]) -> Tuple[List[str], Optional[str]]:
    """Package names changed since the cursor, and the new cursor."""
    if since is None:
        root = fetch_json("https://replicate.npmjs.com/")
        return [], str(root.get("update_seq"))
    names: List[str] = []
    cursor = since
    for _ in range(MAX_NPM_PAGES):
        feed = fetch_json(f"{NPM_CHANGES}?since={cursor}&limit={NPM_PAGE}")
        for change in feed.get("results") or []:
            if not change.get("deleted") and change.get("id") and not str(change["id"]).startswith("_design/"):
                names.append(str(change["id"]))
        if feed.get("last_seq") is not None:
            cursor = str(feed["last_seq"])
        if len(feed.get("results") or []) < NPM_PAGE:
            break
    return list(dict.fromkeys(names)), cursor


def npm_new_versions(fetch_json: Callable[[str], Dict[str, Any]], names: Iterable[str], since: datetime,
                     workers: int = 16) -> Tuple[List[Dict[str, Any]], int]:
    """Versions of the changed packages published after ``since`` (and how many documents failed)."""
    found: List[Dict[str, Any]] = []
    failures = 0

    def one(name: str) -> List[Dict[str, Any]]:
        doc = fetch_json(NPM_REGISTRY + name.replace("/", "%2F"))
        out = []
        for version, stamp in (doc.get("time") or {}).items():
            published = _parse(stamp)
            if version in {"created", "modified"} or published is None or published <= since:
                continue
            if version in (doc.get("versions") or {}):
                signals = takeover_signals.npm_signals(doc, version)
                out.append({"ecosystem": "npm", "package": name, "version": version, "published_at": _iso(published),
                            "takeover": {key: signals[key] for key in ("signals", "score")}})
        return out

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(one, name) for name in names]
        for future in as_completed(futures):
            try:
                found.extend(future.result())
            except Exception:
                failures += 1
    return found, failures


def pypi_new_releases(changelog: Callable[[int], List[list]], last_serial: Callable[[], int],
                      serial: Optional[int], roles: Optional[Dict[str, str]] = None) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    """'new release' events since the serial, and the new serial.

    Owner or maintainer additions are remembered in ``roles`` (package -> when),
    so a release soon after one is flagged.
    """
    if serial is None:
        return [], int(last_serial())
    events = changelog(int(serial))
    releases = []
    newest = int(serial)
    for name, version, stamp, action, event_serial in events:
        newest = max(newest, int(event_serial))
        if roles is not None and str(action).startswith(("add Owner", "add Maintainer")):
            roles[str(name).lower()] = _iso(datetime.fromtimestamp(int(stamp), timezone.utc))
        if action == "new release" and version:
            published = datetime.fromtimestamp(int(stamp), timezone.utc)
            releases.append({"ecosystem": "pypi", "package": str(name), "version": str(version), "published_at": _iso(published)})
    return releases, newest


def mcp_new_servers(fetch_json: Callable[[str], Dict[str, Any]], since: Optional[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """New MCP registry server versions since the cursor: (package-backed targets, unscannable, new cursor).

    A target's ``packages`` are the npm and PyPI packages the server runs; its
    verdict is the content scan of those packages.
    """
    current = _now()
    if since is None:
        return [], [], _iso(current)
    floor = _parse(since) or current
    targets: List[Dict[str, Any]] = []
    unscannable: List[Dict[str, Any]] = []
    newest = floor
    cursor = ""
    from urllib.parse import quote
    for _ in range(MCP_PAGES):
        page = fetch_json(f"{MCP_REGISTRY}?limit=100&updated_since={quote(_iso(floor - timedelta(minutes=5)))}"
                          + (f"&cursor={quote(cursor)}" if cursor else ""))
        for item in page.get("servers") or []:
            server = item.get("server") or {}
            meta = (item.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
            published = _parse(meta.get("publishedAt"))
            if not server.get("name") or not server.get("version") or published is None or published <= floor:
                continue
            newest = max(newest, published)
            packages = [{"ecosystem": MCP_SCANNABLE[str(package.get("registryType"))], "package": str(package.get("identifier")),
                         "version": str(package.get("version") or server["version"])}
                        for package in server.get("packages") or []
                        if str(package.get("registryType")) in MCP_SCANNABLE and package.get("identifier")]
            target = {"ecosystem": "mcp-registry", "package": str(server["name"]), "version": str(server["version"]),
                      "published_at": _iso(published)}
            if packages:
                targets.append({**target, "packages": packages[:5]})
            else:
                kinds = sorted({str(package.get("registryType")) for package in server.get("packages") or []}
                               | ({"remote"} if server.get("remotes") else set()))
                unscannable.append({**target, "kinds": kinds})
        cursor = str((page.get("metadata") or {}).get("nextCursor") or "")
        if not cursor:
            break
    return targets, unscannable, _iso(newest)


def scan_mcp(scan_package: Callable[[Dict[str, Any]], Dict[str, Any]], target: Dict[str, Any]) -> Dict[str, Any]:
    """An MCP server's verdict is the worst verdict of the packages it runs."""
    order = {"error": 0, "clean": 1, "hit": 2}
    levels = {"none": 0, "info": 1, "warning": 2, "alert": 3}
    worst: Dict[str, Any] = {"status": "error", "reason": "no packages"}
    for package in target.get("packages") or []:
        result = scan_package(package)
        if (order.get(result.get("status"), 0), levels.get(result.get("level"), 0)) > (order.get(worst.get("status"), 0), levels.get(worst.get("level"), 0)):
            worst = {**result, "package": package}
    return worst


# --- statistics ---------------------------------------------------------------

def _bucket(stats: Dict[str, Any], published_at: str, ecosystem: str) -> Dict[str, Any]:
    hour = str(published_at)[:13]
    return stats.setdefault("hours", {}).setdefault(hour, {}).setdefault(
        ecosystem, {"published": 0, "scanned": 0, "hits": 0, "errors": 0, "latencies": []})


def record_unscannable(stats: Dict[str, Any], targets: Iterable[Dict[str, Any]]) -> None:
    for target in targets:
        bucket = _bucket(stats, target["published_at"], target["ecosystem"])
        bucket["unscannable"] = bucket.get("unscannable", 0) + 1


def record_published(stats: Dict[str, Any], targets: Iterable[Dict[str, Any]]) -> None:
    for target in targets:
        _bucket(stats, target["published_at"], target["ecosystem"])["published"] += 1


def record_verdict(stats: Dict[str, Any], target: Dict[str, Any], result: Dict[str, Any], verdict_at: datetime) -> None:
    bucket = _bucket(stats, target["published_at"], target["ecosystem"])
    status = result.get("status")
    if status in SCANNED:
        bucket["scanned"] += 1
        bucket["hits"] += int(status == "hit")
        published = _parse(target["published_at"])
        if published and len(bucket["latencies"]) < MAX_LATENCIES_PER_BUCKET:
            bucket["latencies"].append(round(max(0.0, (verdict_at - published).total_seconds() / 60), 1))
    elif status == "error":
        bucket["errors"] += 1


MAX_FLAGGED = 3000


def record_takeover(stats: Dict[str, Any], target: Dict[str, Any], takeover: Optional[Dict[str, Any]] = None) -> None:
    """Count the flag and keep the release, so it can later be checked against published advisories."""
    bucket = _bucket(stats, target["published_at"], target["ecosystem"])
    bucket["takeover_flags"] = bucket.get("takeover_flags", 0) + 1
    flagged = stats.setdefault("takeover_flagged", [])
    flagged.append({"ecosystem": target["ecosystem"], "package": target["package"], "version": target["version"],
                    "published_at": target["published_at"], **{key: (takeover or {}).get(key) for key in ("signals", "score")}})
    del flagged[:-MAX_FLAGGED]


def prune_stats(stats: Dict[str, Any], now: datetime) -> None:
    oldest = (now - timedelta(hours=STATS_HOURS)).strftime("%Y-%m-%dT%H")
    stats["hours"] = {hour: value for hour, value in (stats.get("hours") or {}).items() if hour >= oldest}


def _percentile(values: List[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))]


def coverage_from_stats(stats: Dict[str, Any], *, now: Optional[datetime] = None, hours: int = 24,
                        settle_minutes: int = 60) -> Dict[str, Any]:
    """The live coverage block the frontier scorecard scores, from the stream statistics.

    Hours are judged once settled: the current hour, and any hour that ended
    less than ``settle_minutes`` ago, are left out.
    """
    current = now or _now()
    first = (current - timedelta(hours=hours)).strftime("%Y-%m-%dT%H")
    last = (current - timedelta(minutes=settle_minutes) - timedelta(hours=1)).strftime("%Y-%m-%dT%H")
    totals: Dict[str, Dict[str, Any]] = {}
    for hour, ecosystems in (stats.get("hours") or {}).items():
        if not (first <= hour <= last):
            continue
        for ecosystem, bucket in ecosystems.items():
            total = totals.setdefault(ecosystem, {"published": 0, "scanned": 0, "hits": 0, "errors": 0, "unscannable": 0, "latencies": []})
            for field in ("published", "scanned", "hits", "errors", "unscannable"):
                total[field] += int(bucket.get(field) or 0)
            total["latencies"] += list(bucket.get("latencies") or [])
    report: Dict[str, Any] = {"source": "stream_scan", "window_hours": hours, "settle_minutes": settle_minutes, "ecosystems": {}}
    everything: Dict[str, Any] = {"published": 0, "scanned": 0, "latencies": []}
    for ecosystem, total in sorted(totals.items()):
        if not total["published"] and not total["unscannable"]:
            continue
        report["ecosystems"][ecosystem] = {
            "published": total["published"], "scanned": total["scanned"], "hits": total["hits"], "errors": total["errors"],
            **({"unscannable": total["unscannable"]} if total["unscannable"] else {}),
            "coverage": round(total["scanned"] / total["published"], 4) if total["published"] else None,
            "p50_minutes": _percentile(total["latencies"], 0.5), "p95_minutes": _percentile(total["latencies"], 0.95)}
        everything["published"] += total["published"]
        everything["scanned"] += total["scanned"]
        everything["latencies"] += total["latencies"]
    report["all"] = {"published": everything["published"], "scanned": everything["scanned"],
                     "coverage": round(everything["scanned"] / everything["published"], 4) if everything["published"] else None,
                     "p50_minutes": _percentile(everything["latencies"], 0.5), "p95_minutes": _percentile(everything["latencies"], 0.95)}
    return report


# --- run ----------------------------------------------------------------------

def run(*, state: Dict[str, Any], stats: Dict[str, Any], fetch_json: Callable[[str], Dict[str, Any]],
        pypi_changelog: Callable[[int], List[list]], pypi_last_serial: Callable[[], int],
        scan: Callable[[Dict[str, Any]], Dict[str, Any]], escalate: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]],
        budget_seconds: float = 900, workers: int = 12, now: Callable[[], datetime] = _now, mcp: bool = False,
        clock: Callable[[], float] = time.monotonic) -> Dict[str, Any]:
    """One pass. Mutates and returns ``state`` and ``stats``; the caller saves them."""
    started = clock()
    current = now()
    summary: Dict[str, Any] = {"discovered": {}, "scanned": 0, "hits": 0, "escalated": 0, "alerts": 0, "errors": 0, "takeover_flags": 0,
                               "backlog_before": len(state.get("backlog") or []), "dropped": 0, "discovery_failures": 0}
    seen = list(state.get("seen") or [])
    seen_set = set(seen)

    names, npm_cursor = npm_changes(fetch_json, state.get("npm_seq"))
    npm_since = _parse(state.get("npm_since")) or (current - timedelta(minutes=30))
    npm_targets, failures = npm_new_versions(fetch_json, names, npm_since, workers=workers) if names else ([], 0)
    summary["discovery_failures"] += failures
    roles = dict(state.get("pypi_roles") or {})
    pypi_targets, pypi_serial = pypi_new_releases(pypi_changelog, pypi_last_serial, state.get("pypi_serial"), roles)
    for target in pypi_targets:
        if roles.get(target["package"].lower()):
            target["role_added_at"] = roles[target["package"].lower()]
    mcp_targets: List[Dict[str, Any]] = []
    mcp_cursor = state.get("mcp_since")
    if mcp:
        try:
            mcp_targets, unscannable, mcp_cursor = mcp_new_servers(fetch_json, state.get("mcp_since"))
            unscannable = [target for target in unscannable if key(target) not in seen_set]
            record_unscannable(stats, unscannable)
            summary["discovered"]["mcp-registry-unscannable"] = len(unscannable)
            seen.extend(key(target) for target in unscannable)
        except Exception:  # noqa: BLE001 - the registry being down must not stop npm and PyPI
            summary["discovery_failures"] += 1

    fresh = [target for target in npm_targets + pypi_targets + mcp_targets if key(target) not in seen_set]
    fresh = list({key(target): target for target in fresh}.values())
    for target in fresh:
        summary["discovered"][target["ecosystem"]] = summary["discovered"].get(target["ecosystem"], 0) + 1
        seen.append(key(target))
    record_published(stats, fresh)
    queue = sorted((state.get("backlog") or []) + fresh, key=lambda target: target["published_at"])

    done: List[str] = []
    remaining: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        pending = {}
        position = 0
        while position < len(queue) or pending:
            while position < len(queue) and len(pending) < workers * 2 and clock() - started < budget_seconds:
                target = queue[position]
                pending[pool.submit(scan, target)] = target
                position += 1
            if not pending:
                break
            future = next(as_completed(list(pending)))
            target = pending.pop(future)
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - one release must not stop the stream
                result = {"status": "error", "reason": f"{type(exc).__name__}: {str(exc)[:200]}"}
            record_verdict(stats, target, result, now())
            done.append(key(target))
            if result.get("status") in SCANNED:
                summary["scanned"] += 1
                summary["hits"] += int(result.get("status") == "hit")
            elif result.get("status") == "error":
                summary["errors"] += 1
            takeover = result.get("takeover") or target.get("takeover") or {}
            if takeover.get("score", 0) >= takeover_signals.ESCALATE_SCORE:
                summary["takeover_flags"] += 1
                record_takeover(stats, target, takeover)
            if result.get("level") in ESCALATE_LEVELS or takeover.get("score", 0) >= takeover_signals.ESCALATE_SCORE:
                summary["escalated"] += 1
                try:
                    # An MCP server is escalated as the package that raised the verdict.
                    subject = ({**result["package"], "published_at": target["published_at"], "mcp_server": target["package"]}
                               if target["ecosystem"] == "mcp-registry" and result.get("package") else target)
                    outcome = escalate(subject, result)
                    summary["alerts"] += int(bool(outcome.get("alerted")))
                except Exception:  # noqa: BLE001 - the prescan verdict is already recorded
                    summary["errors"] += 1
        remaining = queue[position:]

    if len(remaining) > MAX_BACKLOG:
        summary["dropped"] = len(remaining) - MAX_BACKLOG
        remaining = remaining[-MAX_BACKLOG:]  # keep the newest; the dropped are counted, never hidden
    newest = max([_parse(target["published_at"]) for target in npm_targets if _parse(target["published_at"])] or [npm_since])
    cutoff = _iso(current - timedelta(days=30))
    roles = dict(sorted(((name, when) for name, when in roles.items() if when >= cutoff), key=lambda item: item[1])[-5000:])
    state.update({"mcp_since": mcp_cursor, "pypi_roles": roles, "npm_seq": npm_cursor, "npm_since": _iso(max(npm_since, newest - timedelta(minutes=10))),
                  "pypi_serial": pypi_serial, "backlog": remaining, "seen": seen[-MAX_SEEN:], "updated_at": _iso(now())})
    prune_stats(stats, now())
    summary.update(backlog_after=len(remaining), elapsed_seconds=round(clock() - started, 1))
    return summary


def pypi_client(timeout: int = 60) -> Tuple[Callable[[int], List[list]], Callable[[], int]]:
    """PyPI's XML-RPC changelog, parsed with defusedxml (no entity expansion or external entities)."""
    import ssl

    from defusedxml.xmlrpc import monkey_patch

    monkey_patch()
    import xmlrpc.client  # nosec B411

    class TimeoutTransport(xmlrpc.client.SafeTransport):
        def make_connection(self, host):  # noqa: ANN001
            connection = super().make_connection(host)
            connection.timeout = timeout
            return connection

    proxy = xmlrpc.client.ServerProxy(PYPI_XMLRPC, transport=TimeoutTransport(context=ssl.create_default_context()))
    return proxy.changelog_since_serial, proxy.changelog_last_serial
