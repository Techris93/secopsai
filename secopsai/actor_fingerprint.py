"""Actor fingerprinting: link flagged packages into campaigns.

Every flagged package contributes fingerprints:

- ``infra``: exfiltration / webhook URLs (with their ids), raw IPs and
  domains found in the code that triggered a rule (not every URL in the
  package, which keeps big packages from linking through common CDNs);
- ``code``: a 64-bit simhash of the normalised file that carried the
  behaviour, so lightly edited copies of one payload still match;
- ``publisher``: author / maintainer email from the manifest.

Packages sharing a fingerprint are linked (code: simhash within
``CODE_DISTANCE`` bits); an indicator seen in more than ``MAX_SHARED``
packages is treated as common and ignored.  Connected packages form a
campaign with a stable id derived from its earliest member.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import closing
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import soc_store

CODE_DISTANCE = 3
MAX_SHARED = 40
URL = re.compile(r"https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s'\"`<>)]*)?")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Domains only as whole string literals: bare code (System.IO) is not a domain,
# and .sh is left out because script names ("run.sh") are far more common.
DOMAIN = re.compile(r"['\"`]((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|top|ru|cn|tk|ml|ga|cf|gq|pw|cc|su|info|biz|app|dev|site|online|live|fun|pro|me|in|co|us|to))['\"`]", re.IGNORECASE)
# Shared by many unrelated actors or tools: never an actor fingerprint.
GENERIC_HOST = re.compile(
    r"^(localhost|.*\.local|.*\.internal|metadata\.google\.internal|169\.254\.\d+\.\d+|127\.\d+\.\d+\.\d+|0\.0\.0\.0|"
    r"(api\d*\.)?ipify\.org|ifconfig\.(me|co)|ipinfo\.io|icanhazip\.com|ip-api\.com|checkip\.amazonaws\.com|wtfismyip\.com|myexternalip\.com|"
    r"(.*\.)?(gmail|outlook|hotmail|yahoo|proton|protonmail|icloud)\.(com|me)|"
    r"(.*\.)?(amazon\.com|amazonaws\.com\.cn|amazonwebservices\.com\.cn|kubernetes\.io|golang\.org|grpc\.io|gstatic\.com|ietf\.org|"
    r"roblox\.com|wikipedia\.org|stackoverflow\.com|docker\.com|docker\.io|gitlab\.com|bitbucket\.org|npms\.io))$",
    re.IGNORECASE,
)
MAX_SHARED_HOST = 15
FOCUSED_HOSTS = 3
MAX_DOMAINS_PER_FILE = 25
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
COMMON = re.compile(
    r"(^|\.)(npmjs\.(org|com)|github\.com|githubusercontent\.com|pypi\.org|pythonhosted\.org|nodejs\.org|python\.org|"
    r"googleapis\.com|google\.com|w3\.org|schema\.org|example\.(com|org|net)|mozilla\.org|microsoft\.com|apache\.org|"
    r"opensource\.org|jsdelivr\.net|unpkg\.com|cloudflare\.com|amazonaws\.com|readthedocs\.io|yarnpkg\.com|json-schema\.org)$",
    re.IGNORECASE,
)
# Shared platforms: only the specific webhook / bot / bin identifies an actor.
PLATFORM = re.compile(r"(^|\.)(discord(app)?\.com|telegram\.org|pastebin\.com|webhook\.site|pipedream\.net|ngrok(-free)?\.(io|app|dev)|"
                      r"requestbin\.(com|net)|canarytokens\.(com|org)|transfer\.sh|oast\.(fun|pro|site|me|live|online)|interactsh\.com|burpcollaborator\.net|"
                      r"glitch\.me|herokuapp\.com|vercel\.app|netlify\.app|workers\.dev|pages\.dev|github\.io)$", re.IGNORECASE)
PRIVATE_IP = re.compile(r"^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|255\.)")


def _host(url: str) -> str:
    return re.sub(r"^https?://", "", url).split("/", 1)[0].split(":", 1)[0].lower()


def infrastructure(texts: Iterable[str]) -> Set[str]:
    """Network indicators in the code that triggered a rule."""
    found: Set[str] = set()
    for text in texts:
        for url in URL.findall(text):
            host = _host(url)
            if COMMON.search(host):
                continue
            # Webhook / bot URLs identify an actor down to the path.
            if re.search(r"discord(app)?\.com/api/webhooks/\d+|api\.telegram\.org/bot\d+|webhook\.site/[0-9a-f-]{8,}|pipedream\.net|oast\.", url, re.I):
                found.add("url:" + re.sub(r"(/api/webhooks/\d+)/[\w-]+", r"\1", url.split("?", 1)[0]).lower()[:200])
            if not PLATFORM.search(host) and not GENERIC_HOST.search(host) and "." in host.strip("."):
                found.add("host:" + host)
        for ip in IPV4.findall(text):
            if not PRIVATE_IP.match(ip) and all(int(part) < 256 for part in ip.split(".")):
                found.add("ip:" + ip)
        domains = [match.group(1).lower() for match in DOMAIN.finditer(text)]
        if len(set(domains)) > MAX_DOMAINS_PER_FILE:
            continue  # a domain list (TLDs, disposable mail) is data, not infrastructure
        for domain in domains:
            if not COMMON.search(domain) and not PLATFORM.search(domain) and not GENERIC_HOST.search(domain):
                found.add("host:" + domain)
    return found


def simhash(text: str) -> int:
    """64-bit simhash over normalised 4-token shingles."""
    tokens = re.findall(r"[A-Za-z_$][\w$]*|\d+|[^\s\w]", re.sub(r"(['\"`]).*?\1", "S", text))
    if len(tokens) < 8:
        return 0
    weights = [0] * 64
    for index in range(len(tokens) - 3):
        digest = int.from_bytes(hashlib.blake2b(" ".join(tokens[index:index + 4]).encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if digest >> bit & 1 else -1
    return sum(1 << bit for bit in range(64) if weights[bit] > 0)


def fingerprints(*, evidence_texts: Iterable[str], code_text: str = "", manifest: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fingerprints for one flagged package."""
    texts = list(evidence_texts)
    publisher = set()
    for value in json.dumps(manifest or {}).split('"'):
        publisher |= {email.lower() for email in EMAIL.findall(value) if not COMMON.search(email.split("@", 1)[1])}
    code = simhash(code_text) if code_text else 0
    return {"infra": sorted(infrastructure(texts)), "code": f"{code:016x}" if code else "", "publisher": sorted(publisher)}


SUSPICIOUS_FLAGS = ("exfil_service", "discord_webhook", "telegram_bot", "raw_ip_url", "credential_files", "browser_data",
                    "crypto_wallet", "download_tool", "js_obfuscator", "runner_memory", "prompt_injection", "system_info", "dns_lookup")


def from_members(members: List[Tuple[str, bytes]], *, manifest: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fingerprints from a package: only files showing suspicious behaviour feed infra and code."""
    from secopsai.package_features import COMPILED, MAX_TEXT_BYTES, _is_text_path

    suspicious: List[str] = []
    for path, data in members:
        if not _is_text_path(path) or path.lower().endswith((".md", ".d.ts", ".map")):
            continue
        text = data[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
        if any(COMPILED[flag].search(text) for flag in SUSPICIOUS_FLAGS):
            suspicious.append(text[:262144])
        if len(suspicious) >= 10:
            break
    if manifest is None:
        raw = next((data for path, data in members if path.split("/", 1)[-1] == "package.json" or path.endswith("/PKG-INFO")), b"")
        manifest = {"raw": raw[:65536].decode("utf-8", errors="ignore")}
    return fingerprints(evidence_texts=suspicious, code_text=max(suspicious, key=len) if suspicious else "", manifest=manifest)


# ------------------------------------------------------------------ storage
def _ensure(connection: Any) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS actor_fingerprints (
            artifact_key TEXT PRIMARY KEY,
            fingerprints_json TEXT NOT NULL,
            seen_at TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS actor_campaigns (
            campaign_id TEXT PRIMARY KEY,
            members_json TEXT NOT NULL,
            indicators_json TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
    )


def record(artifact_key: str, prints: Dict[str, Any], *, seen_at: str, db_path: Optional[str] = None) -> None:
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        connection.execute(
            "INSERT INTO actor_fingerprints (artifact_key, fingerprints_json, seen_at) VALUES (?, ?, ?) "
            "ON CONFLICT(artifact_key) DO UPDATE SET fingerprints_json = excluded.fingerprints_json",
            (artifact_key, json.dumps(prints, sort_keys=True), seen_at),
        )
        connection.commit()


# --------------------------------------------------------------- clustering
def _clean_prints(prints: Dict[str, Any]) -> Dict[str, Any]:
    """Apply the current indicator filters (fingerprints may predate them)."""
    infra = []
    for value in prints.get("infra") or []:
        if value.startswith("host:"):
            host = value[5:]
            if COMMON.search(host) or PLATFORM.search(host) or GENERIC_HOST.search(host) or host.endswith(".sh") or host.startswith(("-", ".")) or host in {"system.io", "system.net"}:
                continue
        infra.append(value)
    if sum(value.startswith("host:") for value in infra) > MAX_DOMAINS_PER_FILE:
        infra = [value for value in infra if not value.startswith("host:")]  # a domain list, not infrastructure
    return {**prints, "infra": infra}


def cluster(items: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Connected groups of artifacts sharing a fingerprint; each with the indicators that link it."""
    items = {key: _clean_prints(prints) for key, prints in items.items()}
    parent = {key: key for key in items}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(a: str, b: str) -> None:
        root_a, root_b = find(a), find(b)
        if root_a != root_b:
            parent[max(root_a, root_b)] = min(root_a, root_b)

    index: Dict[str, List[str]] = {}
    for key, prints in items.items():
        for value in list(prints.get("infra") or []) + [f"publisher:{p}" for p in prints.get("publisher") or []]:
            index.setdefault(value, []).append(key)
    # Evidence per pair. A pair links on one strong indicator (exact webhook/bot
    # URL, IP, publisher email), two shared hosts, or a host plus similar code:
    # single weak links would otherwise chain unrelated actors together.
    shared: Dict[Tuple[str, str], Set[str]] = {}
    for value, keys in index.items():
        if 2 <= len(keys) <= (MAX_SHARED_HOST if value.startswith("host:") else MAX_SHARED):
            ordered = sorted(keys)
            for i, key_a in enumerate(ordered):
                for key_b in ordered[i + 1:]:
                    shared.setdefault((key_a, key_b), set()).add(value)
    # Similar code links only within small groups: code shared by more than
    # MAX_SHARED packages is a public template, not one actor.
    code_parent: Dict[str, str] = {}

    def code_find(key: str) -> str:
        while code_parent.setdefault(key, key) != key:
            key = code_parent[key]
        return key

    codes = [(key, int(prints["code"], 16)) for key, prints in items.items() if prints.get("code")]
    buckets: Dict[int, List[Tuple[str, int]]] = {}
    for key, code in codes:
        for band in range(4):  # 4 bands of 16 bits: near-duplicates share at least one band
            buckets.setdefault(band << 16 | (code >> (band * 16)) & 0xFFFF, []).append((key, code))
    similar: Set[Tuple[str, str]] = set()
    for bucket in buckets.values():
        if len(bucket) > MAX_SHARED:
            continue
        for i, (key_a, code_a) in enumerate(bucket):
            for key_b, code_b in bucket[i + 1:]:
                if key_a != key_b and bin(code_a ^ code_b).count("1") <= CODE_DISTANCE:
                    similar.add(tuple(sorted((key_a, key_b))))
                    root_a, root_b = code_find(key_a), code_find(key_b)
                    if root_a != root_b:
                        code_parent[max(root_a, root_b)] = min(root_a, root_b)
    code_groups: Dict[str, List[str]] = {}
    for key in list(code_parent):
        code_groups.setdefault(code_find(key), []).append(key)
    template = {key for members in code_groups.values() if len(members) > MAX_SHARED for key in members}
    host_count = {key: sum(value.startswith("host:") for value in prints.get("infra") or []) for key, prints in items.items()}
    links: Dict[Tuple[str, str], Set[str]] = {}
    for pair in set(shared) | similar:
        values = set(shared.get(pair, set()))
        code_link = pair in similar and not (set(pair) & template)
        strong = any(not value.startswith("host:") for value in values)
        hosts = sum(value.startswith("host:") for value in values)
        # A rare host shared by two focused packages (few suspicious hosts each)
        # is strong; in packages full of URLs it needs corroboration.
        focused = all(host_count.get(key, 0) <= FOCUSED_HOSTS for key in pair)
        if strong or hosts >= 2 or (hosts >= 1 and (code_link or focused)) or (code_link and not values):
            union(*pair)
            links[pair] = values | ({"code:similar"} if code_link else set())
    groups: Dict[str, List[str]] = {}
    for key in items:
        groups.setdefault(find(key), []).append(key)
    out = []
    for members in groups.values():
        if len(members) < 2:
            continue
        shared = sorted({value for (a, b), values in links.items() if a in members for value in values})
        campaign_id = "CMP-" + hashlib.sha256(min(members).encode()).hexdigest()[:10].upper()
        out.append({"campaign_id": campaign_id, "members": sorted(members), "indicators": shared[:30]})
    return sorted(out, key=lambda item: -len(item["members"]))


def link_campaigns(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Recompute campaigns; raise an alert when one gains members."""
    import secrets

    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        rows = connection.execute("SELECT artifact_key, fingerprints_json, seen_at FROM actor_fingerprints").fetchall()
        seen = {row["artifact_key"]: row["seen_at"] for row in rows}
        campaigns = cluster({row["artifact_key"]: json.loads(row["fingerprints_json"]) for row in rows})
        grown = []
        for campaign in campaigns:
            previous = connection.execute("SELECT members_json FROM actor_campaigns WHERE campaign_id = ?", (campaign["campaign_id"],)).fetchone()
            before = set(json.loads(previous["members_json"])) if previous else set()
            added = sorted(set(campaign["members"]) - before)
            dates = sorted(seen[key] for key in campaign["members"])
            connection.execute(
                """INSERT INTO actor_campaigns (campaign_id, members_json, indicators_json, first_seen, last_seen, updated_at) VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(campaign_id) DO UPDATE SET members_json = excluded.members_json, indicators_json = excluded.indicators_json,
                   last_seen = excluded.last_seen, updated_at = excluded.updated_at""",
                (campaign["campaign_id"], json.dumps(campaign["members"]), json.dumps(campaign["indicators"]), dates[0], dates[-1], now),
            )
            if added:
                grown.append(campaign["campaign_id"])
                evidence = {**campaign, "added": added, "first_seen": dates[0]}
                connection.execute(
                    """INSERT INTO research_alerts (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key,
                           reason, evidence_json, status, owner, created_at, updated_at)
                       VALUES (?, 'campaign_activity', 'medium', NULL, ?, NULL, ?, ?, ?, 'open', '', ?, ?)
                       ON CONFLICT(dedupe_key) DO UPDATE SET reason = excluded.reason, evidence_json = excluded.evidence_json,
                       updated_at = excluded.updated_at, status = 'open'""",
                    (f"RAL-{secrets.token_hex(8).upper()}", campaign["campaign_id"], f"campaign:{campaign['campaign_id']}",
                     f"Campaign {campaign['campaign_id']}: {len(campaign['members'])} packages ({len(added)} new) linked by "
                     + ", ".join(campaign["indicators"][:3]), json.dumps(evidence, sort_keys=True), now, now),
                )
        # Campaigns that no longer exist under the current linking rules (for
        # example over-merged by indicators since filtered) are removed and
        # their alerts resolved.
        current = {campaign["campaign_id"] for campaign in campaigns}
        stale = [row["campaign_id"] for row in connection.execute("SELECT campaign_id FROM actor_campaigns").fetchall() if row["campaign_id"] not in current]
        for campaign_id in stale:
            connection.execute("DELETE FROM actor_campaigns WHERE campaign_id = ?", (campaign_id,))
            connection.execute("UPDATE research_alerts SET status = 'resolved', owner = 'campaign-relink', updated_at = ? WHERE alert_type = 'campaign_activity' AND campaign_id = ? AND status = 'open'",
                               (now, campaign_id))
        connection.commit()
    return {"campaigns": len(campaigns), "grown": grown, "retired": len(stale), "largest": [len(c["members"]) for c in campaigns[:5]]}


def campaign_of(artifact_key: str, *, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        for row in connection.execute("SELECT * FROM actor_campaigns").fetchall():
            members = json.loads(row["members_json"])
            if artifact_key in members:
                return {"campaign_id": row["campaign_id"], "members": len(members), "indicators": json.loads(row["indicators_json"])[:10],
                        "first_seen": row["first_seen"]}
    return None
