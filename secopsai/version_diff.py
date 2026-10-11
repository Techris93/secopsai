"""Version-diff detection: what a release added compared with the previous one.

Hijacked releases of trusted packages are best seen as changes: an install
script that was not there before, a new outbound endpoint, new reads of
credential files.  Each behaviour on its own may be ordinary for that
package; appearing in a patch release is not.

``new_flags`` returns the risky behaviour flags present in a release but not
in the version published before it.  They are added to the flag set as
``new:<flag>`` so behaviour rules can require them.  The previous version is
only fetched when the release already shows a risky flag, which bounds the
extra downloads.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from secopsai import package_features
from secopsai.research_intake import SafeFetcher

RISKY = {
    "install_hook", "install_hook_inline_command", "setup_py_cmdclass", "setup_py_side_effects", "build_rs_side_effects",
    "exfil_service", "discord_webhook", "telegram_bot", "credential_files", "browser_data", "crypto_wallet",
    "js_obfuscator", "runner_memory", "raw_ip_url", "download_tool", "dynamic_eval", "long_base64", "native_binary",
    "prompt_injection", "persistence", "child_process", "py_subprocess", "http_send", "system_info", "dns_lookup",
}
# Only these trigger fetching the previous version (cheap pre-check).
TRIGGERS = RISKY - {"child_process", "py_subprocess", "http_send", "system_info", "dns_lookup", "dynamic_eval"}
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
# Packages with huge version histories (tens of MB of metadata) are skipped:
# fetching that for every flagged release would dominate a worker cycle.
METADATA_LIMIT = 8 * 1024 * 1024
PRERELEASE = re.compile(r"[-+]|(a|b|rc|dev|alpha|beta)\d*$", re.IGNORECASE)


def previous_version(fetcher: SafeFetcher, ecosystem: str, package: str, version: str, before: str = "") -> str:
    """The stable version published most recently before ``version`` ('' if none).

    ``before`` (an ISO date) stands in when the registry no longer lists the
    version itself, as for removed malicious releases.
    """
    if ecosystem == "npm":
        _u, _h, body = fetcher.get("https://registry.npmjs.org/" + package.replace("/", "%2F"), allowed_hosts=("registry.npmjs.org",), max_bytes=METADATA_LIMIT)
        times = {key: value for key, value in (json.loads(body).get("time") or {}).items() if key not in {"created", "modified"}}
    elif ecosystem == "pypi":
        _u, _h, body = fetcher.get(f"https://pypi.org/pypi/{package}/json", allowed_hosts=("pypi.org",), max_bytes=METADATA_LIMIT)
        times = {}
        for name, files in (json.loads(body).get("releases") or {}).items():
            stamps = [item.get("upload_time_iso_8601") for item in files or [] if item.get("upload_time_iso_8601")]
            if stamps:
                times[name] = min(stamps)
    else:
        return ""
    published = times.get(version) or before
    if not published:
        return ""
    earlier = sorted((stamp, name) for name, stamp in times.items() if stamp < published and not PRERELEASE.search(name))
    return earlier[-1][1] if earlier else ""


def fetch_members(fetcher: SafeFetcher, ecosystem: str, package: str, version: str) -> List[Tuple[str, bytes]]:
    from secopsai.artifact_fleet import _safe_archive_files
    from secopsai.research_content_funnel import _resolve_npm, resolve_artifact

    url, hosts, filename = _resolve_npm(fetcher, package, version) if ecosystem == "npm" else resolve_artifact(fetcher, ecosystem, package, version)
    _u, _h, raw = fetcher.get(url, allowed_hosts=hosts, max_bytes=MAX_ARTIFACT_BYTES)
    members: List[Tuple[str, bytes]] = []
    with tempfile.TemporaryDirectory(prefix="secopsai-diff-") as tmp:
        path = Path(tmp) / Path(filename).name
        path.write_bytes(raw)
        _safe_archive_files(path, members)
    return members


def new_flags(current: Iterable[str], previous: Iterable[str]) -> List[str]:
    return sorted((set(current) - set(previous)) & RISKY)


def with_diff(fetcher: SafeFetcher, ecosystem: str, package: str, version: str, flags: List[str], *, before: str = "") -> Tuple[List[str], Dict[str, object]]:
    """Flags plus ``new:<flag>`` entries for behaviour the previous version lacked."""
    if ecosystem not in {"npm", "pypi"} or not (set(flags) & TRIGGERS):
        return flags, {}
    try:
        previous = previous_version(fetcher, ecosystem, package, version, before)
        if not previous:
            return flags, {"previous_version": "", "note": "first release"}
        previous_flags = package_features.profile(fetch_members(fetcher, ecosystem, package, previous), version=previous)
    except Exception as exc:  # the diff is extra signal; never fail the scan
        return flags, {"error": str(exc)[:200]}
    added = new_flags(flags, previous_flags)
    return sorted(set(flags) | {f"new:{flag}" for flag in added}), {"previous_version": previous, "new_flags": added}
