"""Behaviour flags for a package's files.

Flags describe what a package's code does (install hooks, reading
credentials, talking to webhooks, dynamic evaluation of encoded data...)
without keeping any of the code.  The recall benchmark compares how often
each flag appears in missed malware against clean popular packages, which
shows where new detection rules will pay off; the same flags can feed the
funnel's score.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import zlib
import re
from pathlib import PurePosixPath
from typing import Dict, Iterable, List, Optional, Set, Tuple

MAX_TEXT_BYTES = 1024 * 1024
TINY_CODE_BYTES = 50_000
INSTALL_NETWORK_FLAGS = ("exfil_service", "discord_webhook", "telegram_bot", "raw_ip_url", "download_tool", "http_send")
TEXT_SUFFIXES = {".rs", ".js", ".cjs", ".mjs", ".ts", ".py", ".pyw", ".json", ".sh", ".bat", ".cmd", ".ps1", ".cfg", ".toml", ".txt", ".yml", ".yaml", ""}
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")

# flag -> pattern over the text of code files (case-insensitive).
PATTERNS: Dict[str, str] = {
    "child_process": r"child_process|\bexecSync\b|\bspawnSync\b",
    "py_subprocess": r"\bsubprocess\.|\bos\.system\s*\(|\bos\.popen\s*\(",
    "env_read": r"process\.env\b|os\.environ\b|os\.getenv\s*\(",
    "home_dir": r"os\.homedir\s*\(|expanduser\s*\(|Path\.home\s*\(|\$HOME\b|%USERPROFILE%",
    "credential_files": r"\.npmrc|\.pypirc|\.ssh/|id_rsa|\.aws/credentials|\.git-credentials|\.bash_history|\.docker/config\.json|\.kube/config",
    "browser_data": r"Login Data|Local State|\bCookies\b|Local Storage/leveldb",
    # Not `privateKey`: auth libraries (google-auth-library) use it for service accounts.
    "crypto_wallet": r"metamask|exodus|electrum|\bmnemonic\b|seed phrase|solana|wallet\.dat",
    # Joined URL, or host and path built separately (common in stealers).
    "discord_webhook": r"discord(app)?\.com/api/webhooks|discord(app)?\.com['\"`].{0,200}/api/webhooks",
    "telegram_bot": r"api\.telegram\.org",
    # Service domains, word-bounded: identifiers such as `transfer.shutdown`
    # and bare tool names (`ngrok` in a CLI list) do not count.
    "exfil_service": r"\b(pastebin\.com|transfer\.sh|webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok(-free)?\.(io|app|dev)|interactsh\.com|oast\.(fun|pro|site|me|live|online)|burpcollaborator\.net|canarytokens\.(com|org))\b",
    # Public addresses only: loopback and private ranges (benchmarks, local dev servers) are not C2.
    "raw_ip_url": r"https?://(?!(?:127|10|0)\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    "dns_lookup": r"dns\.(lookup|resolve\w*)\s*\(|gethostbyname|\bnslookup\b|dns\.resolver",
    "http_send": r"https?\.request\s*\(|axios\.post|requests\.post|urlopen\s*\(|method\s*:\s*['\"]POST|XMLHttpRequest",
    "dynamic_eval": r"\beval\s*\(|new Function\s*\(|\bexec\s*\(\s*(base64|codecs|zlib|bytes|compile|__import__|.{0,40}decode)",
    "base64_decode": r"atob\s*\(|Buffer\.from\([^)]{0,200}['\"]base64['\"]|b64decode\s*\(",
    "long_base64": r"[A-Za-z0-9+/]{300,}={0,2}",
    "hex_blob": r"(\\x[0-9a-fA-F]{2}){60,}",
    "js_obfuscator": r"_0x[0-9a-f]{4,6}\b.{0,200}_0x[0-9a-f]{4,6}\b",
    "system_info": r"os\.hostname\s*\(|os\.userInfo\s*\(|os\.networkInterfaces|platform\.node\s*\(|getpass\.getuser|socket\.gethostname|\bwhoami\b",
    "download_tool": r"\bcurl\s+-|\bwget\s+|Invoke-WebRequest|urlretrieve\s*\(|DownloadFile|Command::new\(\s*\"(curl|wget)\"",
    "chmod_exec": r"chmod\s+\+?[0-7x]+|os\.chmod\s*\(|fs\.chmodSync",
    "persistence": r"crontab|LaunchAgents|CurrentVersion\\\\Run|\.bashrc|\.zshrc|systemctl\s+enable|schtasks",
    # tj-actions/changed-files (2025): read the runner process memory to dump secrets.
    # Process memory reads, not mentions of the runner (security tools such as
    # harden-runner legitimately name Runner.Worker).
    "runner_memory": r"/proc/[^\s'\"]{0,40}/mem\b|memdump\.py|isSecret\\\":true",
    # MCP tool poisoning: instructions to the model hidden in tool descriptions.
    # Concealment is the tell: "ignore previous instructions" is mostly found in
    # injection *defences* (scanners, their demos and tests), so it is not used.
    "prompt_injection": r"<IMPORTANT>|do not (tell|mention|reveal|inform) the user|without (telling|informing|notifying) the user|the user (must|should) not (know|see)|do not mention (that|this) (you|to)",
    "anti_analysis": r"\bisVM\b|virtualbox|vmware|sandbox|debugger|process\.exit\(\)\s*;?\s*}\s*else",
}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?)/|(^|/)test_[^/]*\.py$|_test\.py$|\.(test|spec)\.[cm]?[jt]s$")
def _actor_infrastructure_pattern() -> str:
    """Known actor domains/IPs from rules/watchlists/actor-infrastructure.txt (subdomains included)."""
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "rules" / "watchlists" / "actor-infrastructure.txt"
    entries = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.split("#", 1)[0].strip().lower()
            if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(\.\d{1,3}){3}", value):
                entries.append(re.escape(value))
    return r"(?<![a-z0-9-])(?:[a-z0-9-]+\.)*(?:" + "|".join(entries) + r")\b" if entries else r"(?!x)x"


PATTERNS["known_actor_infra"] = _actor_infrastructure_pattern()
COMPILED = {name: re.compile(pattern, re.IGNORECASE | re.DOTALL) for name, pattern in PATTERNS.items()}


def _is_text_path(path: str) -> bool:
    return PurePosixPath(path.lower()).suffix in TEXT_SUFFIXES


def profile(members: Iterable[Tuple[str, bytes]], *, version: str = "") -> List[str]:
    """Sorted behaviour flags for one package's (path, bytes) members."""
    flags: Set[str] = set()
    files = list(members)
    manifest_paths = [path for path, _ in files if PurePosixPath(path.lower()).name in {"package.json", "setup.py", "build.rs", "pyproject.toml"}]
    root_depth = min((path.count("/") for path in manifest_paths), default=1)
    code_files = 0
    code_bytes = 0
    for path, data in files:
        lowered = path.lower()
        name = PurePosixPath(lowered).name
        if data[:2] == b"MZ" or data[:4] == b"\x7fELF" or data[:4] in {b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"} or lowered.endswith((".exe", ".dll", ".so", ".dylib")):
            flags.add("native_binary")
            continue
        if lowered.endswith(".d.ts"):
            continue  # type declarations describe APIs; they do not run
        if not _is_text_path(path) or lowered.endswith((".md", ".txt")) and name not in {"requirements.txt"}:
            continue
        text = data[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
        if name == "package.json" and lowered.count("/") == root_depth:
            try:
                manifest = json.loads(text)
            except ValueError:
                manifest = {}
            scripts = manifest.get("scripts") if isinstance(manifest, dict) and isinstance(manifest.get("scripts"), dict) else {}
            hooks = {hook: str(scripts[hook]) for hook in INSTALL_HOOKS if hook in scripts}
            if hooks:
                flags.add("install_hook")
                if any(re.search(r"\bnode\s+-e|curl|wget|\bsh\s|bash|powershell|https?://", command, re.I) for command in hooks.values()):
                    flags.add("install_hook_inline_command")
            continue
        if name == "setup.py":
            flags.add("setup_py")
            if re.search(r"cmdclass|class\s+\w+\s*\(\s*(install|develop|egg_info)\b", text):
                flags.add("setup_py_cmdclass")
            if re.search(r"subprocess|os\.system|urlopen|requests\.|socket\.|exec\s*\(|eval\s*\(|b64decode", text):
                flags.add("setup_py_side_effects")
            if any(COMPILED[flag].search(text) for flag in ("exfil_service", "discord_webhook", "telegram_bot", "raw_ip_url")):
                flags.add("setup_py_exfil")
        if name == "build.rs" and lowered.count("/") == root_depth:
            flags.add("build_rs")
            if re.search(r"Command::new|std::net|TcpStream|reqwest|ureq|curl|std::env::var|include_bytes!", text):
                flags.add("build_rs_side_effects")
            # Network behaviour inside build.rs itself (not elsewhere in the crate).
            if any(COMPILED[flag].search(text) for flag in INSTALL_NETWORK_FLAGS):
                flags.add("build_rs_network")
        if lowered.endswith(".json"):
            continue
        code_files += 1
        code_bytes += len(data)
        in_tests = bool(TEST_PATH.search(lowered))
        for flag, pattern in COMPILED.items():
            # Injection strings in tests are defences being tested, not tool descriptions.
            if flag == "prompt_injection" and in_tests:
                continue
            if flag not in flags and pattern.search(text):
                flags.add(flag)
    # Few files AND little code: bundlers pack whole CLIs into one large
    # dist/index.js (backscan: 69 of 79 recon false positives), while
    # throwaway malicious packages are a few kilobytes.
    if code_files <= 2 and code_bytes < TINY_CODE_BYTES:
        flags.add("tiny_package")
    major = re.match(r"(\d+)", version or "")
    # Dependency-confusion packages publish 99.x / 100.x to win resolution.
    # Calendar versions (2026.9.0) and long-lived majors (setuptools 84) are not.
    if major and 90 <= int(major.group(1)) < 1990:
        flags.add("inflated_version")
    return sorted(flags)


SMALL_PACKAGE = ("tiny_package", "install_hook_inline_command")

# Flag sets of legitimate packages that rules must not fire on: each one was
# a real false positive (pnpm/vitest-style tooling, platform-checking
# setup.py, injection-defence libraries). The regression tests and the rule
# lab both enforce them.
KNOWN_BENIGN_SHAPES: Tuple[Tuple[str, ...], ...] = (
    ("system_info", "http_send", "home_dir", "install_hook", "child_process", "env_read"),  # pnpm, vitest
    ("child_process", "env_read", "home_dir", "system_info"),  # node-gyp
    ("setup_py_side_effects", "system_info", "http_send", "home_dir", "env_read", "download_tool"),  # psutil, coverage
    ("system_info", "http_send", "home_dir", "child_process", "download_tool", "env_read"),  # bundled CLIs (backscan: @lotics/cli, @pollinations/cli)
    ("inflated_version", "child_process", "chmod_exec", "download_tool", "env_read", "install_hook"),  # npm chromedriver 155.0.0
    ("inflated_version", "chmod_exec", "env_read", "http_send", "py_subprocess", "setup_py", "setup_py_cmdclass", "setup_py_side_effects"),  # PyPI chromedriver-binary 157.x
)

# Behaviour rules: combinations of flags that are common in missed malware and
# rare in popular clean packages (recall benchmark, 2026-10-10).  Each entry:
# (rule id, ecosystems, groups — every group needs at least one flag, score).
# Editor extensions legitimately spawn processes and download language
# servers, so only the exfiltration rules apply to Open VSX until it has its
# own false-positive baseline.
BEHAVIOUR_RULES: Tuple[Tuple[str, Tuple[str, ...], Tuple[Tuple[str, ...], ...], int], ...] = (
    # Package managers and test runners legitimately do recon + network, so
    # the npm recon rules also need the shape of a throwaway package.
    ("BEH_RECON_AND_SEND", ("npm",), (("system_info",), ("http_send",), SMALL_PACKAGE), 60),
    ("BEH_HOME_DIR_RECON", ("npm",), (("home_dir",), ("system_info",), SMALL_PACKAGE), 50),
    ("BEH_EXFIL_SERVICE", ("npm", "pypi", "open-vsx", "vscode-marketplace", "crates", "github-actions", "mcp-registry"), (("exfil_service",), ("http_send", "system_info", "dns_lookup")), 70),
    # npm needs the throwaway shape: chromedriver-style packages track browser
    # versions (155.x) and download binaries. PyPI dependency confusion is
    # rarely "tiny", and calendar versions are already excluded there.
    # PyPI: a plain download is not enough (chromedriver-binary 157.x fetches
    # its driver); dependency-confusion payloads beacon recon or use DNS/exfil.
    ("BEH_DEPENDENCY_CONFUSION", ("pypi",), (("inflated_version",), ("system_info", "dns_lookup", "exfil_service")), 70),
    ("BEH_DEPENDENCY_CONFUSION_NPM", ("npm",), (("inflated_version",), ("system_info", "http_send", "dns_lookup", "exfil_service"), SMALL_PACKAGE), 70),
    ("BEH_SHELL_DOWNLOAD", ("npm",), (("child_process",), ("download_tool",), SMALL_PACKAGE), 60),
    ("BEH_DISCORD_WEBHOOK", ("npm", "pypi", "open-vsx", "vscode-marketplace", "crates", "github-actions", "mcp-registry"),
     (("discord_webhook",), ("system_info", "home_dir", "credential_files", "browser_data", "crypto_wallet", "http_send")), 60),
    # build.rs runs on every `cargo build`; legitimate ones compile C code,
    # so only network/exfil behaviour in it counts.
    ("BEH_BUILD_RS_BEACON", ("crates",), (("build_rs_side_effects",), ("build_rs_network",)), 60),
    # Agent tooling (hooks, skills) legitimately tells models what not to say;
    # poisoning pairs concealment with credential files or an exfil endpoint.
    ("BEH_MCP_TOOL_POISONING", ("mcp-registry", "npm", "pypi"), (("prompt_injection",), ("credential_files", "exfil_service")), 70),
    ("BEH_ACTIONS_RUNNER_MEMORY", ("github-actions",), (("runner_memory",),), 80),
    # setup.py commonly checks the platform; only exfil endpoints count.
    # The exfil endpoint must be in setup.py itself (it runs at install).
    ("BEH_SETUP_PY_BEACON", ("pypi",), (("setup_py_side_effects",), ("setup_py_exfil",)), 60),
    # From rule lab issue #110 (benchmark run 38089864099), chosen on pre-2026
    # samples; held-out 2026 gains in brackets.
    ("BEH_JS_OBFUSCATOR", ("npm",), (("js_obfuscator",),), 60),  # +35 (+43 held-out), 0 popular flagged
    # Throwaway shape required: chromedriver and friends track browser versions (155.x).
    ("BEH_VERSION_CONFUSION", ("npm",), (("inflated_version",), SMALL_PACKAGE), 60),  # 84 of 88 such misses are throwaway-shaped
    ("BEH_SHELL_WALLET_SEND", ("npm",), (("child_process",), ("crypto_wallet",), ("http_send",)), 60),  # +37 (+15), 1 popular flagged
    # Version diff (secopsai/version_diff.py): behaviour the previous release lacked.
    ("BEH_DIFF_NEW_INSTALL_HOOK_NETWORK", ("npm", "pypi"),
     # Both the hook and the network behaviour must be new: packages change
     # build systems (multidict 7.1.0 gained a setup.py cmdclass) without
     # starting to phone home.
     (("new:install_hook", "new:install_hook_inline_command", "new:setup_py_cmdclass", "new:setup_py_side_effects"),
      ("new:http_send", "new:exfil_service", "new:discord_webhook", "new:raw_ip_url", "new:telegram_bot", "new:dns_lookup")), 80),
    ("BEH_DIFF_NEW_EXFIL", ("npm", "pypi"), (("new:exfil_service", "new:discord_webhook", "new:telegram_bot"),), 70),
    ("BEH_DIFF_NEW_SECRETS_AND_SEND", ("npm", "pypi"),
     (("new:credential_files", "new:browser_data", "new:crypto_wallet"), ("http_send", "exfil_service", "discord_webhook", "dns_lookup")), 70),
    ("BEH_DIFF_NEW_OBFUSCATION", ("npm", "pypi"), (("new:js_obfuscator", "new:runner_memory"),), 60),
    # Infrastructure from investigated cases (rules/watchlists/actor-infrastructure.txt).
    ("BEH_KNOWN_ACTOR_INFRA", ("npm", "pypi", "open-vsx", "vscode-marketplace", "crates", "github-actions", "mcp-registry"), (("known_actor_infra",),), 80),
)


def behaviour_findings(flags: Iterable[str], ecosystem: str) -> List[Dict[str, object]]:
    present = set(flags)
    findings: List[Dict[str, object]] = []
    for rule_id, ecosystems, groups, score in BEHAVIOUR_RULES:
        if ecosystem.lower() in ecosystems and all(present & set(group) for group in groups):
            matched = sorted(flag for group in groups for flag in group if flag in present)
            findings.append({"rule_id": f"BEHAVIOUR:{rule_id}", "severity": "high" if score >= 60 else "medium", "score": score,
                             "matched_indicator": "behaviour: " + " + ".join(matched), "safe_context": "", "file_path": "(package)"})
    return findings


# Flags computed from a specific file rather than a pattern: point at that file.
FILE_FLAGS = {
    "build_rs": "build.rs", "build_rs_side_effects": "build.rs", "build_rs_network": "build.rs",
    "setup_py": "setup.py", "setup_py_cmdclass": "setup.py", "setup_py_side_effects": "setup.py", "setup_py_exfil": "setup.py",
    "install_hook": "package.json", "install_hook_inline_command": "package.json",
}


def _clean_window(text: str) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", ".", text)


def flag_evidence(members: Iterable[Tuple[str, bytes]], flag: str, *, window: int = 360) -> Dict[str, object]:
    """Where a flag matched: file path, line number and an inert text window around the first match."""
    flag = flag.removeprefix("new:")
    members = list(members)
    if flag in FILE_FLAGS:
        target = FILE_FLAGS[flag]
        depth = min((path.count("/") for path, _ in members if PurePosixPath(path.lower()).name == target), default=-1)
        for path, data in members:
            if PurePosixPath(path.lower()).name == target and path.count("/") == depth:
                return {"flag": flag, "file_path": path[:300], "line": 1, "context": _clean_window(data[:1200].decode("utf-8", errors="ignore"))}
        return {}
    pattern = COMPILED.get(flag)
    if pattern is None:
        return {}
    for path, data in members:
        lowered = path.lower()
        if lowered.endswith(".d.ts") or not _is_text_path(path) or (flag == "prompt_injection" and TEST_PATH.search(lowered)):
            continue
        text = data[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
        match = pattern.search(text)
        if match:
            start = max(0, match.start() - window // 2)
            snippet = _clean_window(text[start:match.end() + window // 2])
            return {"flag": flag, "file_path": path[:300], "line": text.count("\n", 0, match.start()) + 1, "context": snippet[:window + 120]}
    return {}


def install_time_files(members: Iterable[Tuple[str, bytes]], *, per_file: int = 12000, total: int = 24000) -> List[Dict[str, object]]:
    """Full text of what runs at install or build time, for triage: package.json
    scripts and the files they call, setup.py, build.rs. Bounded in size."""
    members = list(members)
    by_path = {path: data for path, data in members}
    wanted: List[str] = []
    # The package root is the shallowest folder holding a manifest; archives
    # nest it at different depths (npm: package/, sdists: name-1.0/, sample
    # archives one level deeper still).
    manifests = [path for path, _ in members if PurePosixPath(path.lower()).name in {"package.json", "setup.py", "build.rs", "pyproject.toml"}]
    root_depth = min((path.count("/") for path in manifests), default=1)
    for path, data in members:
        name = PurePosixPath(path.lower()).name
        if path.count("/") != root_depth:
            continue
        if name in {"setup.py", "build.rs"}:
            wanted.append(path)
        elif name == "package.json":
            try:
                scripts = (json.loads(data.decode("utf-8", errors="ignore")).get("scripts") or {})
            except ValueError:
                scripts = {}
            hooks = {hook: str(scripts[hook]) for hook in INSTALL_HOOKS if hook in scripts}
            if hooks:
                wanted.append(path)
                root = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
                for command in hooks.values():
                    for token in re.findall(r"[\w./-]+\.(?:js|cjs|mjs|sh|py)", command):
                        candidate = root + token.lstrip("./")
                        if candidate in by_path:
                            wanted.append(candidate)
    out: List[Dict[str, object]] = []
    budget = total
    for path in dict.fromkeys(wanted):
        if budget <= 0:
            break
        text = by_path[path].decode("utf-8", errors="ignore")
        if PurePosixPath(path.lower()).name == "package.json":
            try:
                text = json.dumps({"scripts": json.loads(text).get("scripts")}, indent=1)
            except ValueError:
                pass
        clipped = _clean_window(text[:min(per_file, budget)])
        budget -= len(clipped)
        out.append({"path": path[:300], "truncated": len(text) > len(clipped), "content": clipped})
    return out


def combine(scan: Dict[str, object], flags: Iterable[str], ecosystem: str, members: Optional[List[Tuple[str, bytes]]] = None) -> Dict[str, object]:
    """Add behaviour-rule scores to a YARA scan result (sum of distinct rules, capped at 100).

    With ``members``, each behaviour finding carries the code that matched
    each of its flags, so model triage can judge it.
    """
    from secopsai.yara_engine import ALERT, NOTICE, WARNING

    extra = behaviour_findings(flags, ecosystem)
    if not extra:
        return scan
    if members:
        for item in extra:
            evidence = [found for found in (flag_evidence(members, flag) for flag in str(item["matched_indicator"]).removeprefix("behaviour: ").split(" + ")) if found]
            item["evidence"] = evidence
            item["safe_context"] = "\n[...]\n".join(f"{found['flag']} in {found['file_path']} line {found.get('line', '?')}:\n{found['context']}" for found in evidence)[:2400]
            if evidence:
                item["file_path"] = evidence[0]["file_path"]
    score = min(100, int(scan.get("score") or 0) + sum(int(item["score"]) for item in extra))
    level = "alert" if score >= ALERT else "warning" if score >= WARNING else "notice" if score >= NOTICE else "none"
    return {**scan, "score": score, "level": level, "findings": list(scan.get("findings") or []) + extra,
            "rules_matched": sorted(set(scan.get("rules_matched") or []) | {str(item["rule_id"]).split(":", 1)[1] for item in extra})}


# ---------------------------------------------------------------- triage evidence
# What the triage model needs to decide a hit instead of asking for "the full
# file": the flagged files themselves, where every risky flag matched, any
# encoded payloads decoded statically (never executed), and the native binaries
# with what launches them.  All bounded; research_ai_triage.fit_context trims
# further to fit the job size limit.
FLAGGED_FILE_BYTES = 16_000
ENCODED = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{120,}={0,2})(?![A-Za-z0-9+/=])|(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){60,})(?![0-9a-fA-F])")
BINARY_MAGIC = ((b"MZ", "Windows PE"), (b"\x7fELF", "ELF"), (b"\xcf\xfa\xed\xfe", "Mach-O"), (b"\xca\xfe\xba\xbe", "Mach-O universal"),
                (b"\x1f\x8b", "gzip"), (b"PK\x03\x04", "zip"), (b"\x00asm", "WebAssembly"))
RISKY_FLAGS = (
    "install_hook", "install_hook_inline_command", "setup_py_cmdclass", "setup_py_side_effects", "build_rs_side_effects",
    "exfil_service", "discord_webhook", "telegram_bot", "credential_files", "browser_data", "crypto_wallet",
    "js_obfuscator", "runner_memory", "raw_ip_url", "download_tool", "dynamic_eval", "long_base64",
    "prompt_injection", "persistence", "child_process", "py_subprocess", "http_send", "system_info", "dns_lookup", "anti_analysis",
)


def _binary_kind(data: bytes) -> str:
    return next((kind for magic, kind in BINARY_MAGIC if data.startswith(magic)), "")


def _excerpt(text: str, positions: List[int], limit: int) -> Tuple[str, bool]:
    """Whole text when it fits; otherwise the head plus a window around each matched position."""
    if len(text) <= limit:
        return text, False
    positions = sorted({pos for pos in positions if 0 <= pos < len(text)})[:6]
    head = limit // 5 if positions else limit
    parts, cursor = [text[:head]], head
    share = (limit - head) // max(1, len(positions))
    for pos in positions:
        start = max(cursor, pos - share // 3)
        end = min(len(text), max(start, pos - share // 3) + share)
        if end <= cursor:
            continue
        parts.append(f"\n[... {start - cursor} characters omitted ...]\n" + text[start:end])
        cursor = end
    if cursor < len(text):
        parts.append(f"\n[... {len(text) - cursor} characters omitted ...]")
    return "".join(parts), True


def _positions(data: bytes, text: str, finding: Dict[str, object], path: str) -> List[int]:
    """Character positions of a finding's matches in ``text`` (the file decoded with errors ignored)."""
    out = [len(data[:int(offset)].decode("utf-8", errors="ignore")) for offset in finding.get("match_offsets") or [] if isinstance(offset, int)]
    for found in finding.get("evidence") or []:
        if isinstance(found, dict) and found.get("file_path") == path and isinstance(found.get("line"), int):
            line = int(found["line"])
            pos = 0
            for _ in range(line - 1):
                pos = text.find("\n", pos) + 1
                if pos <= 0:
                    break
            out.append(max(0, pos))
    if not out:  # fall back to locating the excerpt's distinctive lines
        for line in str(finding.get("safe_context") or "").replace("\ufffd", "").splitlines():
            line = line.strip()
            if len(line) >= 24 and not line.startswith("[..."):
                pos = text.find(line[len(line) // 3:len(line) // 3 + 40])
                if pos >= 0:
                    out.append(pos)
    return out


def decode_payload(blob: str) -> Optional[Dict[str, object]]:
    """Decode a base64 or hex blob statically and describe what it holds."""
    try:
        raw = bytes.fromhex(blob) if re.fullmatch(r"[0-9a-fA-F]+", blob) and len(blob) % 2 == 0 else base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (ValueError, binascii.Error):
        return None
    layers = []
    for _ in range(2):
        try:
            if raw[:2] == b"\x1f\x8b":
                raw, _l = gzip.decompress(raw)[:200_000], layers.append("gzip")
            elif raw[:1] == b"\x78":
                raw, _l = zlib.decompress(raw)[:200_000], layers.append("zlib")
        except (OSError, zlib.error, EOFError):
            break
    kind = _binary_kind(raw)
    if kind and kind not in {"gzip"}:
        return {"kind": kind, "bytes": len(raw), "layers": layers}
    for encoding in ("utf-8", "utf-16-le"):  # PowerShell -EncodedCommand is UTF-16LE
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text))
        if printable >= 0.9 and len(text.strip()) >= 16:
            return {"kind": "text", "encoding": encoding, "bytes": len(raw), "layers": layers, "text": _clean_window(text[:3000]), "truncated": len(text) > 3000}
    return {"kind": "binary data", "bytes": len(raw), "layers": layers}


def triage_evidence(members: Iterable[Tuple[str, bytes]], findings: Iterable[Dict[str, object]], flags: Iterable[str]) -> Dict[str, object]:
    members = list(members)
    by_path = {path: data for path, data in members}
    findings = list(findings)
    flagged: Dict[str, List[Dict[str, object]]] = {}
    for item in findings:
        path = str(item.get("file_path") or "")
        if path in by_path:
            flagged.setdefault(path, []).append(item)
        for found in item.get("evidence") or []:
            if isinstance(found, dict) and found.get("file_path") in by_path:
                flagged.setdefault(str(found["file_path"]), []).append(item)
    files: List[Dict[str, object]] = []
    for path, related in list(flagged.items())[:6]:
        data = by_path[path]
        kind = _binary_kind(data)
        if kind or b"\x00" in data[:4096]:
            files.append({"path": path[:300], "bytes": len(data), "binary": kind or "binary data"})
            continue
        text = _clean_window(data[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore"))
        positions = [pos for item in related for pos in _positions(data, text, item, path)]
        content, truncated = _excerpt(text, positions, FLAGGED_FILE_BYTES)
        files.append({"path": path[:300], "bytes": len(data), "complete": not truncated, "truncated": truncated,
                      "matched_regions_shown": bool(positions) or not truncated, "content": content})
    install_files = install_time_files(members)
    fully_supplied = {
        str(item.get("path"))
        for item in [*files, *install_files]
        if isinstance(item, dict)
        and item.get("path")
        and item.get("truncated") is not True
        and item.get("complete") is not False
    }
    package_paths = sorted({str(path) for path, _data in members if str(path).strip()})
    missing_files = [path for path in package_paths if path not in fully_supplied]
    bounded_missing_files = [path for path in missing_files if len(path) <= 300][:200]
    flag_set = {flag.removeprefix("new:") for flag in flags}
    locations = [found for found in (flag_evidence(members, flag, window=240) for flag in RISKY_FLAGS if flag in flag_set) if found][:14]
    payloads: List[Dict[str, object]] = []
    seen: Set[str] = set()
    sources = [(item["path"], str(item.get("content") or "")) for item in files] + [(path, by_path[path].decode("utf-8", errors="ignore"))
                                                                                   for path in flagged if path in by_path][:6]
    for path, text in sources:
        for match in ENCODED.finditer(text[:MAX_TEXT_BYTES]):
            blob = match.group(1) or match.group(2)
            if blob[:64] in seen or len(payloads) >= 12:
                continue
            seen.add(blob[:64])
            decoded = decode_payload(blob)
            if decoded and decoded["kind"] != "binary data":  # random-looking bytes say nothing
                payloads.append({"found_in": str(path)[:300], "line": text.count("\n", 0, match.start()) + 1, "encoded_chars": len(blob), **decoded})
    # Readable payloads first: embedded images and fonts are common and say little.
    payloads = sorted(payloads, key=lambda item: item["kind"] != "text")[:4]
    binaries = []
    for path, data in members:
        kind = _binary_kind(data)
        if kind in {"Windows PE", "ELF", "Mach-O", "Mach-O universal", "WebAssembly"} or path.lower().endswith((".exe", ".dll", ".so", ".dylib", ".node")):
            binaries.append({"path": path[:300], "bytes": len(data), "kind": kind or "native library", "referenced_by": []})
    if binaries:
        for path, data in members:
            if not _is_text_path(path) or len(data) > MAX_TEXT_BYTES:
                continue
            text = data.decode("utf-8", errors="ignore")
            for item in binaries[:10]:
                name = PurePosixPath(str(item["path"])).name
                if len(item["referenced_by"]) < 3 and path != item["path"] and name in text:
                    item["referenced_by"].append(path[:300])
    return {"flagged_files": files, "flag_locations": locations, "decoded_payloads": payloads, "binaries": binaries[:10],
            "binaries_total": len(binaries), "missing_files": bounded_missing_files,
            "missing_files_truncated": len(missing_files) > len(bounded_missing_files)}
