"""Behaviour flags for a package's files.

Flags describe what a package's code does (install hooks, reading
credentials, talking to webhooks, dynamic evaluation of encoded data...)
without keeping any of the code.  The recall benchmark compares how often
each flag appears in missed malware against clean popular packages, which
shows where new detection rules will pay off; the same flags can feed the
funnel's score.
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Dict, Iterable, List, Optional, Set, Tuple

MAX_TEXT_BYTES = 1024 * 1024
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
    "crypto_wallet": r"metamask|exodus|electrum|\bmnemonic\b|seed phrase|solana|wallet\.dat|privateKey",
    # Joined URL, or host and path built separately (common in stealers).
    "discord_webhook": r"discord(app)?\.com/api/webhooks|discord(app)?\.com['\"`].{0,200}/api/webhooks",
    "telegram_bot": r"api\.telegram\.org",
    # Service domains, word-bounded: identifiers such as `transfer.shutdown`
    # and bare tool names (`ngrok` in a CLI list) do not count.
    "exfil_service": r"\b(pastebin\.com|transfer\.sh|webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok(-free)?\.(io|app|dev)|interactsh\.com|oast\.(fun|pro|site|me|live|online)|burpcollaborator\.net|canarytokens\.(com|org))\b",
    "raw_ip_url": r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
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
COMPILED = {name: re.compile(pattern, re.IGNORECASE | re.DOTALL) for name, pattern in PATTERNS.items()}


def _is_text_path(path: str) -> bool:
    return PurePosixPath(path.lower()).suffix in TEXT_SUFFIXES


def profile(members: Iterable[Tuple[str, bytes]], *, version: str = "") -> List[str]:
    """Sorted behaviour flags for one package's (path, bytes) members."""
    flags: Set[str] = set()
    files = list(members)
    code_files = 0
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
        if name == "package.json" and lowered.count("/") <= 1:
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
        if name == "build.rs" and lowered.count("/") <= 1:
            flags.add("build_rs")
            if re.search(r"Command::new|std::net|TcpStream|reqwest|ureq|curl|std::env::var|include_bytes!", text):
                flags.add("build_rs_side_effects")
        if lowered.endswith(".json"):
            continue
        code_files += 1
        in_tests = bool(TEST_PATH.search(lowered))
        for flag, pattern in COMPILED.items():
            # Injection strings in tests are defences being tested, not tool descriptions.
            if flag == "prompt_injection" and in_tests:
                continue
            if flag not in flags and pattern.search(text):
                flags.add(flag)
    if code_files <= 2:
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
    ("BEH_DEPENDENCY_CONFUSION", ("npm", "pypi"), (("inflated_version",), ("system_info", "http_send", "dns_lookup", "exfil_service")), 70),
    ("BEH_SHELL_DOWNLOAD", ("npm",), (("child_process",), ("download_tool",), SMALL_PACKAGE), 60),
    ("BEH_DISCORD_WEBHOOK", ("npm", "pypi", "open-vsx", "vscode-marketplace", "crates", "github-actions", "mcp-registry"),
     (("discord_webhook",), ("system_info", "home_dir", "credential_files", "browser_data", "crypto_wallet", "http_send")), 60),
    # build.rs runs on every `cargo build`; legitimate ones compile C code,
    # so only network/exfil behaviour in it counts.
    ("BEH_BUILD_RS_BEACON", ("crates",), (("build_rs_side_effects",), ("exfil_service", "discord_webhook", "telegram_bot", "raw_ip_url", "download_tool")), 60),
    # Agent tooling (hooks, skills) legitimately tells models what not to say;
    # poisoning pairs concealment with credential files or an exfil endpoint.
    ("BEH_MCP_TOOL_POISONING", ("mcp-registry", "npm", "pypi"), (("prompt_injection",), ("credential_files", "exfil_service")), 70),
    ("BEH_ACTIONS_RUNNER_MEMORY", ("github-actions",), (("runner_memory",),), 80),
    # setup.py commonly checks the platform; only exfil endpoints count.
    ("BEH_SETUP_PY_BEACON", ("pypi",), (("setup_py_side_effects",), ("exfil_service", "discord_webhook", "telegram_bot")), 60),
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


def flag_evidence(members: Iterable[Tuple[str, bytes]], flag: str, *, window: int = 360) -> Dict[str, str]:
    """Where a flag matched: file path and an inert text window around the first match."""
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
            snippet = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", ".", text[start:match.end() + window // 2])
            return {"flag": flag, "file_path": path[:300], "context": snippet[:window + 120]}
    return {}


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
            item["safe_context"] = "\n[...]\n".join(f"{found['flag']} in {found['file_path']}:\n{found['context']}" for found in evidence)[:2400]
            if evidence:
                item["file_path"] = evidence[0]["file_path"]
    score = min(100, int(scan.get("score") or 0) + sum(int(item["score"]) for item in extra))
    level = "alert" if score >= ALERT else "warning" if score >= WARNING else "notice" if score >= NOTICE else "none"
    return {**scan, "score": score, "level": level, "findings": list(scan.get("findings") or []) + extra,
            "rules_matched": sorted(set(scan.get("rules_matched") or []) | {str(item["rule_id"]).split(":", 1)[1] for item in extra})}
