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
from typing import Dict, Iterable, List, Set, Tuple

MAX_TEXT_BYTES = 1024 * 1024
TEXT_SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".py", ".pyw", ".json", ".sh", ".bat", ".cmd", ".ps1", ".cfg", ".toml", ".txt", ".yml", ".yaml", ""}
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
    "exfil_service": r"pastebin\.com|transfer\.sh|webhook\.site|requestbin|pipedream\.net|ngrok|interactsh|oast\.(fun|pro|site|me|live|online)|burpcollaborator|canarytokens",
    "raw_ip_url": r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    "dns_lookup": r"dns\.(lookup|resolve\w*)\s*\(|gethostbyname|\bnslookup\b|dns\.resolver",
    "http_send": r"https?\.request\s*\(|axios\.post|requests\.post|urlopen\s*\(|method\s*:\s*['\"]POST|XMLHttpRequest",
    "dynamic_eval": r"\beval\s*\(|new Function\s*\(|\bexec\s*\(\s*(base64|codecs|zlib|bytes|compile|__import__|.{0,40}decode)",
    "base64_decode": r"atob\s*\(|Buffer\.from\([^)]{0,200}['\"]base64['\"]|b64decode\s*\(",
    "long_base64": r"[A-Za-z0-9+/]{300,}={0,2}",
    "hex_blob": r"(\\x[0-9a-fA-F]{2}){60,}",
    "js_obfuscator": r"_0x[0-9a-f]{4,6}\b.{0,200}_0x[0-9a-f]{4,6}\b",
    "system_info": r"os\.hostname\s*\(|os\.userInfo\s*\(|os\.networkInterfaces|platform\.node\s*\(|getpass\.getuser|socket\.gethostname|\bwhoami\b",
    "download_tool": r"\bcurl\s+-|\bwget\s+|Invoke-WebRequest|urlretrieve\s*\(|DownloadFile",
    "chmod_exec": r"chmod\s+\+?[0-7x]+|os\.chmod\s*\(|fs\.chmodSync",
    "persistence": r"crontab|LaunchAgents|CurrentVersion\\\\Run|\.bashrc|\.zshrc|systemctl\s+enable|schtasks",
    "anti_analysis": r"\bisVM\b|virtualbox|vmware|sandbox|debugger|process\.exit\(\)\s*;?\s*}\s*else",
}
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
        if lowered.endswith(".json"):
            continue
        code_files += 1
        for flag, pattern in COMPILED.items():
            if flag not in flags and pattern.search(text):
                flags.add(flag)
    if code_files <= 2:
        flags.add("tiny_package")
    major = re.match(r"(\d+)", version or "")
    if major and int(major.group(1)) >= 50:
        flags.add("inflated_version")  # dependency-confusion packages publish 99.x to win resolution
    return sorted(flags)
