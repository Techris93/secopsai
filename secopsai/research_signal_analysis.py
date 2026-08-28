"""Context-aware, non-executing artifact signal analysis.

This module intentionally favors structural parsing and language-aware call
sites over keyword searches.  It never imports or executes package code.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


TOOL_NAME = "secopsai-contextual-static-analyzer"
TOOL_VERSION = "2"

EXECUTABLE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".java", ".js", ".jsx", ".mjs",
    ".php", ".ps1", ".py", ".rb", ".rs", ".sh", ".ts", ".tsx",
}
MANIFEST_BASENAMES = {
    "package.json", "pyproject.toml", "setup.py", "setup.cfg", "composer.json",
    "cargo.toml", "go.mod", "pom.xml", "extension.vsixmanifest",
}
LOCKFILE_BASENAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "composer.lock", "cargo.lock", "go.sum", "packages.lock.json",
    "gemfile.lock",
}
DOCUMENT_BASENAMES = {
    "readme", "license", "licence", "changelog", "changes", "history",
    "contributing", "code_of_conduct", "security", "authors", "notice",
}
SOURCE_REFERENCE_HOSTS = {
    "npmjs.com", "npmjs.org", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
    "crates.io", "static.crates.io", "packagist.org", "repo.packagist.org",
    "rubygems.org", "nuget.org", "api.nuget.org", "maven.org", "maven.apache.org",
    "repo1.maven.org", "golang.org", "proxy.golang.org", "open-vsx.org",
    "github.com", "api.github.com", "raw.githubusercontent.com", "gitlab.com",
    "bitbucket.org", "shields.io", "img.shields.io", "w3.org",
    "json.schemastore.org", "schema.org",
    # Reporting and advisory hosts are evidence sources, never attacker IOCs
    # merely because a package README links to them.
    "thehackernews.com", "socket.dev", "research.jfrog.com", "jfrog.com",
    "blog.rust-lang.org", "rust-lang.org", "rustsec.org", "cisa.gov",
    "cert.org", "kb.cert.org", "grafana.com", "blog.cloudflare.com",
    "snyk.io", "checkmarx.com", "reversinglabs.com", "wiz.io", "jetbrains.org",
}
SHARED_SERVICE_HOSTS = {
    "googleapis.com", "microsoft.com", "cloudflare.com", "discord.com",
    "slack.com", "amazonaws.com", "azure.com", "google.com",
}


def _basename(path: str) -> str:
    return PurePosixPath(str(path).replace("\\", "/")).name.lower()


def classify_path(path: str) -> dict[str, str]:
    """Classify an archive member before applying behavior rules."""
    normalized = str(path or "").replace("\\", "/")
    lower = normalized.lower()
    parts = [part for part in lower.split("/") if part]
    name = _basename(normalized)
    stem = name.rsplit(".", 1)[0]
    suffix = PurePosixPath(name).suffix.lower()
    if name.endswith(".map"):
        context = "source_map"
    elif name in LOCKFILE_BASENAMES:
        context = "lockfile"
    elif name in MANIFEST_BASENAMES or name.endswith((".gemspec", ".nuspec")):
        context = "manifest"
    elif any(part in {"docs", "doc", "documentation"} for part in parts) or stem in DOCUMENT_BASENAMES:
        context = "documentation"
    elif suffix in {".md", ".rst", ".adoc"}:
        context = "documentation"
    elif any(part in {"test", "tests", "spec", "specs", "__tests__", "fixtures"} for part in parts):
        context = "test"
    elif any(part in {"example", "examples", "demo", "demos", "sample", "samples"} for part in parts):
        context = "example"
    elif any(token in lower for token in ("/themes/", "/theme/", "/syntaxes/", "/grammar/", "highlight", "tmLanguage".lower())):
        context = "static_data"
    elif name.endswith((".min.js", ".min.css")) or any(part in {"dist", "bundle", "bundles", "generated"} for part in parts):
        context = "generated_bundle"
    elif suffix in EXECUTABLE_SUFFIXES:
        context = "executable_source"
    elif suffix in {".json", ".toml", ".yaml", ".yml", ".xml", ".ini", ".cfg", ".conf"}:
        context = "configuration"
    elif suffix in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".otf"}:
        context = "image_font_binary"
    elif suffix in {".dll", ".exe", ".so", ".dylib", ".bin", ".wasm"}:
        context = "image_font_binary"
    else:
        context = "unknown"
    file_type = suffix.lstrip(".") or ("manifest" if context == "manifest" else "unknown")
    return {"path": normalized, "file_type": file_type, "context_classification": context}


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _safe_snippet(text: str, start: int, end: int, limit: int = 220) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    return re.sub(r"\s+", " ", text[line_start:line_end]).strip()[:limit]


def observation_fingerprint(observation: Mapping[str, Any], *, artifact_sha256: str = "") -> str:
    stable = {
        "artifact_sha256": str(artifact_sha256 or "").lower(),
        "tool": str(observation.get("tool") or TOOL_NAME),
        "tool_version": str(observation.get("tool_version") or TOOL_VERSION),
        "rule_id": str(observation.get("rule_id") or observation.get("indicator_id") or ""),
        "path": str(observation.get("path") or "").replace("\\", "/").lower(),
        "source_range": str(observation.get("source_range") or ""),
        "analysis_method": str(observation.get("analysis_method") or ""),
        "matched_operation": str(observation.get("matched_operation") or ""),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _observation(
    *,
    rule_id: str,
    category: str,
    path_info: Mapping[str, str],
    text: str,
    start: int,
    end: int,
    analysis_method: str,
    operation: str,
    confidence: int,
    severity: str,
    reachability: str = "direct_call",
    contributes: bool = True,
    recommendation: str = "Review the referenced call site and package purpose.",
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    line = _line_for_offset(text, start)
    result: dict[str, Any] = {
        "rule_id": rule_id,
        "indicator_id": rule_id,
        "category": category,
        "severity": severity,
        "confidence": max(0, min(int(confidence), 100)),
        "file_type": path_info.get("file_type", "unknown"),
        "path": path_info.get("path", ""),
        "source_range": {"start_line": line, "end_line": line},
        "analysis_method": analysis_method,
        "matched_operation": operation,
        "reachability_status": reachability,
        "context_classification": path_info.get("context_classification", "unknown"),
        "snippet": _safe_snippet(text, start, end),
        "recommended_verification": recommendation,
        "contributes_to_score": bool(contributes),
        "matches": 1,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
    }
    if details:
        result["details"] = dict(details)
    result["observation_fingerprint"] = observation_fingerprint(result)
    return result


def manifest_observations(path: str, text: str) -> tuple[dict[str, str], list[dict[str, Any]], dict[str, Any]]:
    """Parse executable manifest behavior without searching prose files."""
    name = _basename(path)
    info = classify_path(path)
    lifecycle: dict[str, str] = {}
    observations: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    if name == "package.json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return lifecycle, observations, {"package_json": "invalid_json"}
        if not isinstance(payload, dict):
            return lifecycle, observations, {"package_json": "invalid_shape"}
        summary = {key: payload.get(key) for key in ("name", "version", "description", "license", "repository", "homepage") if key in payload}
        scripts = payload.get("scripts") if isinstance(payload.get("scripts"), dict) else {}
        lifecycle_names = {
            "preinstall", "install", "postinstall", "prepare", "prepublish",
            "prepublishonly", "prepack", "postpack", "preversion", "version", "postversion",
        }
        for script_name, command in scripts.items():
            if script_name not in lifecycle_names:
                continue
            command_text = str(command)[:500]
            lifecycle[str(script_name)] = command_text
            offset = text.find(f'"{script_name}"')
            observations.append(_observation(
                rule_id="manifest-lifecycle-hook",
                category="lifecycle",
                path_info=info,
                text=text,
                start=max(0, offset),
                end=max(0, offset) + len(script_name) + 2,
                analysis_method="json_manifest_parser",
                operation=f"npm script {script_name}",
                confidence=100,
                severity="high" if script_name in {"preinstall", "install", "postinstall"} else "medium",
                reachability="package_manager_lifecycle",
                contributes=True,
                recommendation="Review the exact lifecycle command and the referenced executable source before installation.",
                details={"script_name": script_name, "command_summary": command_text},
            ))
    elif name == "composer.json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return lifecycle, observations, {"composer_json": "invalid_json"}
        if isinstance(payload, dict):
            scripts = payload.get("scripts") if isinstance(payload.get("scripts"), dict) else {}
            autoload = payload.get("autoload") if isinstance(payload.get("autoload"), dict) else {}
            files = autoload.get("files") if isinstance(autoload.get("files"), list) else []
            for key, command in scripts.items():
                if str(key).startswith(("pre-", "post-")):
                    lifecycle[str(key)] = str(command)[:500]
            for file_path in files:
                offset = text.find(str(file_path))
                observations.append(_observation(
                    rule_id="composer-autoload-file",
                    category="lifecycle",
                    path_info=info,
                    text=text,
                    start=max(0, offset),
                    end=max(0, offset) + len(str(file_path)),
                    analysis_method="json_manifest_parser",
                    operation="composer autoload.files",
                    confidence=100,
                    severity="medium",
                    reachability="autoload",
                    details={"autoload_file": str(file_path)},
                ))
    return lifecycle, observations, summary


def _javascript_tokens(text: str) -> list[tuple[str, str, int, int]]:
    """Tokenize JavaScript without interpreting or executing it.

    The scanner only needs call-site and literal context. Ignoring comments and
    strings here prevents prose, examples, and string contents from becoming
    executable observations while keeping source offsets for evidence.
    """
    tokens: list[tuple[str, str, int, int]] = []
    index = 0
    length = len(text)
    identifier = re.compile(r"[A-Za-z_$][\w$]*")
    while index < length:
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = length if newline < 0 else newline
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        if char == "/":
            previous = tokens[-1][1] if tokens else ""
            regex_context = not tokens or previous in {
                "=", "(", "[", "{", ",", ":", ";", "!", "&&", "||", "??", "?",
                "return", "throw", "case", "delete", "void", "typeof", "new", "in", "of",
            }
            if regex_context:
                start = index
                index += 1
                in_class = False
                escaped = False
                while index < length:
                    current = text[index]
                    if escaped:
                        escaped = False
                    elif current == "\\":
                        escaped = True
                    elif current == "[":
                        in_class = True
                    elif current == "]":
                        in_class = False
                    elif current == "/" and not in_class:
                        index += 1
                        while index < length and text[index].isalpha():
                            index += 1
                        break
                    index += 1
                tokens.append(("regex", text[start:index], start, index))
                continue
        if char in "'\"`":
            quote = char
            start = index
            index += 1
            value_start = index
            value_parts: list[str] = []
            while index < length:
                if text[index] == "\\" and index + 1 < length:
                    value_parts.append(text[value_start:index])
                    value_parts.append(text[index + 1])
                    index += 2
                    value_start = index
                    continue
                if text[index] == quote:
                    value_parts.append(text[value_start:index])
                    index += 1
                    break
                index += 1
            else:
                value_parts.append(text[value_start:index])
            tokens.append(("string", "".join(value_parts), start, index))
            continue
        match = identifier.match(text, index)
        if match:
            tokens.append(("identifier", match.group(0), match.start(), match.end()))
            index = match.end()
            continue
        if char.isdigit():
            start = index
            while index < length and (text[index].isalnum() or text[index] in "._-"):
                index += 1
            tokens.append(("number", text[start:index], start, index))
            continue
        punct = next((candidate for candidate in ("?.", "=>", "===", "!==", "&&", "||", "??", "++", "--") if text.startswith(candidate, index)), char)
        tokens.append(("punct", punct, index, index + len(punct)))
        index += len(punct)
    return tokens


def _javascript_call(tokens: Sequence[tuple[str, str, int, int]], index: int, *, allow_member: bool = False) -> bool:
    if index + 1 >= len(tokens) or tokens[index + 1][1] != "(":
        return False
    if index == 0:
        return True
    previous = tokens[index - 1][1]
    if previous in {"function", "class"}:
        return False
    return allow_member or previous not in {".", "?."}


def _javascript_call_arguments(tokens: Sequence[tuple[str, str, int, int]], index: int) -> tuple[list[tuple[str, str, int, int]], int]:
    """Return tokens inside a call and the index of its closing parenthesis."""
    if index + 1 >= len(tokens) or tokens[index + 1][1] != "(":
        return [], index
    depth = 0
    arguments: list[tuple[str, str, int, int]] = []
    for cursor in range(index + 1, len(tokens)):
        value = tokens[cursor][1]
        if value == "(":
            depth += 1
            if depth > 1:
                arguments.append(tokens[cursor])
        elif value == ")":
            depth -= 1
            if depth == 0:
                return arguments, cursor
            arguments.append(tokens[cursor])
        else:
            arguments.append(tokens[cursor])
    return arguments, len(tokens) - 1


def _javascript_import_bindings(tokens: Sequence[tuple[str, str, int, int]]) -> tuple[set[str], dict[str, str]]:
    module_aliases: set[str] = set()
    call_aliases: dict[str, str] = {}
    child_process_names = {"exec", "execFile", "spawn", "fork", "execSync", "execFileSync", "spawnSync"}

    def add_destructured(start: int, end: int) -> None:
        cursor = start
        while cursor < end:
            if tokens[cursor][0] != "identifier":
                cursor += 1
                continue
            source = tokens[cursor][1]
            alias = source
            if cursor + 2 < end and tokens[cursor + 1][1] in {":", "as"} and tokens[cursor + 2][0] == "identifier":
                alias = tokens[cursor + 2][1]
                cursor += 2
            if source in child_process_names:
                call_aliases[alias] = source
            cursor += 1

    for index, token in enumerate(tokens):
        if token[1] != "require" or index + 3 >= len(tokens):
            continue
        if tokens[index + 1][1] != "(" or tokens[index + 2][0] != "string" or tokens[index + 3][1] != ")":
            continue
        if tokens[index + 2][1] not in {"child_process", "node:child_process"}:
            continue
        if index >= 3 and tokens[index - 1][1] == "=" and tokens[index - 2][0] == "identifier":
            module_aliases.add(tokens[index - 2][1])
        if index >= 2 and tokens[index - 1][1] == "=" and tokens[index - 2][1] == "}":
            opening = index - 3
            while opening >= 0 and tokens[opening][1] != "{":
                opening -= 1
            if opening >= 0:
                add_destructured(opening + 1, index - 2)

    for index, token in enumerate(tokens):
        if token[1] != "from" or index + 1 >= len(tokens) or tokens[index + 1][0] != "string" or tokens[index + 1][1] not in {"child_process", "node:child_process"}:
            continue
        opening = index - 1
        if opening >= 0 and tokens[opening][1] == "}":
            opening -= 1
            while opening >= 0 and tokens[opening][1] != "{":
                opening -= 1
            if opening >= 0:
                add_destructured(opening + 1, index - 1)
        elif index >= 2 and tokens[index - 2][1] == "as" and tokens[index - 1][0] == "identifier":
            module_aliases.add(tokens[index - 1][1])
    return module_aliases, call_aliases


def _javascript_observations(path: str, text: str) -> list[dict[str, Any]]:
    info = classify_path(path)
    context = info["context_classification"]
    if context in {"documentation", "static_data", "source_map", "image_font_binary"}:
        return []
    results: list[dict[str, Any]] = []
    methods = "javascript_token_context"
    tokens = _javascript_tokens(text)
    contributes = context not in {"test", "example", "generated_bundle"}

    def add(rule_id: str, category: str, token: tuple[str, str, int, int], operation: str, confidence: int, severity: str, *, details: Mapping[str, Any] | None = None) -> None:
        results.append(_observation(
            rule_id=rule_id,
            category=category,
            path_info=info,
            text=text,
            start=token[2],
            end=token[3],
            analysis_method=methods,
            operation=operation,
            confidence=confidence if contributes else max(30, confidence - 35),
            severity=severity,
            reachability="direct_call" if contributes else "non_production_context",
            contributes=contributes,
            details=details,
        ))

    for index, token in enumerate(tokens):
        value = token[1]
        if value == "eval" and _javascript_call(tokens, index):
            add("dynamic-eval", "obfuscation", token, "eval call", 95, "high")
        elif value == "Function" and _javascript_call(tokens, index) and not (index and tokens[index - 1][1] in {"function", "class"}):
            _arguments, close = _javascript_call_arguments(tokens, index)
            # ``Function(args) { ... }`` is an object/class method declaration,
            # not the dynamic Function constructor.
            if not (close + 1 < len(tokens) and tokens[close + 1][1] == "{"):
                add("dynamic-function-constructor", "obfuscation", token, "Function constructor", 95, "high")
        elif value in {"fetch", "request"} and _javascript_call(tokens, index):
            add("outbound-network", "network", token, "network call", 85, "medium")
        elif value in {"get", "post", "request", "connect", "createConnection"} and _javascript_call(tokens, index, allow_member=True) and index and tokens[index - 1][1] == ".":
            root = tokens[index - 2][1] if index >= 2 else ""
            if root in {"axios", "got", "request", "https", "http", "net"}:
                add("outbound-network", "network", token, "network call", 85, "medium")
        elif value == "WebSocket" and _javascript_call(tokens, index) and index and tokens[index - 1][1] == "new":
            add("outbound-network", "network", token, "network call", 85, "medium")
        elif value in {"atob", "btoa"} and _javascript_call(tokens, index):
            add("encoded-payload", "obfuscation", token, "encoded data operation", 70, "low")
        elif value == "from" and _javascript_call(tokens, index, allow_member=True) and index >= 2 and tokens[index - 1][1] == "." and tokens[index - 2][1] == "Buffer":
            arguments, _end = _javascript_call_arguments(tokens, index)
            if any(item[0] == "string" and item[1].lower() == "base64" for item in arguments):
                add("encoded-payload", "obfuscation", token, "encoded data operation", 70, "low")

    module_aliases, call_aliases = _javascript_import_bindings(tokens)
    for index, token in enumerate(tokens):
        if token[1] in call_aliases and _javascript_call(tokens, index):
            actual = call_aliases[token[1]]
            arguments, _end = _javascript_call_arguments(tokens, index)
            argument_text = text[token[2]: arguments[-1][3] if arguments else token[3] + 180]
            shell = actual in {"exec", "execSync"} or bool(re.search(r"\bshell\s*:\s*true\b", argument_text))
            add("process-execution", "execution", token, f"child_process.{actual}", 75, "medium" if shell else "low", details={"shell_usage": shell, "argument_source": "requires_manual_dataflow_review", "lifecycle_reachable": False})
        elif token[1] in module_aliases and index + 3 < len(tokens) and tokens[index + 1][1] in {".", "?."} and tokens[index + 2][1] in {"exec", "execFile", "spawn", "fork", "execSync", "execFileSync", "spawnSync"} and tokens[index + 3][1] == "(":
            actual = tokens[index + 2][1]
            arguments, _end = _javascript_call_arguments(tokens, index + 2)
            argument_text = text[token[2]: arguments[-1][3] if arguments else token[3] + 180]
            shell = actual in {"exec", "execSync"} or bool(re.search(r"\bshell\s*:\s*true\b", argument_text))
            add("process-execution", "execution", token, f"child_process.{actual}", 75, "medium" if shell else "low", details={"shell_usage": shell, "argument_source": "requires_manual_dataflow_review", "lifecycle_reachable": False})

    credential_words = re.compile(r"(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)", re.I)
    credential_paths = re.compile(r"(?:\.npmrc|\.pypirc|\.ssh|\.aws|\.docker|\.env|credentials|token|secret)", re.I)
    read_functions = {"readFileSync", "readFile", "createReadStream"}
    for index, token in enumerate(tokens):
        if token[1] == "process" and index + 3 < len(tokens) and tokens[index + 1][1] == "." and tokens[index + 2][1] == "env" and tokens[index + 3][1] == "." and index + 4 < len(tokens) and credential_words.search(tokens[index + 4][1]):
            add("credential-access", "credential_access", tokens[index + 4], "developer or CI credential access", 75, "high")
        elif token[1] in read_functions and _javascript_call(tokens, index, allow_member=True):
            arguments, _end = _javascript_call_arguments(tokens, index)
            match = next((item for item in arguments if item[0] == "string" and credential_paths.search(item[1])), None)
            if match:
                add("credential-access", "credential_access", match, "developer or CI credential access", 75, "high")

    persistence_target = re.compile(r"(?:LaunchAgents?|CurrentVersion[\\/]+Run|/etc/(?:systemd|cron)|\bcrontab\b|\.config/autostart)", re.I)
    write_functions = {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "copyFile", "copyFileSync", "rename", "renameSync", "createWriteStream", "exec", "spawn"}
    variables: dict[str, str] = {}
    for index in range(len(tokens) - 3):
        if tokens[index][1] in {"const", "let", "var"} and tokens[index + 1][0] == "identifier" and tokens[index + 2][1] == "=" and tokens[index + 3][0] == "string":
            variables[tokens[index + 1][1]] = tokens[index + 3][1]
    for index, token in enumerate(tokens):
        if token[1] not in write_functions or not _javascript_call(tokens, index, allow_member=True):
            continue
        arguments, _end = _javascript_call_arguments(tokens, index)
        target = next((item for item in arguments if item[0] == "string" and persistence_target.search(item[1])), None)
        if target is None:
            target = next((item for item in arguments if item[0] == "identifier" and persistence_target.search(variables.get(item[1], ""))), None)
        if target:
            add("persistence-target-write", "persistence", target, "write to persistence target", 90, "high")
    return results


def _python_observations(path: str, text: str) -> list[dict[str, Any]]:
    info = classify_path(path)
    if info["context_classification"] in {"documentation", "static_data", "source_map"}:
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _textual_fallback(path, text)
    aliases: dict[str, str] = {}
    results: list[dict[str, Any]] = []

    def qualified_name(value: ast.AST) -> str:
        if isinstance(value, ast.Name):
            return value.id
        if isinstance(value, ast.Attribute):
            prefix = qualified_name(value.value)
            return f"{prefix}.{value.attr}" if prefix else value.attr
        return ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                aliases[item.asname or item.name] = f"{module}.{item.name}".strip(".")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = qualified_name(node.func)
        parts = qualified.split(".") if qualified else []
        if parts:
            parts[0] = aliases.get(parts[0], parts[0])
        called = ".".join(parts)
        if not called:
            continue
        rule: tuple[str, str, str, int, str] | None = None
        if called in {"eval", "exec", "compile"}:
            rule = ("dynamic-eval", "obfuscation", called, 95, "high")
        elif called.startswith(("subprocess.", "os.system", "os.popen")):
            rule = ("process-execution", "execution", called, 85, "medium")
        elif called.startswith(("requests.", "urllib.request.", "http.client.", "socket.")):
            rule = ("outbound-network", "network", called, 85, "medium")
        if rule:
            line = max(1, int(getattr(node, "lineno", 1)))
            offset = sum(len(value) + 1 for value in text.splitlines()[: line - 1])
            contributes = info["context_classification"] not in {"test", "example"}
            results.append(_observation(
                rule_id=rule[0], category=rule[1], path_info=info, text=text,
                start=offset, end=min(len(text), offset + len(rule[2])),
                analysis_method="python_ast", operation=rule[2], confidence=rule[3],
                severity=rule[4], contributes=contributes,
                reachability="direct_call" if contributes else "non_production_context",
            ))
    credential_pattern = re.compile(
        r"(?:\.npmrc|\.pypirc|\.ssh|\.aws|\.docker|\.env|/var/run/secrets|/proc/[^\s'\"]+/environ|"
        r"(?:TOKEN|API_KEY|SECRET|PASSWORD|CREDENTIAL))",
        re.I,
    )

    def constant_strings(node: ast.AST) -> list[tuple[str, int, int]]:
        values: list[tuple[str, int, int]] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                start = getattr(child, "col_offset", 0)
                line = max(1, int(getattr(child, "lineno", 1)))
                offset = sum(len(value) + 1 for value in text.splitlines()[: line - 1]) + start
                values.append((child.value, offset, offset + len(child.value)))
        return values

    def credential_lookup(node: ast.Call, called: str) -> bool:
        if called in {
            "os.getenv", "os.environ.get", "os.environ.setdefault", "os.environ.pop",
            "os.getenvb", "os.environ.__getitem__",
        }:
            return True
        if called in {"open", "io.open", "read_text", "read_bytes", "read_file", "readfile", "readFile", "pathlib.Path.read_text", "pathlib.Path.read_bytes"}:
            return True
        if called.endswith((".read_text", ".read_bytes", ".read_file", ".readfile", ".readFile")):
            return True
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            qualified = qualified_name(node.func)
            parts = qualified.split(".") if qualified else []
            if parts:
                parts[0] = aliases.get(parts[0], parts[0])
            called = ".".join(parts)
            if not credential_lookup(node, called):
                continue
            for value, start, end in constant_strings(node):
                if not credential_pattern.search(value):
                    continue
                contributes = info["context_classification"] not in {"test", "example"}
                results.append(_observation(
                    rule_id="credential-access",
                    category="credential_access",
                    path_info=info,
                    text=text,
                    start=start,
                    end=end,
                    analysis_method="python_ast_context",
                    operation="developer or CI credential lookup",
                    confidence=85 if contributes else 40,
                    severity="high" if contributes else "low",
                    reachability="direct_call" if contributes else "non_production_context",
                    contributes=contributes,
                    recommendation="Confirm that the credential value is intentionally accessed and whether it reaches an outbound sink.",
                ))
        elif isinstance(node, ast.Subscript):
            target = qualified_name(node.value)
            parts = target.split(".") if target else []
            if parts:
                parts[0] = aliases.get(parts[0], parts[0])
            if ".".join(parts) not in {"os.environ", "os.environb"}:
                continue
            for value, start, end in constant_strings(node.slice):
                if not credential_pattern.search(value):
                    continue
                contributes = info["context_classification"] not in {"test", "example"}
                results.append(_observation(
                    rule_id="credential-access",
                    category="credential_access",
                    path_info=info,
                    text=text,
                    start=start,
                    end=end,
                    analysis_method="python_ast_context",
                    operation="developer or CI credential lookup",
                    confidence=85 if contributes else 40,
                    severity="high" if contributes else "low",
                    reachability="direct_call" if contributes else "non_production_context",
                    contributes=contributes,
                    recommendation="Confirm that the credential value is intentionally accessed and whether it reaches an outbound sink.",
                ))
    return results


def _textual_fallback(path: str, text: str) -> list[dict[str, Any]]:
    info = classify_path(path)
    if info["context_classification"] in {"documentation", "static_data", "source_map", "image_font_binary", "manifest", "lockfile"}:
        return []
    results: list[dict[str, Any]] = []
    patterns = (
        ("textual-process-primitive", "execution", re.compile(r"\b(?:shell_exec|proc_open|ProcessBuilder)\s*\("), "possible process call"),
        ("textual-network-primitive", "network", re.compile(r"\b(?:curl_exec|HttpClient|TcpClient)\s*\("), "possible network call"),
    )
    for rule_id, category, pattern, operation in patterns:
        for match in pattern.finditer(text):
            results.append(_observation(
                rule_id=rule_id, category=category, path_info=info, text=text,
                start=match.start(), end=match.end(), analysis_method="textual_heuristic",
                operation=operation, confidence=35, severity="low", contributes=False,
                reachability="unknown", recommendation="Confirm with a language parser before using this observation for prioritization.",
            ))
    return results


def analyze_text_files(files: Sequence[tuple[str, str]], *, artifact_sha256: str = "") -> list[dict[str, Any]]:
    """Return unique structural and language-aware observations."""
    observations: list[dict[str, Any]] = []
    for path, text in files:
        info = classify_path(path)
        if info["context_classification"] == "manifest":
            _lifecycle, manifest_results, _summary = manifest_observations(path, text)
            observations.extend(manifest_results)
            if _basename(path) not in {"setup.py"}:
                continue
        suffix = PurePosixPath(path.lower()).suffix
        if suffix in {".js", ".jsx", ".mjs", ".ts", ".tsx"}:
            observations.extend(_javascript_observations(path, text))
        elif suffix == ".py" or _basename(path) == "setup.py":
            observations.extend(_python_observations(path, text))
        elif suffix in EXECUTABLE_SUFFIXES:
            observations.extend(_textual_fallback(path, text))
    return deduplicate_observations(observations, artifact_sha256=artifact_sha256)["observations"]


def deduplicate_observations(observations: Iterable[Mapping[str, Any]], *, artifact_sha256: str = "") -> dict[str, Any]:
    unique: dict[str, dict[str, Any]] = {}
    repeat_count = 0
    for raw in observations:
        item = dict(raw)
        fingerprint = str(item.get("observation_fingerprint") or observation_fingerprint(item, artifact_sha256=artifact_sha256))
        item["observation_fingerprint"] = fingerprint
        item.setdefault("occurrence_count", 1)
        if fingerprint in unique:
            repeat_count += int(item.get("occurrence_count") or 1)
            unique[fingerprint]["occurrence_count"] = int(unique[fingerprint].get("occurrence_count") or 1) + int(item.get("occurrence_count") or 1)
        else:
            unique[fingerprint] = item
    return {
        "observations": list(unique.values()),
        "unique_observations": len(unique),
        "repeat_observations": repeat_count,
    }


def normalize_observation(raw: Mapping[str, Any], *, source_kind: str = "observation") -> dict[str, Any] | None:
    """Normalize legacy rule-hit shapes into the contextual observation contract."""
    item = dict(raw)
    rule_id = str(item.get("rule_id") or item.get("indicator_id") or "").strip()
    # URL/IP/hash indicators are enrichment, not behavioral observations.
    if not rule_id:
        return None
    confidence = item.get("confidence", 0)
    if isinstance(confidence, str):
        confidence = {"critical": 95, "high": 90, "medium": 65, "low": 35}.get(confidence.lower(), 0)
    try:
        confidence = max(0, min(100, int(confidence)))
    except (TypeError, ValueError):
        confidence = 0
    severity = str(item.get("severity") or "low").lower()
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "low"
    item["rule_id"] = rule_id
    item.setdefault("indicator_id", rule_id)
    item.setdefault("category", str(item.get("category") or rule_id).lower())
    item["confidence"] = confidence
    item["severity"] = severity
    item.setdefault("path", str(item.get("file_path") or ""))
    item.setdefault("snippet", str(item.get("safe_context") or item.get("matched_indicator") or "")[:220])
    item.setdefault("matched_operation", str(item.get("matched_indicator") or rule_id))
    item.setdefault("analysis_method", "artifact_fleet_rule" if source_kind == "finding" else "legacy_observation")
    item.setdefault("context_classification", "unknown")
    item.setdefault("reachability_status", "unknown")
    item.setdefault("recommended_verification", str(item.get("recommended_mitigation") or "Review the rule hit and its execution context."))
    item.setdefault("contributes_to_score", source_kind != "indicator")
    item.setdefault("matches", 1)
    item["observation_fingerprint"] = str(item.get("observation_fingerprint") or observation_fingerprint(item))
    return item


def collect_observations(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Read current and legacy evidence keys while excluding IOC enrichment rows."""
    rows: list[dict[str, Any]] = []
    for key in ("observations", "findings", "indicators"):
        values = metadata.get(key) or []
        if not isinstance(values, list):
            continue
        source_kind = "finding" if key == "findings" else "indicator" if key == "indicators" else "observation"
        for raw in values:
            if not isinstance(raw, Mapping):
                continue
            normalized = normalize_observation(raw, source_kind=source_kind)
            if normalized is not None:
                rows.append(normalized)
    return rows


def _host_matches(host: str, domains: Iterable[str]) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in domains)


def classify_url(
    value: str,
    *,
    path: str = "",
    declared_source_urls: Sequence[str] = (),
    network_call_evidence: bool = False,
) -> dict[str, Any]:
    """Classify a URL without assuming every string is attacker infrastructure."""
    cleaned = str(value or "").strip().strip("<>[](){}'*\"").rstrip(".,;:!?*")
    try:
        parsed = urlsplit(cleaned)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    declared_hosts = set()
    for source in declared_source_urls:
        try:
            current = (urlsplit(str(source)).hostname or "").lower().rstrip(".")
        except ValueError:
            current = ""
        if current:
            declared_hosts.add(current)
    context = classify_path(path)["context_classification"] if path else "unknown"
    if not host:
        classification, reason, confidence = "unknown_url", "URL has no valid public hostname", 10
    elif _host_matches(host, declared_hosts):
        classification, reason, confidence = "source_reference", "URL host matches declared package or research source metadata", 100
    elif _host_matches(host, SOURCE_REFERENCE_HOSTS):
        classification, reason, confidence = "source_reference", "URL belongs to a registry, repository, documentation, badge, or schema service", 100
    elif context == "documentation":
        # An unknown URL in prose is a documentation reference, not attacker
        # infrastructure. It can be promoted manually only after corroboration.
        classification, reason, confidence = "documentation_url", "URL appears in documentation and is not eligible for automatic IOC approval", 35
    elif _host_matches(host, SHARED_SERVICE_HOSTS):
        classification, reason, confidence = "shared_legitimate_service", "URL uses a shared legitimate service and requires corroboration", 75
    elif network_call_evidence and context == "executable_source":
        classification, reason, confidence = "ioc_candidate", "URL is associated with a language-aware network call in executable source", 70
    else:
        classification, reason, confidence = "unknown_url", "URL lacks evidence tying it to attacker-controlled runtime infrastructure", 35
    return {
        "value": cleaned,
        "host": host,
        "classification": classification,
        "classification_reason": reason,
        "confidence": confidence,
        "eligible_for_ioc_review": classification in {"ioc_candidate", "unknown_url"},
    }


def evidence_quality_summary(observations: Sequence[Mapping[str, Any]], *, independent_sources: int = 1) -> dict[str, Any]:
    unique = deduplicate_observations(observations)
    scoring = [item for item in unique["observations"] if item.get("contributes_to_score")]
    structural = [item for item in scoring if item.get("analysis_method") not in {"textual_heuristic", "bounded_strings"}]
    if any(int(item.get("confidence") or 0) >= 90 and item.get("severity") in {"high", "critical"} for item in structural):
        label = "strong_static"
    elif structural:
        label = "moderate_static"
    elif unique["observations"]:
        label = "weak_heuristic"
    else:
        label = "insufficient"
    return {
        "label": label,
        "unique_observations": unique["unique_observations"],
        "repeat_observations": unique["repeat_observations"],
        "independent_sources": max(0, int(independent_sources)),
        "scoring_observations": len(scoring),
    }
