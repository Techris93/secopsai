"""YARA-X scanning for package artifacts.

Rules-first funnel (the approach Nextron describes for THOR): every artifact
is scanned with cheap deterministic rules; only artifacts with matches move
on to deeper (and costlier) analysis.  Many generic rules carry low scores
on their own, so the per-artifact score is the sum of matched rule scores,
graded like THOR: notice >= 40, warning >= 60, alert >= 80.

Rule packs:
- ``rules/yara`` in this repository (SecOpsAI generic OSS rules).
- Optional extra directories from ``SECOPSAI_YARA_RULE_DIRS`` (os.pathsep
  separated), e.g. Neo23x0/signature-base checked out at a pinned commit.
  Those rules are under the Detection Rule License 1.1: findings keep each
  rule's ``author`` and ``reference`` so every alert credits its author.

Files that fail to compile (THOR-only features, YARA-X incompatibilities)
are skipped and counted, never fatal.  Without the ``yara_x`` module the
engine reports itself unavailable and callers fall back to their other
checks.
"""

from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
BUILTIN_RULE_DIR = ROOT / "rules" / "yara"
DISABLED_RULES_FILE = BUILTIN_RULE_DIR / "disabled-rules.txt"
CONTEXT_BYTES = 2_048
MAX_MATCHES_PER_PATTERN = 4
SCAN_TIMEOUT_SECONDS = 10
NOTICE, WARNING, ALERT = 40, 60, 80
# signature-base rules may reference THOR's external variables.
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}

_lock = threading.Lock()
_compiled: Optional[Dict[str, Any]] = None


def _rule_dirs() -> List[Path]:
    dirs = [BUILTIN_RULE_DIR]
    for item in os.environ.get("SECOPSAI_YARA_RULE_DIRS", "").split(os.pathsep):
        if item.strip():
            dirs.append(Path(item.strip()).expanduser())
    return [path for path in dirs if path.is_dir()]


def _disabled_rules() -> set:
    try:
        lines = DISABLED_RULES_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    return {line.split("#", 1)[0].strip() for line in lines if line.split("#", 1)[0].strip()}


def load(*, force: bool = False) -> Dict[str, Any]:
    """Compile all rule packs once per process; returns engine status."""
    global _compiled
    with _lock:
        if _compiled is not None and not force:
            return _compiled
        try:
            import yara_x  # type: ignore
        except ImportError:
            _compiled = {"available": False, "reason": "yara_x is not installed", "rules": None, "files": 0, "skipped": 0}
            return _compiled
        compiler = yara_x.Compiler()
        for name, value in EXTERNALS.items():
            compiler.define_global(name, value)
        loaded, skipped = 0, []
        for directory in _rule_dirs():
            for path in sorted(list(directory.rglob("*.yar")) + list(directory.rglob("*.yara"))):
                try:
                    source = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                compiler.new_namespace(re.sub(r"[^A-Za-z0-9_]", "_", path.stem)[:60] or "rules")
                try:
                    compiler.add_source(source, origin=str(path))
                    loaded += 1
                except Exception as exc:  # incompatible file: skip, keep the rest
                    skipped.append({"file": path.name, "error": str(exc).splitlines()[0][:200]})
        try:
            rules = compiler.build()
        except Exception as exc:
            _compiled = {"available": False, "reason": f"rule build failed: {exc}"[:300], "rules": None, "files": loaded, "skipped": len(skipped)}
            return _compiled
        _compiled = {
            "available": True,
            "engine": "yara-x",
            "rules": rules,
            "files": loaded,
            "skipped": len(skipped),
            "skipped_detail": skipped[:50],
            "rule_dirs": [str(path) for path in _rule_dirs()],
            "disabled": _disabled_rules(),
        }
        return _compiled


def status() -> Dict[str, Any]:
    state = load()
    return {key: value for key, value in state.items() if key not in {"rules", "disabled"}}


def _meta(rule: Any) -> Dict[str, Any]:
    return {str(key): value for key, value in (rule.metadata or ())}


def _score(meta: Dict[str, Any]) -> int:
    if "score" in meta:
        try:
            return max(0, min(int(meta["score"]), 100))
        except (TypeError, ValueError):
            pass
    return {"critical": 90, "high": 75, "medium": 60, "low": 40}.get(str(meta.get("severity") or "").lower(), 50)


def _severity(score: int) -> str:
    return "high" if score >= ALERT else "medium" if score >= WARNING else "low"


def _safe_context(data: bytes, offset: int, length: int, size: int = CONTEXT_BYTES) -> str:
    start = max(0, offset - size // 2)
    end = min(len(data), offset + length + size // 2)
    text = data[start:end].decode("utf-8", errors="replace")
    # Keep the window readable and inert: no control characters.
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", ".", text)[:size]


def scan_files(files: Iterable[Tuple[str, bytes]]) -> Dict[str, Any]:
    """Scan (path, bytes) pairs.  Returns findings plus the artifact score."""
    state = load()
    if not state.get("available"):
        return {"available": False, "reason": state.get("reason"), "findings": [], "score": 0, "level": "none"}
    import yara_x  # type: ignore

    scanner = yara_x.Scanner(state["rules"])
    scanner.set_timeout(SCAN_TIMEOUT_SECONDS)
    scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN)
    disabled = state.get("disabled") or set()
    findings: List[Dict[str, Any]] = []
    rule_scores: Dict[str, int] = {}
    for path, data in files:
        if not data:
            continue
        scanner.set_global("filename", Path(path).name)
        scanner.set_global("filepath", path)
        scanner.set_global("extension", Path(path).suffix.lower())
        try:
            results = scanner.scan(data)
        except Exception as exc:  # timeout or engine error on one file
            findings.append({"rule_id": "YARA-SCAN-ERROR", "severity": "low", "confidence": "low", "file_path": path, "matched_indicator": str(exc)[:200], "safe_context": "", "score": 0})
            continue
        for rule in results.matching_rules:
            if rule.identifier in disabled:
                continue
            meta = _meta(rule)
            score = _score(meta)
            # One window per matched pattern (up to three), so the context shows
            # every part of a multi-string match, not just the first string.
            hits = [(pattern.identifier, pattern.matches[0].offset, pattern.matches[0].length) for pattern in rule.patterns if pattern.matches]
            windows: List[str] = []
            covered: List[Tuple[int, int]] = []
            for _identifier, offset, length in sorted(hits, key=lambda item: item[1]):
                if len(windows) >= 3 or any(start <= offset < end for start, end in covered):
                    continue
                half = CONTEXT_BYTES // 6
                covered.append((max(0, offset - half), offset + length + half))
                windows.append(_safe_context(data, offset, length, CONTEXT_BYTES // 3))
            findings.append({
                "rule_id": f"YARA:{rule.identifier}",
                "severity": str(meta.get("severity") or "").lower() if str(meta.get("severity") or "").lower() in {"low", "medium", "high", "critical"} else _severity(score),
                "confidence": "high" if score >= ALERT else "medium",
                "file_path": path,
                "matched_indicator": str(meta.get("description") or rule.identifier)[:500],
                "safe_context": "\n[...]\n".join(windows),
                "matched_patterns": sorted({identifier for identifier, _offset, _length in hits})[:10],
                "score": score,
                "rule_author": str(meta.get("author") or "")[:200],
                "rule_reference": str(meta.get("reference") or "")[:500],
                "rule_namespace": rule.namespace,
                "rule_meta_id": str(meta.get("rule_id") or "")[:120],
                "recommended_mitigation": "Quarantine and review the artifact before installation.",
            })
            rule_scores[rule.identifier] = max(rule_scores.get(rule.identifier, 0), score)
    # Sum distinct rules (not repeated hits of one rule across files).
    total = min(sum(rule_scores.values()), 200)
    level = "alert" if total >= ALERT else "warning" if total >= WARNING else "notice" if total >= NOTICE else ("low" if total else "none")
    return {"available": True, "findings": findings, "score": total, "level": level, "rules_matched": sorted(rule_scores)}
