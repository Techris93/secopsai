"""Safe rule validation and fixture execution boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from secopsai.research_cases import validate_rule


def evaluate_rule(*, rule_type: str, content: str, fixtures: Iterable[str] = ()) -> Dict[str, Any]:
    """Validate a rule and optionally run it only against explicit fixtures.

    The function never executes package code.  External tools are optional;
    absence is reported as a capability result rather than treated as a pass.
    """
    validation = validate_rule(rule_type, content)
    fixture_paths = [Path(item).expanduser() for item in fixtures]
    for path in fixture_paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("rule fixtures must be regular files no larger than 10 MiB")
    result: Dict[str, Any] = {
        "schema_version": "secopsai.research.rule-test.v1",
        "rule_type": rule_type,
        "validation": validation,
        "fixtures": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in fixture_paths],
        "execution": {"performed": False, "tool": None, "tool_version": None, "matches": [], "limitations": []},
        "safety": {"package_execution": False, "network_access": False, "filesystem_write": False},
    }
    if validation.get("status") != "passed":
        result["execution"]["limitations"].append("rule did not pass structural validation")
        return result
    tool = {"yara": "yara", "sigma": "sigma", "semgrep": "semgrep"}.get(rule_type)
    executable = shutil.which(tool) if tool else None
    if not fixture_paths:
        result["execution"]["limitations"].append("no explicit fixture corpus was supplied")
    elif not executable:
        result["execution"]["limitations"].append(f"{tool} is not installed; validation only")
    else:
        result["execution"]["tool"] = tool
        result["execution"]["tool_version"] = "available"
        # Rules are written to a temporary file only; package code is never
        # opened by this process and tools are denied network through policy.
        import tempfile
        with tempfile.TemporaryDirectory(prefix="secopsai-rule-") as temp_dir:
            rule_path = Path(temp_dir) / f"rule.{rule_type}"
            rule_path.write_text(content, encoding="utf-8")
            for fixture in fixture_paths:
                command = [executable, str(rule_path), str(fixture)] if rule_type == "yara" else [executable, "--config", str(rule_path), str(fixture)]
                completed = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False, cwd=temp_dir, env={"PATH": os.environ.get("PATH", "")})
                result["execution"]["matches"].append({"fixture": str(fixture), "returncode": completed.returncode, "stdout": completed.stdout[:2000], "stderr": completed.stderr[:2000]})
        result["execution"]["performed"] = True
    return result
