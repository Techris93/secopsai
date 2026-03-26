from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _load_repo_cli() -> ModuleType:
    root = Path(__file__).resolve().parents[1]
    repo_cli = root / "cli.py"
    spec = importlib.util.spec_from_file_location("secopsai_repo_universal_cli", repo_cli)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load universal CLI module from {repo_cli}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    module = _load_repo_cli()
    if not hasattr(module, "main"):
        raise RuntimeError("Universal CLI module does not define main()")
    return int(module.main() or 0)
