from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from secopsai.edge_actions import (
    apply_edge_worker_action,
    generate_edge_report,
    normalize_edge_scan_payload,
    normalize_edge_report_payload,
    normalize_edge_worker_payload,
    queue_edge_scan,
)


def test_edge_scan_payload_is_private_and_canonical() -> None:
    assert normalize_edge_scan_payload(
        {"kind": "edge_scan", "target_cidr": "192.168.10.7/24", "include_wifi": True}
    ) == {
        "kind": "edge_scan",
        "target_cidr": "192.168.10.0/24",
        "include_wifi": True,
    }


@pytest.mark.parametrize("target", ["8.8.8.0/24", "192.168.0.0/23", "192.168.1.1/33"])
def test_edge_scan_payload_rejects_unsafe_targets(target: str) -> None:
    with pytest.raises(ValueError):
        normalize_edge_scan_payload({"kind": "edge_scan", "target_cidr": target})


def test_approved_edge_scan_uses_structured_helper_without_persisting_output(tmp_path: Path) -> None:
    root = tmp_path / "edge"
    script = root / "scripts" / "edge"
    script.parent.mkdir(parents=True)
    args_file = tmp_path / "args.json"
    script.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$@\" > '{args_file}'\n"
        "printf '%s' 'raw scan output must not be returned'\n",
        encoding="utf-8",
    )
    script.chmod(0o700)

    result = queue_edge_scan(
        {"kind": "edge_scan", "target_cidr": "10.0.0.7/24", "include_wifi": True},
        edge_root=str(root),
    )

    assert result == {
        "status": "queued",
        "target_cidr": "10.0.0.0/24",
        "include_wifi": True,
    }
    assert args_file.read_text(encoding="utf-8").splitlines() == ["queue", "10.0.0.0/24", "--cloud", "--wifi"]
    assert "raw" not in json.dumps(result)


def test_report_and_worker_actions_use_allowlisted_helper_arguments(tmp_path: Path) -> None:
    root = tmp_path / "edge"
    script = root / "scripts" / "edge"
    script.parent.mkdir(parents=True)
    args_file = tmp_path / "args.json"
    script.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$@\" > '{args_file}'\n"
        "printf '%s' 'raw report output must not be returned'\n",
        encoding="utf-8",
    )
    script.chmod(0o700)

    assert normalize_edge_report_payload({"kind": "edge_report"}) == {"kind": "edge_report"}
    assert generate_edge_report({"kind": "edge_report"}, edge_root=str(root))["status"] == "generated"
    assert args_file.read_text(encoding="utf-8").splitlines() == ["report", "--cloud"]

    assert normalize_edge_worker_payload({"kind": "edge_worker", "action": "stop"}) == {
        "kind": "edge_worker",
        "action": "stop",
    }
    assert apply_edge_worker_action(
        {"kind": "edge_worker", "action": "start"}, edge_root=str(root)
    )["action"] == "start"
    assert args_file.read_text(encoding="utf-8").splitlines() == ["worker", "start"]
