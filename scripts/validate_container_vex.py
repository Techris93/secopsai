#!/usr/bin/env python3
"""Validate that container VEX statements match verified, current backports."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate(root: Path, policy_path: Path, *, now: datetime | None = None) -> dict[str, object]:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    vex_path = policy_path.parent / policy["vex_document"]
    manifest_path = (policy_path.parent / policy["patch_manifest"]).resolve()
    vex = json.loads(vex_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    issued_at = _timestamp(policy["issued_at"])
    review_after = _timestamp(policy["review_after"])
    current = now or datetime.now(timezone.utc)
    assert review_after > current, f"Container VEX review expired at {review_after.isoformat()}"
    assert (review_after - issued_at).days <= int(policy["maximum_review_days"])

    patch_cves: set[str] = set()
    verified_files: list[dict[str, str]] = []
    source_root = root / "container/stdlib/3.13"
    for file_record in manifest["files"]:
        relative = Path(file_record["path"])
        local_path = source_root / (Path("html/parser.py") if relative == Path("Lib/html/parser.py") else relative.name)
        actual = hashlib.sha256(local_path.read_bytes()).hexdigest()
        assert actual == file_record["sha256"], f"Patch hash mismatch: {local_path}"
        patch_cves.update(item["id"] for item in file_record["vulnerabilities"])
        verified_files.append({"path": str(local_path.relative_to(root)), "sha256": actual})

    statements = vex["statements"]
    vex_cves = {statement["vulnerability"]["name"] for statement in statements}
    assert vex_cves == patch_cves, f"VEX CVEs {sorted(vex_cves)} do not match patched CVEs {sorted(patch_cves)}"
    for statement in statements:
        assert statement["status"] == "fixed"
        assert statement["products"] == [{"@id": "pkg:generic/python@3.13.14"}]

    return {
        "schema_version": policy["schema_version"],
        "status": "valid",
        "review_after": policy["review_after"],
        "vulnerabilities": sorted(vex_cves),
        "verified_files": verified_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(__file__).resolve().parents[1] / ".github/vex/python-3.13.14-backports.policy.json",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = validate(args.root.resolve(), args.policy.resolve())
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
