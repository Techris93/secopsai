#!/usr/bin/env python3
"""Append a concise entry to CHANGELOG.md under the Unreleased section."""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
ALLOWED_SECTIONS = {"Added", "Changed", "Fixed", "Security", "Docs", "Internal"}


def add_entry(section: str, message: str, *, changelog: Path = CHANGELOG) -> Path:
    section = section[:1].upper() + section[1:].lower()
    if section not in ALLOWED_SECTIONS:
        allowed = ", ".join(sorted(ALLOWED_SECTIONS))
        raise ValueError(f"section must be one of: {allowed}")
    message = " ".join(message.strip().split())
    if not message:
        raise ValueError("message is required")
    text = changelog.read_text(encoding="utf-8") if changelog.exists() else "# Changelog\n\n## Unreleased\n"
    if "## Unreleased" not in text:
        text = text.rstrip() + "\n\n## Unreleased\n"
    section_header = f"### {section}"
    unreleased_index = text.index("## Unreleased")
    next_release_index = text.find("\n## ", unreleased_index + len("## Unreleased"))
    if next_release_index == -1:
        next_release_index = len(text)
    before = text[:unreleased_index]
    unreleased = text[unreleased_index:next_release_index]
    after = text[next_release_index:]
    if section_header not in unreleased:
        insert_at = unreleased.find("\n### ")
        if insert_at == -1:
            unreleased = unreleased.rstrip() + f"\n\n{section_header}\n\n"
        else:
            unreleased = unreleased[:insert_at] + f"\n\n{section_header}\n\n" + unreleased[insert_at:]
    lines = unreleased.splitlines()
    output = []
    inserted = False
    for index, line in enumerate(lines):
        output.append(line)
        if line == section_header:
            next_line = lines[index + 1] if index + 1 < len(lines) else ""
            if next_line != "":
                output.append("")
            output.append(f"- {message}")
            inserted = True
    if not inserted:
        output.extend(["", section_header, "", f"- {message}"])
    changelog.write_text(before + "\n".join(output).rstrip() + "\n" + after, encoding="utf-8")
    return changelog


def main() -> int:
    parser = argparse.ArgumentParser(description="Append an Unreleased changelog entry.")
    parser.add_argument("--section", required=True, help="Added, Changed, Fixed, Security, Docs, or Internal")
    parser.add_argument("--message", required=True, help="One concise changelog bullet")
    args = parser.parse_args()
    path = add_entry(args.section, args.message)
    print(f"updated={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
