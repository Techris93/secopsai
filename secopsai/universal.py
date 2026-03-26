from __future__ import annotations

"""Backward-compatible wrapper for the legacy secopsai-universal entrypoint."""

from secopsai.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
