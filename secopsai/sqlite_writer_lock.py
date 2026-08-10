"""Cross-process serialization for the local Core SQLite writers."""

from __future__ import annotations

import fcntl
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# A monitor cycle may include bounded registry requests and static analysis.
# Edge sync must wait for that complete writer transaction instead of
# abandoning the sync while the Research Monitor still owns the database.
DEFAULT_LOCK_TIMEOUT_SECONDS = 1800.0
LOCK_POLL_SECONDS = 0.05
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.RLock] = {}
_LOCAL_HELD = threading.local()


def lock_path(db_path: str | None = None) -> Path:
    """Return the stable, sibling lock-file path for a Core database."""
    if db_path is None:
        import soc_store

        db_path = soc_store.default_db_path()
    database = Path(db_path).expanduser().resolve()
    return database.with_name(f"{database.name}.writer.lock")


def _timeout_seconds(timeout_seconds: float | None) -> float:
    if timeout_seconds is not None:
        return max(0.0, float(timeout_seconds))
    raw = os.environ.get("SECOPSAI_SQLITE_WRITER_LOCK_TIMEOUT_SECONDS", "")
    try:
        value = float(raw) if raw.strip() else DEFAULT_LOCK_TIMEOUT_SECONDS
    except ValueError:
        value = DEFAULT_LOCK_TIMEOUT_SECONDS
    return max(5.0, min(value, 3600.0))


def _local_lock(path: Path) -> threading.RLock:
    key = os.fspath(path)
    with _LOCAL_LOCKS_GUARD:
        lock = _LOCAL_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCAL_LOCKS[key] = lock
        return lock


def _held_locks() -> dict[str, dict[str, object]]:
    held = getattr(_LOCAL_HELD, "locks", None)
    if held is None:
        held = {}
        _LOCAL_HELD.locks = held
    return held


@contextmanager
def sqlite_writer_lock(
    db_path: str | None = None,
    *,
    timeout_seconds: float | None = None,
) -> Iterator[Path]:
    """Serialize a complete writer operation across independent processes.

    The lock is a separate sibling file, so SQLite journal files and the
    database itself are never used as the coordination primitive. ``flock``
    releases automatically when the descriptor closes, and the explicit
    ``finally`` makes the release visible in the writer call sites.
    """
    path = lock_path(db_path)
    timeout = _timeout_seconds(timeout_seconds)
    deadline = time.monotonic() + timeout
    local_lock = _local_lock(path)
    if timeout <= 0:
        acquired = local_lock.acquire(blocking=False)
    else:
        acquired = local_lock.acquire(timeout=timeout)
    if not acquired:
        raise TimeoutError(f"timed out waiting for SQLite writer lock: {path}")

    key = os.fspath(path)
    held = _held_locks()
    existing = held.get(key)
    if existing is not None and int(existing["pid"]) == os.getpid():
        existing["depth"] = int(existing["depth"]) + 1
        try:
            yield path
        finally:
            existing["depth"] = int(existing["depth"]) - 1
            local_lock.release()
        return

    handle = None
    os_locked = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
        handle = path.open("a+")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                os_locked = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"timed out waiting for SQLite writer lock: {path}")
                time.sleep(LOCK_POLL_SECONDS)
        held[key] = {"pid": os.getpid(), "depth": 1, "handle": handle}
        try:
            yield path
        finally:
            held.pop(key, None)
    finally:
        if handle is not None:
            if os_locked:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            try:
                handle.close()
            finally:
                local_lock.release()
