"""Optional production error reporting with conservative privacy defaults."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional


_INITIALIZED = False


def _sample_rate(name: str, default: float = 0.0) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return max(0.0, min(value, 1.0))


def initialize_observability(*, service: str) -> bool:
    """Initialize Sentry only when a server-side DSN is present.

    Raw package contents and local variables are intentionally excluded. The
    integration is optional so local-first installations keep working without
    an external telemetry provider.
    """
    global _INITIALIZED
    if _INITIALIZED:
        return True
    dsn = (os.environ.get("SECOPSAI_SENTRY_DSN") or os.environ.get("SENTRY_DSN") or "").strip()
    if not dsn:
        return False
    try:
        import sentry_sdk
    except ImportError:
        return False

    sentry_sdk.init(
        dsn=dsn,
        environment=os.environ.get("SECOPSAI_CORE_ENVIRONMENT", "local"),
        release=os.environ.get("RENDER_GIT_COMMIT") or None,
        server_name=service,
        send_default_pii=False,
        include_local_variables=False,
        traces_sample_rate=_sample_rate("SECOPSAI_SENTRY_TRACES_SAMPLE_RATE"),
        profiles_sample_rate=_sample_rate("SECOPSAI_SENTRY_PROFILES_SAMPLE_RATE"),
    )
    sentry_sdk.set_tag("secopsai.service", service)
    _INITIALIZED = True
    return True


def capture_exception(error: BaseException, *, context: Optional[Dict[str, Any]] = None) -> None:
    """Report an isolated exception without making Sentry a runtime dependency."""
    if not _INITIALIZED:
        return
    try:
        import sentry_sdk
    except ImportError:
        return
    if context:
        with sentry_sdk.push_scope() as scope:
            for key, value in context.items():
                scope.set_tag(str(key), str(value)[:200])
            sentry_sdk.capture_exception(error)
        return
    sentry_sdk.capture_exception(error)
