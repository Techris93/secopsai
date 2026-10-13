"""Bounded provider requests. Error text never includes response bodies or keys."""
from __future__ import annotations
import random
import math
import time
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any
import requests
from secopsai.decision_contracts import DecisionError


def _retry_after(response: Any) -> float | None:
    raw = response.headers.get("Retry-After") if isinstance(response.headers, dict) or hasattr(response.headers, "get") else None
    if not isinstance(raw, str):
        return None
    try:
        delay = float(raw)
        return max(0.0, delay) if math.isfinite(delay) else None
    except ValueError:
        try:
            return max(0.0, (parsedate_to_datetime(raw) - datetime.now(timezone.utc)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return None


def post_json(url: str, *, headers: dict, payload: dict, timeout: float, provider: str, session: Any = None, max_attempts: int = 3) -> dict:
    http = session or requests
    deadline = time.monotonic() + timeout
    error = DecisionError("evaluation deadline exhausted", provider=provider, category="timeout")
    for attempt in range(max_attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise error
        retry_delay = None
        try:
            response = http.post(url, headers=headers, json=payload, timeout=remaining)
            status = response.status_code
            if not isinstance(status, int):
                raise DecisionError("invalid HTTP response status", provider=provider)
            if 200 <= status < 300:
                try:
                    data = response.json()
                except (ValueError, requests.exceptions.JSONDecodeError) as exc:
                    raise DecisionError("response is not valid JSON", provider=provider) from exc
                if not isinstance(data, dict):
                    raise DecisionError("response must be an object", provider=provider)
                if time.monotonic() > deadline:
                    raise DecisionError("evaluation deadline exhausted", provider=provider, category="timeout")
                return data
            category = "authentication" if status in {401, 403} else "rate_limit" if status == 429 else "availability" if status in {500, 502, 503, 504, 529} else "invalid_request"
            error = DecisionError(f"HTTP {status}", provider=provider, category=category, http_status=status)
            if category not in {"rate_limit", "availability"}:
                raise error
            retry_delay = _retry_after(response)
        except requests.Timeout:
            error = DecisionError("request timed out", provider=provider, category="timeout")
        except requests.ConnectionError:
            error = DecisionError("connection unavailable", provider=provider, category="availability")
        if attempt + 1 == max_attempts:
            raise error
        delay = retry_delay if retry_delay is not None else min(4.0, 0.5 * 2 ** attempt) + random.uniform(0, 0.1)
        if delay >= deadline - time.monotonic():
            raise error
        time.sleep(delay)
    raise error
