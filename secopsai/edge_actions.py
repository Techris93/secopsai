from __future__ import annotations

import os
import subprocess
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Any


PRIVATE_SCAN_RANGES = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
)
MAX_EDGE_SCAN_HOSTS = 256


def normalize_edge_scan_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the small, non-sensitive payload used by an approved Edge action."""
    if not isinstance(payload, dict) or payload.get("kind") != "edge_scan":
        raise ValueError("unsupported Edge approval payload")

    target = str(payload.get("target_cidr") or "").strip()
    try:
        network = ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError("Edge scan target must be a valid IPv4 CIDR") from exc
    if not isinstance(network, IPv4Network):
        raise ValueError("Edge scan target must use IPv4")
    if not any(network.subnet_of(allowed) for allowed in PRIVATE_SCAN_RANGES):
        raise ValueError("Edge scan target must be an RFC1918 private network")
    if network.prefixlen < 24 or network.num_addresses > MAX_EDGE_SCAN_HOSTS:
        raise ValueError("Edge approval is limited to a /24 or narrower private CIDR")

    include_wifi = payload.get("include_wifi", False)
    if not isinstance(include_wifi, bool):
        raise ValueError("include_wifi must be a boolean")
    return {
        "kind": "edge_scan",
        "target_cidr": str(network),
        "include_wifi": include_wifi,
    }


def queue_edge_scan(
    payload: dict[str, Any],
    *,
    edge_root: str | None,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Queue an approved scan through the local Edge helper.

    The helper reads the sensor's scoped cloud credentials from its local
    configuration. Core never receives or forwards those credentials, and the
    subprocess output is deliberately discarded so raw telemetry cannot enter
    Core session state.
    """
    normalized = normalize_edge_scan_payload(payload)
    if not edge_root:
        raise ValueError("--edge-root is required to apply an Edge scan approval")

    root = Path(edge_root).expanduser().resolve()
    script = root / "scripts" / "edge"
    if not root.is_dir() or not script.is_file() or not os.access(script, os.X_OK):
        raise ValueError("configured Edge root does not contain an executable scripts/edge helper")

    command = [str(script), "queue", normalized["target_cidr"], "--cloud"]
    if normalized["include_wifi"]:
        command.append("--wifi")
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Edge scan queue command timed out") from exc
    except OSError as exc:
        raise RuntimeError("Edge scan queue command could not start") from exc

    if completed.returncode != 0:
        raise RuntimeError(f"Edge scan queue command failed with exit code {completed.returncode}")
    return {
        "status": "queued",
        "target_cidr": normalized["target_cidr"],
        "include_wifi": normalized["include_wifi"],
    }
