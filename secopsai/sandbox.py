"""Sandbox detonation: run a package's install and import steps, contained, and record behaviour.

Containment (every run):
- ``--network none``: nothing can leave the container.  A fake nameserver
  (an unroutable address) makes DNS lookups visible in the trace without
  ever being answered;
- ``--cap-drop ALL``, ``no-new-privileges``, read-only root, ``/tmp`` only as
  tmpfs, memory / pid / cpu limits, and a hard per-step and per-run timeout;
- an unprivileged user whose home holds fake credentials (bait).

Observation: ``strace`` records every process started, file opened,
connection attempted and DNS query sent.  Accesses by the package manager
itself (the root process of each step) are ignored; npm reading its own
``.npmrc`` is not evidence.

Real malware must only be detonated on a disposable host chosen for it, never
on a workstation and only where the host's terms allow it.  ``run`` refuses
unless ``SECOPSAI_SANDBOX_ALLOWED=1`` is set on that host.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

IMAGE = os.environ.get("SECOPSAI_SANDBOX_IMAGE", "secopsai-sandbox:dev")
RUN_TIMEOUT_SECONDS = 240
FAKE_NAMESERVER = "127.0.0.1"  # the in-container recorder (sandbox/dnslog.py) on port 53
BAIT_PATHS = (".npmrc", ".pypirc", ".aws/credentials", ".ssh/id_rsa", ".config/gcloud/application_default_credentials.json", ".bashrc")
HOME = "/home/analyst"
# npm runs every script through `sh -c` and pip runs python, so only real
# transfer tools count.
DOWNLOADERS = re.compile(r"(^|/)(curl|wget|nc|ncat|netcat|socat|powershell|pwsh|ftp|tftp|scp|ssh)$")

EXECVE = re.compile(r'^(\d+)\s+\S+\s+execve\("([^"]+)",\s*\[(.*?)\].*\)\s*=\s*0\s*$')  # successful launches only
OPENAT = re.compile(r'^(\d+)\s+\S+\s+openat\([^,]+,\s*"([^"]+)",\s*([A-Z_|]+)')
CONNECT = re.compile(r'^(\d+)\s+\S+\s+connect\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),.*?(?:inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6,\s*"([^"]+)")')
SENDTO = re.compile(r'^(\d+)\s+\S+\s+send(?:to|msg)\(\d+,\s*(?:\[\{iov_base=)?"((?:[^"\\]|\\.)*)"')
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")


def _unescape(text: str) -> bytes:
    out = bytearray()
    index = 0
    while index < len(text):
        if text[index] == "\\" and index + 1 < len(text):
            nxt = text[index + 1]
            if nxt == "x" and index + 3 < len(text):
                out.append(int(text[index + 2:index + 4], 16))
                index += 4
                continue
            out.extend({"n": b"\n", "t": b"\t", "r": b"\r", "\\": b"\\", '"': b'"'}.get(nxt, nxt.encode()))
            index += 2
            continue
        out.extend(text[index].encode("latin-1", "replace"))
        index += 1
    return bytes(out)


def dns_name(payload: bytes) -> str:
    """Question name of a DNS query packet ('' if it is not one)."""
    if len(payload) < 17:
        return ""
    labels, position = [], 12
    while position < len(payload):
        length = payload[position]
        if length == 0:
            break
        if length > 63 or position + 1 + length > len(payload):
            return ""
        labels.append(payload[position + 1:position + 1 + length].decode("ascii", "replace"))
        position += 1 + length
    return ".".join(labels)


def parse_trace(text: str) -> Dict[str, Any]:
    """Behaviour from one step's strace output, ignoring the step's root process."""
    lines = text.splitlines()
    root = lines[0].split()[0] if lines else ""
    processes: List[str] = []
    bait: set = set()
    connects: set = set()
    dns: set = set()
    writes: set = set()
    for line in lines:
        pid = line.split(" ", 1)[0]
        match = EXECVE.match(line)
        if match and pid != root:
            argv = re.findall(r'"((?:[^"\\]|\\.)*)"', match.group(3))
            processes.append(" ".join(argv)[:300] or match.group(2))
            continue
        if pid == root:
            continue
        match = OPENAT.match(line)
        if match:
            path, flags = match.group(2), match.group(3)
            if any(path == f"{HOME}/{item}" for item in BAIT_PATHS):
                bait.add(path.removeprefix(HOME + "/"))
            if path.startswith(HOME) and any(flag in flags for flag in WRITE_FLAGS):
                writes.add(path)
            continue
        match = CONNECT.match(line)
        if match:
            address = match.group(3) or match.group(4) or ""
            if address not in {FAKE_NAMESERVER, "127.0.0.53"} and not address.startswith("127."):
                connects.add(f"{address}:{match.group(2)}")
            continue
        match = SENDTO.match(line)
        if match:
            name = dns_name(_unescape(match.group(2)))
            if name:
                dns.add(name)
    return {"processes": processes[:50], "bait_read": sorted(bait), "connections": sorted(connects), "dns": sorted(dns), "home_writes": sorted(writes)[:20]}


def verdict(report: Dict[str, Any]) -> Dict[str, Any]:
    network = bool(report["connections"] or report["dns"])
    downloaders = [proc for proc in report["processes"] if DOWNLOADERS.search(proc.split(" ", 1)[0])]
    reasons = []
    if report["bait_read"] and network:
        reasons.append("read planted credentials and attempted network access")
    if report["home_writes"]:
        reasons.append("wrote to the user's home (persistence or tampering)")
    if network:
        reasons.append("attempted network access during install or import")
    if downloaders:
        reasons.append("started a shell or downloader")
    level = "malicious" if report["bait_read"] and network else "suspicious" if reasons else "quiet"
    return {"level": level, "reasons": reasons}


def run(ecosystem: str, artifact: Path, *, timeout: int = RUN_TIMEOUT_SECONDS, image: str = IMAGE, step_timeout: int = 60,
        allow: Optional[bool] = None) -> Dict[str, Any]:
    """Detonate one artifact; returns per-step behaviour and a verdict."""
    if not (allow if allow is not None else os.environ.get("SECOPSAI_SANDBOX_ALLOWED") == "1"):
        raise PermissionError("sandbox detonation is disabled on this host (set SECOPSAI_SANDBOX_ALLOWED=1 on a disposable host)")
    if ecosystem not in {"npm", "pypi"}:
        raise ValueError("sandbox supports npm and pypi")
    # Under $HOME by default: Docker Desktop / Colima only share the home folder with their VM.
    base = Path(os.environ.get("SECOPSAI_SANDBOX_WORKDIR") or Path.home() / ".cache" / "secopsai-sandbox")
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    try:
        inbox, outbox = work / "in", work / "out"
        inbox.mkdir()
        outbox.mkdir()
        shutil.copyfile(artifact, inbox / artifact.name)
        (work / "resolv.conf").write_text("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", encoding="utf-8")
        command = [
            "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            # Runs as the invoking user so /out can stay private (0700);
            # the home with the bait is a private tmpfs.
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--tmpfs", f"{HOME}:rw,size=16m,uid={os.getuid()},gid={os.getgid()},mode=0700", "-e", f"HOME={HOME}",
            "--read-only", "--tmpfs", "/tmp:rw,exec,size=512m",
            # lets the unprivileged recorder bind :53 inside this container only
            "--sysctl", "net.ipv4.ip_unprivileged_port_start=53", "--memory", "768m", "--pids-limit", "256", "--cpus", "1",
            "-e", f"STEP_TIMEOUT={step_timeout}",
            "-v", f"{inbox}:/in:ro", "-v", f"{outbox}:/out:rw", "-v", f"{work / 'resolv.conf'}:/etc/resolv.conf:ro",
            image, ecosystem, artifact.name,
        ]
        try:
            subprocess.run(command, capture_output=True, timeout=timeout, check=False)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
        steps: Dict[str, Any] = {}
        merged: Dict[str, Any] = {"processes": [], "bait_read": set(), "connections": set(), "dns": set(), "home_writes": set()}
        for trace in sorted(outbox.glob("trace.*")):
            report = parse_trace(trace.read_text(encoding="utf-8", errors="replace"))
            steps[trace.name.removeprefix("trace.")] = report
            merged["processes"] += report["processes"]
            for key in ("bait_read", "connections", "dns", "home_writes"):
                merged[key] |= set(report[key])
        dns_log = outbox / "dns.log"
        if dns_log.is_file():
            merged["dns"] |= {line.strip() for line in dns_log.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()}
        combined = {key: (sorted(value) if isinstance(value, set) else list(dict.fromkeys(value))[:50]) for key, value in merged.items()}
        return {"steps": steps, "behaviour": combined, "verdict": verdict(combined), "timed_out": timed_out}
    finally:
        shutil.rmtree(work, ignore_errors=True)
