import shutil
import subprocess
from pathlib import Path

import pytest

from secopsai import sandbox

TRACE = """21    00:00:00.1 execve("/usr/bin/node", ["node", "/usr/local/bin/npm", "run", "postinstall"], 0x1 /* 9 vars */) = 0
21    00:00:00.2 openat(AT_FDCWD, "/home/analyst/.npmrc", O_RDONLY|O_CLOEXEC) = 3
30    00:00:00.3 execve("/usr/bin/sh", ["sh", "-c", "node steal.js"], 0x1 /* 9 vars */) = -1 ENOENT (No such file or directory)
30    00:00:00.4 execve("/bin/sh", ["sh", "-c", "node steal.js"], 0x1 /* 9 vars */) = 0
31    00:00:00.5 execve("/usr/bin/curl", ["curl", "-s", "http://x"], 0x1 /* 9 vars */) = 0
31    00:00:00.6 openat(AT_FDCWD, "/home/analyst/.aws/credentials", O_RDONLY|O_CLOEXEC) = 3
31    00:00:00.7 openat(AT_FDCWD, "/home/analyst/.bashrc", O_WRONLY|O_APPEND) = 4
31    00:00:00.8 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = -1 ENETUNREACH (Network is unreachable)
31    00:00:00.9 connect(6, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
"""


def test_trace_parsing_ignores_the_package_manager_and_failed_launches():
    report = sandbox.parse_trace(TRACE)
    assert report["bait_read"] == [".aws/credentials", ".bashrc"], "npm's own .npmrc read (root process) is ignored"
    assert report["processes"] == ["sh -c node steal.js", "curl -s http://x"], "failed PATH lookups are not launches"
    assert report["connections"] == ["203.0.113.10:443"], "the loopback DNS recorder is not a connection"
    assert report["home_writes"] == ["/home/analyst/.bashrc"]
    verdict = sandbox.verdict({**report, "dns": []})
    assert verdict["level"] == "malicious" and "started a shell or downloader" in verdict["reasons"]


def test_dns_query_names_and_quiet_packages():
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06beacon\x07example\x03com\x00\x00\x01\x00\x01"
    assert sandbox.dns_name(query) == "beacon.example.com"
    assert sandbox.dns_name(b"short") == ""
    quiet = {"processes": ["sh -c node -e 1"], "bait_read": [], "connections": [], "dns": [], "home_writes": []}
    assert sandbox.verdict(quiet) == {"level": "quiet", "reasons": []}


def test_refuses_to_run_unless_the_host_is_allowed(tmp_path, monkeypatch):
    monkeypatch.delenv("SECOPSAI_SANDBOX_ALLOWED", raising=False)
    with pytest.raises(PermissionError):
        sandbox.run("npm", tmp_path / "x.tgz")
