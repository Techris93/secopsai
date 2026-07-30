import os
import signal
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_container_entrypoint_handles_term_and_exits_cleanly(tmp_path):
    fake_python = tmp_path / "python"
    fake_python.write_text("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n", encoding="utf-8")
    fake_python.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{tmp_path}:{env['PATH']}"
    env["SECOPS_POLL_INTERVAL_SECONDS"] = "1"
    process = subprocess.Popen(
        ["sh", str(ROOT / "scripts/container-entrypoint.sh")],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        time.sleep(0.2)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()


def test_container_entrypoint_rejects_invalid_interval():
    env = os.environ.copy()
    env["SECOPS_POLL_INTERVAL_SECONDS"] = "not-a-number"
    result = subprocess.run(
        ["sh", str(ROOT / "scripts/container-entrypoint.sh")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 2
    assert "positive integer" in result.stderr
