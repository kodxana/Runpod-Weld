"""Integration checks for the built rpweld scanner (stdlib only)."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

executable = Path(sys.argv[1]).resolve()
if os.name == "nt" and executable.suffix != ".exe":
    executable = executable.with_suffix(".exe")
binary = str(executable)
with tempfile.TemporaryDirectory(prefix="rpweld-scan-") as directory:
    path = Path(directory) / "Dockerfile"

    def run(source, expected):
        path.write_bytes(source)
        result = subprocess.run([binary, "scan", str(path), "--json"],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == expected, result
        return json.loads(result.stdout)["report"] if result.stdout else None

    report = run(b"FROM ubuntu:24.04\nRUN echo USER root\n", 0)
    assert report["builder_ready"] is False
    assert report["scan_complete"] is True
    report = run(b"FROM ubuntu:24.04\r\nUSER root\r\n", 0)
    assert report["scan_complete"] is True
    assert not any(d["code"] == "user_excluded" for d in report["diagnostics"])
    report = run(b"FROM ubuntu:24.04\nRUN echo " + b"\\" * 3 + b"\nUSER root\n", 0)
    assert report["scan_complete"] is True
    assert not any(d["code"] == "user_excluded" for d in report["diagnostics"])
    report = run(b"FROM ubuntu:24.04\nRUN <<EOF\nUSER text\nEOF\n", 0)
    assert report["scan_complete"] is True
    run(b"# syntax=docker/dockerfile:1\nFROM ubuntu:24.04\nCMD []\n", 0)
    run(b"# syntax=docker/dockerfile:1.7\nFROM ubuntu:24.04\n", 2)
    run(b"FROM ubuntu:24.04\nRUN --mount=type=cache echo hello\n", 2)
    assert run(b"x" * 1_048_577, 2) is None
    assert run(b"\xff", 2) is None
    if hasattr(os, "mkfifo"):
        path.unlink()
        os.mkfifo(path)
        result = subprocess.run([binary, "scan", str(path)], capture_output=True,
                                text=True, timeout=5)
        assert result.returncode == 2 and "regular" in result.stderr
print("scanner CLI integration checks passed")
