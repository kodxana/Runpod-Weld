"""Opt-in Linux cancellation regression: TRACE_ROOT ROOTFS STATE_DIR."""
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

binary, root, state = (str(Path(arg).resolve()) for arg in sys.argv[1:])
with tempfile.TemporaryDirectory(prefix="weld-cancel-", dir=Path(root) / "tmp") as temp:
    marker = Path(temp) / "child"
    inner = "/" + str(marker.relative_to(root))
    command = f"sleep 60 & echo $! > {inner}; wait"
    process = subprocess.Popen([binary, root, state, "30", command])
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() or not marker.read_text().strip():
            assert process.poll() is None, "tracer exited before child started"
            assert time.monotonic() < deadline, "child startup timed out"
            time.sleep(0.02)
        pid = int(marker.read_text())
        stat = Path(f"/proc/{pid}/stat")
        # starttime distinguishes this child from a later reuse of its PID.
        identity = stat.read_text().rsplit(")", 1)[1].split()[19]
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 128 + signal.SIGTERM
        if stat.exists():
            try:
                current = stat.read_text().rsplit(")", 1)[1].split()
            except FileNotFoundError:
                current = None
            assert current is None or current[19] != identity, "child was not reaped"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
print("traced cancellation and child reap passed")
