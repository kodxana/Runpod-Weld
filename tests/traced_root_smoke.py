"""Opt-in tests that install packages in a disposable Ubuntu ROOTFS.

Usage: python traced_root_smoke.py TRACE_ROOT ROOTFS STATE_DIR
Requires a root Pod process with chroot/UID-changing capabilities, but no host
permissions. Provide DNS in ROOTFS/etc/resolv.conf. This is not a sandbox test.
"""
from pathlib import Path
import subprocess
import sys
import time

binary, root, state = (str(Path(arg).resolve()) for arg in sys.argv[1:])


def run(command, timeout=120, expected=0):
    started = time.monotonic()
    result = subprocess.run([binary, root, state, str(timeout), command],
                            capture_output=True, text=True, timeout=timeout + 15)
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    assert result.returncode == expected, (command, result.returncode, expected)
    return time.monotonic() - started


run("test -c /dev/null && echo discarded > /dev/null && cat /proc/self/status >/dev/null")
run("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "
    "--no-install-recommends hello python3 python3-venv ca-certificates build-essential "
    "&& hello && python3 -m venv /tmp/weld-trace-venv "
    "&& /tmp/weld-trace-venv/bin/python -m pip --version "
    "&& printf 'int main(void){return 0;}\\n' >/tmp/weld-trace.c "
    "&& cc /tmp/weld-trace.c -o /tmp/weld-trace && /tmp/weld-trace", timeout=600)
run("python3 -c 'import os,stat; os.setgroups([]); os.setgid(1234); os.setuid(1234); "
    "assert os.getuid()==1234; assert stat.S_ISCHR(os.stat(\"/dev/null\").st_mode); "
    "f=open(\"/dev/null\",\"r+b\",buffering=0); assert f.read(1)==b\"\"; "
    "assert f.write(b\"discard\")==7; print(\"REAL_UID_DEVICE_OK\")'")
run("exit 37", expected=37)
assert run("sleep 30 & wait", timeout=1, expected=124) < 12
print("traced private-root smoke checks passed")
