"""Independent Linux x86_64 sharing/terminal-race regression tests.

Build: gcc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -pthread -static \
           tests/trace_sharing.c -o /tmp/weld-trace-sharing
Native: python3 tests/trace_sharing.py --run --fixture /tmp/weld-trace-sharing
Candidate: add --tracer /absolute/trace_root --rootfs /disposable/root \
               --state /disposable/state

Candidate mode also runs every native baseline. Unsupported execution, missing
markers, nonzero exits and timeouts fail; there are no skips. Dumpability calls
must succeed, but GET_DUMPABLE is deliberately not asserted: the trusted tracer
restores it. No root credential drop is needed. Run as a standalone process:
the driver is a subreaper for orphan cleanup. Each run uses a unique fixture path.
"""
import argparse
import ctypes
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time


CASES = ("clone-vm", "clone-files", "vfork", "exec-churn", "exit-churn")


def run_case(label, case, command):
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            code = process.wait(timeout=40)
            output = os.pread(log.fileno(), 1024 * 1024, 0).decode(errors="replace")
            expected = 37 if case == "exit-churn" else 0
            if code != expected:
                raise RuntimeError(f"exit {code}, expected {expected}")
            markers = ["READY exit-churn" if case == "exit-churn" else f"PASS {case}"]
            if case in ("exec-churn", "exit-churn"):
                markers.append("VERIFIED siblings=2 rounds>=32")
            for marker in markers:
                if output.splitlines().count(marker) != 1:
                    raise RuntimeError(f"missing or duplicate marker {marker!r}")
            # An exited group must leave no runnable members or zombies behind.
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise RuntimeError("process group still exists after exit")
            print(f"PASS {label}: {case}", flush=True)
            return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            output = os.pread(log.fileno(), 1024 * 1024, 0).decode(errors="replace")
            print(f"FAIL {label}: {case}: {error}\n{output}", file=sys.stderr, flush=True)
            return False
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if not pid:
                    time.sleep(0.02)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--tracer", type=Path)
    parser.add_argument("--rootfs", type=Path)
    parser.add_argument("--state", type=Path)
    args = parser.parse_args()
    if not args.run or sys.platform != "linux":
        parser.error("Linux and explicit --run required")
    if any((args.tracer, args.rootfs, args.state)) and not all((args.tracer, args.rootfs, args.state)):
        parser.error("--tracer, --rootfs and --state required together")
    fixture = args.fixture.resolve(strict=True)
    if not os.access(fixture, os.X_OK):
        parser.error("fixture must be executable")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
    results = [run_case("native", case, [str(fixture), case]) for case in CASES]
    if args.tracer:
        tracer = args.tracer.resolve(strict=True)
        root = args.rootfs.resolve(strict=True)
        state = args.state.resolve(strict=True)
        if root == Path("/") or not (root / "tmp").is_dir() or not (root / "bin/sh").is_file():
            parser.error("disposable root with tmp and bin/sh required")
        if not state.is_dir():
            parser.error("existing state directory required")
        with tempfile.TemporaryDirectory(prefix="weld-sharing-", dir=root / "tmp") as temp:
            target = Path(temp) / "fixture"
            shutil.copy2(fixture, target)
            inner = "/" + target.relative_to(root).as_posix()
            for case in CASES:
                results.append(run_case("candidate", case,
                    [str(tracer), str(root), str(state), "30",
                     f"exec {shlex.quote(inner)} {shlex.quote(case)}"]))
    print(f"{sum(results)}/{len(results)} cases passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
