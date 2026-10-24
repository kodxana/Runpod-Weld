"""Opt-in Linux integration tests (no Rust, Docker, or Kaniko dependency).

Build on Linux:
  gcc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -pthread -static \
      tests/trace_threads.c -o /tmp/weld-trace-threads
Native baseline:
  python3 tests/trace_threads.py --run --fixture /tmp/weld-trace-threads
Candidate, with a disposable rootfs containing /bin/sh and an existing state dir:
  python3 tests/trace_threads.py --run --fixture /tmp/weld-trace-threads \
      --tracer /absolute/trace_root --rootfs /absolute/rootfs --state /absolute/state

Candidate mode runs the native baseline first, copies the static fixture into a
unique rootfs/tmp directory, then runs every candidate case. Expected baseline:
io/fork/exec exit 0 with PASS markers; worker exit_group exits 37; cancellation
uses native process-group SIGTERM, while candidate cancellation signals ONLY the
tracer and requires exit 143 and disappearance of all recorded descendant TIDs.
The driver becomes a child subreaper to collect native/emergency orphan cleanup.
Candidate zombies count as failures before emergency reaping. Run standalone,
not from a Python process supervising other children. Unsupported execution,
missing markers, timeouts, and missing prerequisites are FAIL, never SKIP.
Full coverage requires root (including CAP_SETUID/CAP_SETGID). The credentials
case uses libc's signal-coordinated setresgid/setresuid and checks all task IDs.
For an explicitly partial native baseline use --credentials omit; candidate
runs always require credentials. Dumpability is not asserted after prctl because
the tracer may restore it for trusted workload introspection.
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


def identity(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def reap():
    while True:
        try:
            if os.waitpid(-1, os.WNOHANG)[0] == 0:
                return
        except ChildProcessError:
            return


def run_case(label, case, command):
    tracked = {}
    with tempfile.TemporaryFile(mode="w+b") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)

        def output():
            # pread leaves the shared output offset untouched.
            return os.pread(log.fileno(), 1024 * 1024, 0).decode(errors="replace")

        try:
            if case == "cancel":
                deadline = time.monotonic() + 15
                while True:
                    lines = [line for line in output().splitlines()
                             if line.startswith("READY cancel ")]
                    if lines:
                        pids = [int(value) for value in lines[-1].split()[2:]]
                        if len(pids) != 3 or len(set(pids)) != 3:
                            raise RuntimeError("invalid descendant readiness record")
                        for pid in pids:
                            for task in Path(f"/proc/{pid}/task").iterdir():
                                tid = int(task.name)
                                tracked[tid] = identity(tid)
                                if tracked[tid] is None:
                                    raise RuntimeError("descendant exited before cancellation")
                        break
                    if process.poll() is not None:
                        raise RuntimeError("exited before cancellation readiness")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("cancellation readiness timeout")
                    time.sleep(0.02)
                if label == "native":
                    os.killpg(process.pid, signal.SIGTERM)
                    expected = -signal.SIGTERM
                else:
                    process.send_signal(signal.SIGTERM)
                    expected = 128 + signal.SIGTERM
                code = process.wait(timeout=10)
                deadline = time.monotonic() + 3
                while True:
                    if label == "native":
                        reap()
                    remaining = [tid for tid, stamp in tracked.items()
                                 if identity(tid) == stamp]
                    if not remaining or time.monotonic() >= deadline:
                        break
                    time.sleep(0.02)
                if remaining:
                    raise RuntimeError(f"descendants not reaped: {remaining}")
            else:
                expected = 37 if case == "exit-group" else 0
                code = process.wait(timeout=40)
                if code == 77 and case == "credentials":
                    raise RuntimeError("root prerequisite missing (fixture exit 77)")
                marker = "READY exit-group" if case == "exit-group" else f"PASS {case}"
                if marker not in output().splitlines():
                    raise RuntimeError(f"missing {marker!r}")
                evidence = {
                    "credentials": "VERIFIED credentials threads=4 uid=65534 gid=65534",
                    "dumpable": "VERIFIED dumpable threads=4 rounds=80",
                }.get(case)
                if evidence and evidence not in output().splitlines():
                    raise RuntimeError(f"missing {evidence!r}")
            if code != expected:
                raise RuntimeError(f"exit {code}, expected {expected}")
            print(f"PASS {label}: {case}", flush=True)
            return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
            print(f"FAIL {label}: {case}: {error}\n{output()}", file=sys.stderr, flush=True)
            return False
        finally:
            # Cleanup is separate from the assertions: it cannot turn a leak into PASS.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for tid, stamp in tracked.items():
                if identity(tid) == stamp:
                    try:
                        os.kill(tid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            process.wait(timeout=5)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                reap()
                if not any(identity(tid) == stamp for tid, stamp in tracked.items()):
                    break
                time.sleep(0.02)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true", help="explicitly enable integration execution")
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--tracer", type=Path)
    parser.add_argument("--rootfs", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--credentials", choices=("required", "omit"), default="required",
                        help="required by default; omit permits only a partial native baseline")
    args = parser.parse_args()
    if not args.run:
        parser.error("integration execution requires --run")
    if sys.platform != "linux":
        parser.error("Linux is required")
    if any((args.tracer, args.rootfs, args.state)) and not all((args.tracer, args.rootfs, args.state)):
        parser.error("--tracer, --rootfs and --state must be supplied together")
    if args.credentials == "omit" and args.tracer:
        parser.error("candidate runs require --credentials required")
    if args.credentials == "required" and os.geteuid() != 0:
        parser.error("PREREQUISITE: root required; use --credentials omit for a partial native baseline")
    fixture = args.fixture.resolve(strict=True)
    if not os.access(fixture, os.X_OK):
        parser.error("fixture must be executable")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
    cases = ("io", "fork", "exec", "exit-group", "cancel", "dumpable")
    if args.credentials == "required":
        cases += ("credentials",)
    else:
        print("PARTIAL native coverage: credentials explicitly omitted", flush=True)
    results = [run_case("native", case, [str(fixture), case]) for case in cases]
    if args.tracer:
        tracer = args.tracer.resolve(strict=True)
        root = args.rootfs.resolve(strict=True)
        state = args.state.resolve(strict=True)
        if root == Path("/") or not (root / "tmp").is_dir():
            parser.error("use a disposable rootfs with an existing tmp directory")
        with tempfile.TemporaryDirectory(prefix="weld-threads-", dir=root / "tmp") as temp:
            target = Path(temp) / "fixture"
            shutil.copy2(fixture, target)
            inner = "/" + target.relative_to(root).as_posix()
            for case in cases:
                command = [str(tracer), str(root), str(state), "35",
                           f"exec {shlex.quote(inner)} {shlex.quote(case)}"]
                results.append(run_case("candidate", case, command))
    print(f"{sum(results)}/{len(results)} cases passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
