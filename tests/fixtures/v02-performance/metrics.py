"""Linux measurements. Sampling never reads build content or advances directory atime."""
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import time


def walk(root):
    """Race-tolerant lstat walk, without following symlinks or touching atime."""
    try:
        info = root.lstat()
        yield root, info
        if stat.S_ISDIR(info.st_mode):
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME | os.O_NOFOLLOW)
            try:
                with os.scandir(fd) as entries:
                    names = sorted(entry.name for entry in entries)
                for name in names:
                    yield from walk(root / name)
            finally:
                os.close(fd)
    except FileNotFoundError:
        pass  # Temporary publication paths can disappear between samples.


def usage(*roots):
    seen = set()
    logical = allocated = 0
    for root in roots:
        for _, item in walk(root):
            logical += item.st_size
            identity = (item.st_dev, item.st_ino)
            if identity not in seen:
                seen.add(identity)
                allocated += item.st_blocks * 512
    return {"logical_bytes": logical, "allocated_bytes": allocated, "unique_inodes": len(seen)}


def proc_counters(pid):
    result = {}
    try:
        for line in Path(f"/proc/{pid}/io").read_text().splitlines():
            key, value = line.split(":")
            result[key] = int(value)
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        result["cpu_ticks_including_waited_children"] = sum(int(fields[i]) for i in (11, 12, 13, 14))
    except FileNotFoundError:
        pass
    return result


def build_environment(root, store):
    """Keep host credentials, private tuning flags and user configs out of the comparison."""
    for name in ("home", "tmp"):
        (root / name).mkdir(mode=0o700, exist_ok=True)
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
            "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"), "RPWELD_HOME": str(store)}


def measure(command, env, roots, log_dir, timeout=600, interval=0.5):
    """Read /proc before wait4 reaps the leader, including its waited descendants.

    All rpweld workers must be reaped by the builder. GNU time/rusage CPU and
    block counts are independent cross-checks. A timeout kills the process group.
    Allocation peaks are sampled lower bounds, not exact kernel high-water marks.
    """
    log_dir.mkdir(parents=True)
    before = usage(*roots)
    samples = [{"seconds": 0, **before}]
    scan_seconds = 0.0
    start = time.monotonic()
    with (log_dir / "stdout.log").open("wb") as stdout, (log_dir / "stderr.log").open("wb") as stderr:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        timed_out = False
        last = time.monotonic()
        try:
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                now = time.monotonic()
                if now - start > timeout:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                if now - last >= interval:
                    scan_start = time.monotonic()
                    samples.append({"seconds": now-start, **usage(*roots)})
                    scan_seconds += time.monotonic() - scan_start
                    last = time.monotonic()
                time.sleep(0.01)
            elapsed = time.monotonic() - start
            counters = proc_counters(process.pid)
            _, status, ru = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    retained = usage(*roots)
    samples.append({"seconds": elapsed, **retained})
    result = {"command": command, "returncode": process.returncode, "timed_out": timed_out,
        "wall_seconds": elapsed, "cpu_user_seconds": ru.ru_utime, "cpu_system_seconds": ru.ru_stime,
        "maxrss_kib": ru.ru_maxrss, "rusage_input_blocks": ru.ru_inblock,
        "rusage_output_blocks": ru.ru_oublock, "proc_io": counters,
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"), "allocated_before": before,
        "allocated_retained": retained, "allocated_sampled_peak_bytes": max(s["allocated_bytes"] for s in samples),
        "allocation_sampling_interval_seconds": interval, "allocation_sampling_seconds": scan_seconds,
        "allocation_samples": samples}
    (log_dir / "measurement.json").write_text(json.dumps(result, indent=2) + "\n")
    assert process.returncode == 0 and not timed_out, f"build failed; see {log_dir}"
    assert "read_bytes" in counters and "write_bytes" in counters, "missing final /proc I/O counters"
    return result


def environment(root):
    files = ["/proc/cpuinfo", "/proc/meminfo", "/proc/self/cgroup", "/proc/self/mountinfo",
             "/proc/mounts", "/proc/version", "/proc/sys/kernel/yama/ptrace_scope"]
    result = {"uname": list(os.uname()), "affinity": sorted(os.sched_getaffinity(0)),
              "python": os.sys.version, "root": str(root), "files": {}}
    for path in files:
        if Path(path).exists():
            result["files"][path] = Path(path).read_text()
    # Capture v2 and common v1 controller paths, including constrained ancestors.
    relative = []
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        _, controllers, location = line.split(":", 2)
        bases = [Path("/sys/fs/cgroup")]
        bases += [Path("/sys/fs/cgroup") / c for c in controllers.split(",") if c]
        for base in bases:
            relative += [base, base / location.lstrip("/")]
    names = ("cpu.max", "cpu.stat", "cpuset.cpus.effective", "memory.max", "memory.high", "memory.current",
             "cpu.cfs_quota_us", "cpu.cfs_period_us", "memory.limit_in_bytes")
    for base in relative:
        while str(base).startswith("/sys/fs/cgroup"):
            for name in names:
                path = base / name
                if path.is_file():
                    result["files"][str(path)] = path.read_text()
            base = base.parent
    result["findmnt"] = subprocess.check_output(
        ["findmnt", "-T", str(root), "-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"], text=True)
    result["df"] = subprocess.check_output(["df", "-B1", "-T", str(root)], text=True)
    result["storage"] = dict(zip(("free_bytes", "available_bytes", "total_bytes"),
        [os.statvfs(root).f_frsize * x for x in (os.statvfs(root).f_bfree, os.statvfs(root).f_bavail, os.statvfs(root).f_blocks)]))
    result["rlimits"] = {name: resource.getrlimit(getattr(resource, name))
                          for name in ("RLIMIT_NOFILE", "RLIMIT_NPROC", "RLIMIT_AS")}
    return result
