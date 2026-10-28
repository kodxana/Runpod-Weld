"""Full builder timing with bounded /proc samples, never a concurrent tree walk."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def write(path, value):
    temp = path.with_name(path.name + '.tmp')
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temp.replace(path)


def kill_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def proc_sample(pid):
    result = {}
    for name in ('io', 'stat', 'status'):
        try:
            value = Path(f'/proc/{pid}/{name}').read_text()
            if name == 'status':
                value = '\n'.join(line for line in value.splitlines() if line.startswith(
                    ('State:', 'VmRSS:', 'VmHWM:', 'Threads:')))
            result[name] = value
        except OSError as error:
            result[name] = {'unavailable_errno': error.errno}
    return result


def measure(command, env, roots, log_dir, timeout=300, *, stall_observer=None):
    from metrics import usage, proc_counters
    assert 0 < timeout <= 300
    log_dir.mkdir(parents=True)
    # Both expensive walks are strictly outside the timed child interval.
    before = usage(*roots)
    result = {'command': command, 'allocated_before': before, 'timed_out': False,
              'allocation_sampling': 'disabled', 'proc_interval_seconds': 0.5,
              'proc_max_samples': 602, 'proc_samples': [], 'returncode': None}
    if stall_observer is not None:
        result['stall_diagnostics'] = []
    write(log_dir / 'measurement.json', result)
    process = None
    started = None
    try:
        with (log_dir / 'stdout.log').open('wb') as stdout, (log_dir / 'stderr.log').open('wb') as stderr:
            started = time.monotonic()
            process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
            last = started
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                now = time.monotonic()
                if now - started >= timeout:
                    result['timed_out'] = True
                    kill_group(process.pid)
                    break
                if now - last >= 0.5 and len(result['proc_samples']) < 601:
                    sample = {'seconds': now-started, **proc_sample(process.pid)}
                    result['proc_samples'].append(sample)
                    if stall_observer is not None:
                        diagnostic = stall_observer.observe(process.pid, sample)
                        if diagnostic is not None:
                            result['stall_diagnostics'].append(diagnostic)
                    last = now
                time.sleep(0.01)
            # Never block indefinitely after SIGKILL (e.g. uninterruptible kernel I/O).
            if result['timed_out']:
                reap_deadline = time.monotonic()+5
                while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    if time.monotonic() >= reap_deadline:
                        raise TimeoutError('builder not reapable within 5s after SIGKILL')
                    time.sleep(0.01)
            elapsed = time.monotonic() - started
            counters = proc_counters(process.pid)
            result['proc_samples'].append({'seconds': elapsed, **proc_sample(process.pid)})
            _, status, ru = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
            result.update(returncode=process.returncode, wall_seconds=elapsed,
                          cpu_user_seconds=ru.ru_utime, cpu_system_seconds=ru.ru_stime,
                          maxrss_kib=ru.ru_maxrss, rusage_input_blocks=ru.ru_inblock,
                          rusage_output_blocks=ru.ru_oublock, proc_io=counters,
                          clock_ticks_per_second=os.sysconf('SC_CLK_TCK'))
            # A completed builder must have reaped its own descendants.
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                kill_group(process.pid)
                raise RuntimeError('builder left a live process group')
        write(log_dir / 'measurement.json', result)
        result['allocated_retained'] = usage(*roots)
        assert process.returncode == 0 and not result['timed_out'], f'build failed: {log_dir}'
        assert 'read_bytes' in counters and 'write_bytes' in counters
        return result
    except BaseException as error:
        if process is not None:
            kill_group(process.pid)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                result['cleanup_error'] = 'process still not reapable after SIGKILL; parent must delete Pod'
        result['error'] = str(error)
        raise
    finally:
        write(log_dir / 'measurement.json', result)
