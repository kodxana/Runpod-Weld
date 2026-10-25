"""Production hidden-parser lifecycle test, Rust 1.90 + libc cache.

Run from repo in WSL: python3 tests/lease_guard_lifecycle.py
Builds the real CLI and creates isolated scratch fixtures.
"""
import ctypes
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def until(predicate):
    deadline = time.monotonic() + 15
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(.02)


def worker(root, mode):
    inode = (root / "lease").stat().st_ino
    for entry in Path('/proc/self/fd').iterdir():
        try:
            assert entry.stat().st_ino != inode, "lease leaked into workload"
            assert entry.resolve() != root, "host directory fd leaked"
        except FileNotFoundError:
            pass
    (root / 'no-leak').touch()
    if mode == 'stdio':
        print('stdout:' + sys.stdin.readline().strip(), flush=True)
        print('stderr:stream', file=sys.stderr, flush=True)
        return 23
    if mode == 'force':
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    os.closerange(3, 65536)
    null = os.open('/dev/null', os.O_RDWR)
    for fd in range(3):
        os.dup2(null, fd)
    if null > 2:
        os.close(null)
    (root / 'worker.pid').write_text(str(os.getpid()))
    if mode == 'tree':
        until(lambda: (root / 'leader.exit').exists())
        child = os.fork()
        if child == 0:
            os.setsid()
            if (root / 'ignore-term').exists():
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            (root / 'descendant.pid').write_text(str(os.getpid()))
            until(lambda: (root / 'descendant.exit').exists())
            os._exit(0)
        until(lambda: (root / 'descendant.pid').exists())
        return 37
    while True:
        signal.pause()


def exclusive(root):
    with open(root / 'lease', 'rb') as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False


def launch(binary, root, mode):
    # Launcher models the CLI. It transfers a locked OFD, then closes its copy.
    parent = os.fork()
    if parent == 0:
        fd = os.open(root / 'lease', os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_SH)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        guard = subprocess.Popen([str(binary), "__lease-guard", str(fd), "--", sys.executable,
                                  __file__, 'worker', str(root), mode],
                                 pass_fds=(fd, directory))
        os.close(fd)
        os.close(directory)
        (root / 'guard.pid').write_text(str(guard.pid))
        while True:
            signal.pause()
    until(lambda: (root / 'worker.pid').exists())
    until(lambda: (root / 'guard.pid').exists())
    assert (root / 'no-leak').exists()
    assert not exclusive(root)
    os.kill(parent, signal.SIGKILL)
    os.waitpid(parent, 0)
    assert not exclusive(root), 'CLI death released lease'
    return int((root / 'guard.pid').read_text())


def reap(pid, expected):
    result = []
    def done():
        child, status = os.waitpid(pid, os.WNOHANG)
        if child:
            result.append(os.waitstatus_to_exitcode(status))
        return bool(child)
    until(done)
    assert result == [expected], result


def test(binary):
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    for mode in ['tree', 'ordinary', 'force', 'adopted-cancel', 'adopted-force']:
        with tempfile.TemporaryDirectory(prefix='lease-guard-') as tmp:
            root = Path(tmp)
            if mode == 'adopted-force':
                (root / 'ignore-term').touch()
            guard = launch(binary, root, 'tree' if mode.startswith('adopted-') else mode)
            worker_pid = int((root / 'worker.pid').read_text())
            if mode == 'tree' or mode.startswith('adopted-'):
                (root / 'leader.exit').touch()
                until(lambda: (root / 'descendant.pid').exists())
                until(lambda: not Path(f'/proc/{worker_pid}').exists())
                assert not exclusive(root), 'leader exit released lease'
                if mode == 'tree':
                    (root / 'descendant.exit').touch()
                else:
                    os.kill(guard, signal.SIGTERM)
                    if mode == 'adopted-force':
                        time.sleep(.2)
                        assert not exclusive(root)
                        os.kill(guard, signal.SIGTERM)
                reap(guard, 37)
                descendant = int((root / 'descendant.pid').read_text())
                assert not Path(f'/proc/{descendant}').exists(), 'descendant not reaped'
            else:
                os.kill(guard, signal.SIGTERM if mode == 'force' else signal.SIGINT)
                if mode == 'force':
                    time.sleep(.2)
                    assert not exclusive(root)
                    assert Path(f'/proc/{guard}').exists()
                    os.kill(guard, signal.SIGTERM)
                reap(guard, 137 if mode == 'force' else 130)
            assert exclusive(root), 'lease retained after final reap'
            print('PASS:', mode, '(CLI killed, no fd leak, final flock granted)', flush=True)
    with tempfile.TemporaryDirectory(prefix='lease-guard-') as tmp:
        root = Path(tmp)
        fd = os.open(root / 'lease', os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_SH)
        proc = subprocess.Popen([str(binary), "__lease-guard", str(fd), "--", sys.executable, __file__,
                                 'worker', str(root), 'stdio'], pass_fds=(fd,),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        os.close(fd)
        proc.stdin.write('hello\n')
        proc.stdin.flush()
        assert proc.stdout.readline() == 'stdout:hello\n'
        assert proc.stderr.readline() == 'stderr:stream\n'
        assert proc.wait(timeout=15) == 23
        assert exclusive(root)
        print('PASS: inherited stdin and live stdout/stderr, exit 23', flush=True)
        for invalid in ['mode', 'links', 'directory', 'exec']:
            os.chmod(root / 'lease', 0o600)
            if invalid == 'mode':
                os.chmod(root / 'lease', 0o644)
            if invalid == 'links':
                os.link(root / 'lease', root / 'alias')
            fd = os.open(root if invalid == 'directory' else root / 'lease', os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_SH)
            command = '/missing-lease-guard-command' if invalid == 'exec' else '/bin/true'
            proc = subprocess.Popen([str(binary), "__lease-guard", str(fd), "--", command], pass_fds=(fd,),
                                    stderr=subprocess.PIPE)
            os.close(fd)
            _, err = proc.communicate(timeout=15)
            assert proc.returncode == 125, (invalid, err)
            if invalid == 'links':
                (root / 'alias').unlink()
        print('PASS: private mode, single link, regular file validation and exec failure', flush=True)

    # Pending startup cancellation must reach the fresh guard, never kill it
    # before it has installed its reaper/signal policy.
    with tempfile.TemporaryDirectory(prefix='lease-startup-') as tmp:
        root = Path(tmp)
        for _ in range(12):
            fd = os.open(root/'lease', os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(fd, fcntl.LOCK_SH)
            proc = subprocess.Popen([str(binary), '__lease-guard', str(fd), '--', '/bin/sleep', '60'], pass_fds=(fd,),
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}))
            os.close(fd)
            proc.send_signal(signal.SIGTERM)
            assert proc.wait(timeout=15) == 143
            assert exclusive(root)
        fd = os.open(root/'lease', os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_SH)
        def close_stdio():
            for descriptor in range(3):
                os.close(descriptor)
        proc = subprocess.Popen([str(binary), '__lease-guard', str(fd), '--', '/bin/true'], pass_fds=(fd,), preexec_fn=close_stdio)
        os.close(fd)
        assert proc.wait(timeout=15) == 0
        assert exclusive(root)
        fd = os.open(root/'lease', os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_SH)
        proc = subprocess.Popen([os.fsencode(binary), b'__lease-guard', str(fd).encode(), b'--', os.fsencode(sys.executable), b'-c',
            b'import os,sys; assert os.fsencode(sys.argv[1]) == bytes([255])', bytes([255])], pass_fds=(fd,))
        os.close(fd)
        assert proc.wait(timeout=15) == 0
        assert exclusive(root)
        print('PASS: startup cancellation, closed stdio, lossless argv', flush=True)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--binary':
        test(Path(sys.argv[2]).resolve())
        return
    repo = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env['CARGO_HOME'] = str(repo / '.local-tools/cargo')
    env['RUSTUP_HOME'] = str(repo / '.local-tools/rustup')
    env['PATH'] = env['CARGO_HOME'] + '/bin:' + env['PATH']
    subprocess.run(['cargo', '+1.90.0', 'build', '--offline', '--bin', 'rpweld'], env=env, check=True)
    test(repo / 'target/debug/rpweld')



if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'worker':
        sys.exit(worker(Path(sys.argv[2]), sys.argv[3]))
    main()
