#!/usr/bin/env python3
"""Opt-in actual CLI tests. Linux root required; all evidence/partial trees retained.

sudo python3 tests/build_lifecycle.py --binary target/debug/rpweld --layout ALPINE_OCI
No downloads or recursive deletion. Use trusted binary/layout only (RUN is not a sandbox).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tarfile
import tempfile
import time


def proc(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return {"state": fields[0], "ppid": int(fields[1]), "start": fields[19]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def descendants(parent):
    table = {int(p.name): proc(int(p.name)) for p in Path('/proc').iterdir() if p.name.isdigit()}
    found = {parent}
    while True:
        more = {pid for pid, info in table.items() if info and info['ppid'] in found}
        if more <= found:
            break
        found |= more
    return {pid: table[pid] for pid in found if pid != parent and table.get(pid)}


def resolver(root):
    path = root / 'etc/resolv.conf'
    if not path.exists() and not path.is_symlink():
        return None
    st = path.lstat()
    assert path.is_file() and not path.is_symlink(), 'resolver must be regular'
    return (path.read_bytes(), st.st_mode & 0o7777, st.st_uid, st.st_gid, int(st.st_mtime))


def exported_resolver(layout):
    def blob(desc):
        algorithm, digest = desc['digest'].split(':')
        assert algorithm == 'sha256'
        path = layout / 'blobs' / algorithm / digest
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        return path
    index = json.loads((layout / 'index.json').read_text())
    manifest = json.loads(blob(index['manifests'][0]).read_text())
    assert len(manifest['layers']) == 1, 'expected flattened export'
    with tarfile.open(blob(manifest['layers'][0])) as archive:
        matches = [m for m in archive if m.name.removeprefix('./').lstrip('/') == 'etc/resolv.conf']
        if not matches:
            return None
        assert len(matches) == 1 and matches[0].isfile()
        m = matches[0]
        return (archive.extractfile(m).read(), m.mode, m.uid, m.gid, int(m.mtime))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--layout', type=Path, required=True)
    parser.add_argument('--temp-parent', type=Path, default=Path('/var/tmp'))
    parser.add_argument('--logs', type=Path, default=Path('.research-private/build-lifecycle'))
    parser.add_argument('--network-url', default='http://dl-cdn.alpinelinux.org/alpine/MIRRORS.txt')
    args = parser.parse_args()
    if platform.system() != 'Linux' or os.geteuid() != 0:
        parser.error('explicit Linux root requirement: run in WSL/Linux as root')
    binary, base = args.binary.resolve(strict=True), args.layout.resolve(strict=True)
    assert (base / 'index.json').is_file(), 'layout requires index.json'
    args.logs.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix='weld-lifecycle-', dir=args.temp_parent))
    logs = Path(tempfile.mkdtemp(prefix='run-', dir=args.logs.resolve()))
    results = []
    print(f'EVIDENCE trees={run} logs={logs}', flush=True)
    help_result = subprocess.run([str(binary), 'build', '--help'], capture_output=True, timeout=10)
    (logs / 'help.log').write_bytes(help_result.stdout + help_result.stderr)
    assert help_result.returncode == 0
    for flag in (b'--host-dns', b'--run-timeout-seconds', b'--base'):
        assert flag in help_result.stdout, f'missing CLI flag {flag!r}'
    (logs / 'binary.json').write_text(json.dumps({'binary': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'layout': str(base)}))

    def build(name, layout, command, dns=False, stopping=None):
        case = run / name
        context = case / 'context'
        context.mkdir(parents=True)
        dockerfile = context / 'Dockerfile'
        dockerfile.write_text('FROM alpine\nRUN ' + command + '\n')
        work, output = case / 'work', case / 'output'
        # Keep this single-layer resolver inspection as explicit flattened coverage.
        argv = [str(binary), 'build', '--export-mode', 'flattened', '-f', str(dockerfile), '--base', f'alpine={layout}', '--work-dir', str(work), '--output', str(output), '--run-timeout-seconds', '4' if stopping == 'timeout' else '25']
        if dns:
            argv.append('--host-dns')
        argv.append(str(context))
        observed = {}
        sent = False
        output_seen = False
        start = time.monotonic()
        with (logs / f'{name}.log').open('wb') as log:
            child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, cwd='/')
            try:
                while child.poll() is None:
                    observed.update(descendants(child.pid))
                    output_seen |= output.exists()
                    ready = work / 'rootfs/lifecycle-ready'
                    if stopping == 'sigterm' and ready.exists() and not sent:
                        assert len(observed) >= 3, 'descendants not observed before cancellation'
                        child.send_signal(signal.SIGTERM)
                        sent = True
                    assert time.monotonic() - start < 40, 'harness deadline exceeded'
                    time.sleep(0.025)
                rc = child.wait(timeout=2)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
                # Only kill matching identities observed below this owned CLI process.
                remaining = {}
                deadline = time.monotonic() + 3
                while True:
                    remaining = {pid: current for pid, info in observed.items() if (current := proc(pid)) and current['start'] == info['start']}
                    if not remaining or time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
                (logs / f'{name}-processes.json').write_text(json.dumps({'observed': observed, 'remaining_before_cleanup': remaining, 'sigterm_sent': sent, 'returncode': child.returncode, 'elapsed_seconds': time.monotonic() - start, 'argv': argv}, indent=2))
                for pid, info in remaining.items():
                    current = proc(pid)
                    if current and current['start'] == info['start'] and current['state'] != 'Z':
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
        assert not remaining, f'observed descendants remain (including zombies): {remaining}'
        assert not output_seen or output.is_dir(), 'created output directory was removed'
        if stopping:
            assert (work / 'rootfs/lifecycle-ready').is_file(), 'RUN did not reach descendant readiness'
            assert len(observed) >= 3, 'insufficient descendant evidence'
        if stopping == 'sigterm':
            assert sent, 'SIGTERM was not sent'
        return rc, work, output

    def record(name, fn):
        try:
            fn()
            results.append({'case': name, 'status': 'PASS'})
        except Exception as error:
            results.append({'case': name, 'status': 'FAIL', 'error': str(error)})
        print('EVIDENCE ' + json.dumps(results[-1]), flush=True)

    for kind in ('absent', 'empty'):
        prepared = {}
        def prepare():
            command = 'rm -f /etc/resolv.conf'
            if kind == 'empty':
                command += '; touch /etc/resolv.conf; chmod 640 /etc/resolv.conf; chown 123:456 /etc/resolv.conf; touch -t 202001020304.05 /etc/resolv.conf'
            rc, work, output = build(f'prepare-{kind}', base, command)
            assert rc == 0, f'fixture build exit {rc}'
            expected = None if kind == 'absent' else (b'', 0o640, 123, 456, 1577934245)
            assert resolver(work / 'rootfs') == expected
            assert exported_resolver(output) == expected
            prepared.update(layout=output, expected=expected)
        record(f'prepare-{kind}', prepare)
        if not prepared:
            continue
        for scenario in ('success', 'network', 'failure', 'timeout', 'sigterm'):
            def test():
                import shlex
                commands = {
                    'success': 'test -s /etc/resolv.conf && echo ok > /lifecycle-success',
                    'network': 'test -s /etc/resolv.conf && wget -T 10 -O /network-result ' + shlex.quote(args.network_url) + ' && test -s /network-result && echo ok > /lifecycle-success',
                    'failure': 'test -s /etc/resolv.conf && echo reached > /lifecycle-failure; exit 23',
                    'timeout': 'sleep 120 & sleep 120 & echo ready > /lifecycle-ready; wait',
                    'sigterm': 'sleep 120 & sleep 120 & echo ready > /lifecycle-ready; wait',
                }
                rc, work, output = build(f'{kind}-{scenario}', prepared['layout'], commands[scenario], dns=True, stopping=scenario if scenario in ('timeout', 'sigterm') else None)
                assert resolver(work / 'rootfs') == prepared['expected'], 'retained resolver contents/metadata changed'
                if scenario in ('success', 'network'):
                    assert rc == 0, f'build exit {rc}; see log (network is environment-dependent)'
                    assert (work / 'rootfs/lifecycle-success').read_text().strip() == 'ok'
                    assert exported_resolver(output) == prepared['expected'], 'export leaked resolver or changed metadata'
                else:
                    assert rc != 0, 'failed/cancelled RUN falsely succeeded'
                    diagnostic = (logs / f'{kind}-{scenario}.log').read_text()
                    expected_error = {'failure': 'exit status: 23', 'timeout': 'timeout', 'sigterm': 'cancelled'}[scenario]
                    assert expected_error in diagnostic, f'missing expected failure evidence: {expected_error}'
                    assert not (output / 'index.json').exists(), 'false OCI index publication'
                    # Export has not begun: output need not exist on RUN failure.
                    assert all((work / part).is_dir() for part in ('rootfs', 'state', 'spool')), 'partial work directories not retained'
                    if scenario == 'failure':
                        assert (work / 'rootfs/lifecycle-failure').is_file(), 'failing RUN not reached'
            record(f'{kind}-{scenario}', test)
    summary = {'passed': sum(r['status'] == 'PASS' for r in results), 'failed': sum(r['status'] == 'FAIL' for r in results), 'results': results, 'trees': str(run), 'logs': str(logs), 'limits': 'WSL root only; proc sampling covers observed identities, not all possible daemon escapes; no cloud/Pod validation; trees retained'}
    (logs / 'summary.json').write_text(json.dumps(summary, indent=2))
    print('EVIDENCE SUMMARY ' + json.dumps(summary), flush=True)
    return bool(summary['failed'])


if __name__ == '__main__':
    raise SystemExit(main())
