#!/usr/bin/env python3
"""One fresh sealed ABBA experiment, supervised independently of agent turns.

No cloud operations. The parent owns collection, exact-Pod deletion and its timer.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid

INTERVAL = 20
SSH_TIMEOUT = 15
BENCHMARK_SECONDS = 2100
SEQUENCE = ['baseline', 'candidate', 'candidate', 'baseline']
FROZEN = {
    'baseline_revision': 'd6fe610d4f38522ca0192fd39b3f531650c4ecbe',
    'candidate_revision': 'e41a8ea0df588fc3f2d58ccdf1e5c5509d943516',
    'baseline_sha256': '67f5d1232ffa650e45aca8af25aefc8e7bc628e907b5da36eeb3f5c6e9bfa1cf',
    'candidate_sha256': '8ec37fb9b072529c99f05ab0a8096c8b98193d86227d0d36f11187831abd176f',
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def utc(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None, 'UTC offset required')
    return parsed.astimezone(timezone.utc)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def configuration(args, now):
    receipt_raw, go_raw = args.receipt.read_bytes(), args.go.read_bytes()
    receipt, go = json.loads(receipt_raw), json.loads(go_raw)
    ready = json.loads(args.ready.read_bytes())
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', args.host), 'literal SSH host required')
    require(1 <= args.port <= 65535, 'invalid port')
    require(re.fullmatch(r'/var/tmp/weld-xattr-[A-Za-z0-9_-]+', args.session), 'invalid session path')
    require(receipt['source'] == 'create-pod' and receipt['created_by_this_task'] is True, 'fresh receipt required')
    require(re.fullmatch(r'[A-Za-z0-9]+', receipt['id']), 'invalid Pod ID')
    require(receipt['create_request_id'] and receipt['create_mcp'] == receipt['cleanup_mcp'], 'same-MCP cleanup required')
    require(receipt['independent_cleanup_armed'] is True and receipt['local_backing_verified'] is True, 'parent preflight required')
    require((receipt['vcpu'], receipt['memory_gib'], receipt['disk_gb']) == (8, 32, 80), 'wrong Pod shape')
    require(go['approved'] is True and go['scope'] == 'xattr-scratch-cold-AB-BA', 'fresh GO required')
    require(go['pod_id'] == receipt['id'] and go['receipt_sha256'] == sha(receipt_raw), 'receipt identity/hash mismatch')
    require(go['cpu_class'] == receipt['cpu_class'] and bool(go['cpu_class']), 'CPU class mismatch')
    require(go['manifest_sha256'] == ready['manifest_sha256'] and re.fullmatch('[0-9a-f]{64}', go['manifest_sha256']), 'manifest mismatch')
    require(all(go[k] == v for k, v in FROZEN.items()), 'frozen binary/revision mismatch')
    require((go['max_builds'], go['per_build_seconds'], go['benchmark_seconds']) == (4, 300, 2100), 'limits changed')
    require(re.fullmatch('[0-9a-f]{32}', go['session_nonce']), 'invalid nonce')
    created, hard = utc(receipt['created_at']), utc(go['pod_delete_deadline_utc'])
    require(created <= now <= created + timedelta(minutes=20), 'stale/future receipt')
    require(hard == created + timedelta(minutes=60), 'Pod deadline changed')
    deadline = now + timedelta(seconds=BENCHMARK_SECONDS)
    require(deadline <= hard - timedelta(minutes=5), 'cleanup reserve unavailable')
    return {'session': args.session, 'pod_id': go['pod_id'], 'session_nonce': go['session_nonce'],
            'receipt_sha256': sha(receipt_raw), 'go_sha256': sha(go_raw),
            'manifest_sha256': go['manifest_sha256'], 'deadline_utc': deadline.isoformat()}


def remote_probe(request):
    """Sent over SSH, never installed in or allowed to modify the sealed payload."""
    import hashlib
    import json
    import os
    from pathlib import Path
    import runpy
    import subprocess
    import sys
    from datetime import datetime, timedelta, timezone

    def check(ok, message):
        if not ok:
            raise RuntimeError(message)

    def read(path):
        return json.loads(path.read_bytes())

    def digest(path):
        check(not path.is_symlink(), 'symlink control file')
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def date(value):
        return datetime.fromisoformat(value.replace('Z', '+00:00'))

    def alive(pid, ticks):
        try:
            fields = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
            return fields[0] != 'Z' and fields[19] == ticks
        except FileNotFoundError:
            return False

    now = datetime.now(timezone.utc)
    check(not sys.flags.optimize, 'optimized Python refused')
    check(now < date(request['expires_utc']) and now < date(request['deadline_utc']), 'expired request/deadline')
    session = Path(request['session'])
    check(session.resolve(strict=True) == session and session.parent == Path('/var/tmp')
          and session.name.startswith('weld-xattr-'), 'invalid session')
    payload = session / 'payload'
    for path, expected in ((session/'GO.json', request['go_sha256']),
                           (session/'created-pod.json', request['receipt_sha256']),
                           (payload/'PAYLOAD-SHA256.json', request['manifest_sha256'])):
        check(digest(path) == expected, 'control hash mismatch: ' + path.name)
    manifest = read(payload/'PAYLOAD-SHA256.json')
    # Only tiny control files during timing; the sealed runner verifies ALL payload bytes.
    for name in ('FREEZE.json', 'harness/common.py', 'harness/pulse.py', 'harness/run.py'):
        check(digest(payload/name) == manifest[name], 'sealed control code changed')
    sys.path.insert(0, str(payload/'harness'))
    from common import authorize, live
    go = read(session/'GO.json')
    check(go['pod_id'] == request['pod_id'] and go['session_nonce'] == request['session_nonce'], 'identity mismatch')
    state_path = session/'controller-start.json'
    evidence = session/'evidence'
    result = {'pod_id': request['pod_id'], 'session_nonce': request['session_nonce'],
              'manifest_sha256': request['manifest_sha256'], 'challenge': request['challenge']}
    if request['action'] == 'start':
        authorize(read(session/'created-pod.json'), go, read(payload/'FREEZE.json'),
                  request['manifest_sha256'], request['receipt_sha256'], now)
        check(not any((session/n).exists() or (session/n).is_symlink() for n in
                      ('run-once.json', 'supervisor-status.json', 'worker-config.json', 'liveness.json', 'scratch', 'evidence')),
              'session already used; no restart')
        with state_path.open('x') as out:
            out.write('{}\n')  # A failed/ambiguous start permanently consumes this session.
        sys.argv = ['pulse.py', '--session', str(session)]
        runpy.run_path(str(payload/'harness/pulse.py'), run_name='__main__')
        with (session/'controller-run.stdout.log').open('xb') as out, (session/'controller-run.stderr.log').open('xb') as err:
            child = subprocess.Popen(['/usr/bin/python3', '-B', str(payload/'harness/run.py'), '--session', str(session)],
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True,
                                     env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
        ticks = Path('/proc', str(child.pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]
        state = {'pid': child.pid, 'start_ticks': ticks, 'deadline_utc': request['deadline_utc'],
                 'pod_id': request['pod_id'], 'session_nonce': request['session_nonce']}
        state_path.write_text(json.dumps(state))
        result.update(status='RUNNING', state=state)
    else:
        check(request['action'] == 'observe', 'unknown action')
        state = read(state_path)
        check(state == request['state'], 'controller state changed')
        terminal = session/'supervisor-status.json'
        worker = read(evidence/'status.json') if (evidence/'status.json').exists() else None
        attempts = read(evidence/'build-attempts.json') if (evidence/'build-attempts.json').exists() else []
        sequence = ['baseline', 'candidate', 'candidate', 'baseline']
        check(isinstance(attempts, list) and len(attempts) <= 4, 'invalid build attempts')
        check(all(a['ordinal'] == i+1 and a['variant'] == sequence[i] for i, a in enumerate(attempts)), 'invalid ABBA order')
        if worker is not None:
            check(worker.get('status') in ('PASS', 'FAIL'), 'unknown worker status')
            if worker['status'] == 'FAIL':
                result.update(status='FAIL', worker=worker)
                return result
            check(worker == {'status': 'PASS', 'builds': 4} and len(attempts) == 4, 'invalid worker PASS')
        if terminal.exists():
            status = read(terminal)
            check(status.get('status') in ('PASS', 'FAIL'), 'unknown supervisor status')
            if status['status'] == 'PASS':
                check(status['pod_id'] == request['pod_id'] and status['manifest_sha256'] == request['manifest_sha256'], 'terminal identity mismatch')
                check(status['accepted_builds'] == 4 and worker == {'status': 'PASS', 'builds': 4}, 'incomplete PASS')
                rows = read(evidence/'results.json')
                check(len(rows) == 4 and [r['variant'] for r in rows] == sequence
                      and all(r['case'] == 'cold' and r['repetition'] == i//2 for i, r in enumerate(rows)), 'invalid accepted results')
                for pair in range(2):
                    completed = read(evidence/f'r{pair:02d}-completed.json')
                    parity = read(evidence/f'pair-{pair:02d}-parity.json')
                    check(completed['order'] == sequence[pair*2:pair*2+2]
                          and completed['mutable_output_mutation_probe'] == 'PASS', 'missing pair acceptance')
                    check(all(parity[k] == 'PASS' for k in ('exact_all_OCI_bytes',
                              'cross_arm_output_mutation_and_cache_isolation', 'source_immutability')), 'missing parity checks')
            result.update(status=status['status'], supervisor=status)
            return result  # Never renew after any terminal status.
        check(alive(state['pid'], state['start_ticks']), 'supervisor missing or PID reused')
        config = read(session/'worker-config.json')
        check(config['pod_id'] == request['pod_id'] and now < date(config['deadline_utc'])
              <= date(request['deadline_utc']) + timedelta(seconds=15), 'invalid worker deadline')
        live(read(session/'liveness.json'), go, now)  # An expired lease cannot be revived.
        check(datetime.now(timezone.utc) < date(request['expires_utc']), 'probe expired before pulse')
        sys.argv = ['pulse.py', '--session', str(session)]
        runpy.run_path(str(payload/'harness/pulse.py'), run_name='__main__')
        result.update(status='RUNNING', state=state, attempts=len(attempts))
    result['lease'] = read(session/'liveness.json')
    return result


class WindowsJob:
    """Kill the active SSH process even if Windows forcibly terminates Python."""
    def __init__(self):
        self.handle = None
        if os.name != 'nt':
            return
        import ctypes
        from ctypes import wintypes
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION: BasicLimitInformation.LimitFlags at offset 16.
        data = ctypes.create_string_buffer(144 if ctypes.sizeof(ctypes.c_void_p) == 8 else 112)
        ctypes.c_uint32.from_buffer(data, 16).value = 0x2000  # KILL_ON_JOB_CLOSE
        self.handle = self.kernel.CreateJobObjectW(None, None)
        require(self.handle, 'CreateJobObject failed')
        if not self.kernel.SetInformationJobObject(self.handle, 9, data, len(data)):
            self.close()
            raise RuntimeError('cannot arm Windows SSH cleanup job')

    def assign(self, process):
        if self.handle:
            require(self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)), 'cannot attach SSH cleanup job')

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def run_ssh(command, timeout):
    job, process = WindowsJob(), None
    try:
        # Windows OpenSSH exits 255 before logging without PROGRAMDATA, even for -V.
        # Only public OS paths are inherited; no auth environment is read.
        env = {k: os.environ[k] for k in ('PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PROGRAMDATA') if k in os.environ}
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       env=env, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            job.assign(process)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                err.seek(0)
                raise RuntimeError('SSH/probe timeout; no retry; stderr: ' + err.read(8192).decode(errors='replace')) from None
            if code:
                err.seek(0)
                raise RuntimeError(f'SSH/probe exited {code}; no retry; stderr: ' + err.read(8192).decode(errors='replace'))
            out.seek(0)
            raw = out.read(65537)
            require(len(raw) <= 65536, 'oversized SSH response')
            return json.loads(raw)
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
        finally:
            job.close()


def ssh_prefix(args):
    return ['ssh', '-F', 'none', '-T', '-p', str(args.port), '-i', str(args.identity),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile="' + str(args.known_hosts).replace('\\', '/') + '"',
            '-o', 'ConnectTimeout=5', '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=1', '-o', 'ClearAllForwardings=yes', 'root@' + args.host]


def supervise(config, exchange, log, clock=time.monotonic, now=lambda: datetime.now(timezone.utc), sleep=time.sleep):
    end = clock() + min(BENCHMARK_SECONDS, (utc(config['deadline_utc']) - now()).total_seconds())
    state = None
    while True:
        started = clock()
        remaining = min(end-started, (utc(config['deadline_utc'])-now()).total_seconds())
        require(remaining > SSH_TIMEOUT, 'controller experiment deadline reached')
        request = dict(config, action='start' if state is None else 'observe', state=state,
                       challenge=uuid.uuid4().hex, expires_utc=(now()+timedelta(seconds=12)).isoformat())
        result = exchange(request, min(SSH_TIMEOUT, remaining))
        require(clock() < end and now() < utc(config['deadline_utc']), 'controller deadline passed during SSH')
        require(isinstance(result, dict), 'invalid SSH response')
        require(all(result.get(k) == request[k] for k in ('pod_id', 'session_nonce', 'manifest_sha256', 'challenge')), 'response identity/hash/challenge mismatch')
        require(result.get('status') in ('RUNNING', 'PASS', 'FAIL'), 'invalid remote status')
        log(result)
        if result['status'] != 'RUNNING':
            require(state is not None, 'terminal status on fresh launch')
            require(result['status'] == 'PASS', 'remote experiment failed; collect partial evidence')
            terminal = result['supervisor']
            require(terminal['status'] == 'PASS' and terminal['accepted_builds'] == 4
                    and terminal['pod_id'] == config['pod_id']
                    and terminal['manifest_sha256'] == config['manifest_sha256'], 'invalid terminal PASS')
            return
        received = result['state']
        require(isinstance(received, dict) and received['pod_id'] == config['pod_id']
                and received['session_nonce'] == config['session_nonce']
                and received['deadline_utc'] == config['deadline_utc']
                and type(received['pid']) is int and received['pid'] > 0
                and str(received['start_ticks']).isdigit(), 'invalid supervisor identity')
        require(state is None or state == received, 'supervisor identity changed')
        lease = result['lease']
        require(lease['pod_id'] == config['pod_id'] and lease['session_nonce'] == config['session_nonce'], 'lease identity mismatch')
        updated, expires = utc(lease['updated_at']), utc(lease['liveness_deadline_utc'])
        require(updated <= now()+timedelta(seconds=5) and now() < expires
                and 0 < (expires-updated).total_seconds() <= 90, 'invalid/stale lease')
        state = received
        sleep(max(0, min(INTERVAL-(clock()-started), end-clock())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('host', 'session'):
        parser.add_argument('--'+flag, required=True)
    parser.add_argument('--port', type=int, required=True)
    for flag in ('identity', 'known-hosts', 'receipt', 'go', 'ready', 'evidence'):
        parser.add_argument('--'+flag, type=Path, required=True)
    args = parser.parse_args()
    require(not sys.flags.optimize, 'Python -O refused')
    config = configuration(args, datetime.now(timezone.utc))
    args.evidence.mkdir(parents=True, exist_ok=False)
    prefix = ssh_prefix(args)
    source = inspect.getsource(remote_probe) + '\nimport base64,json,sys\nprint(json.dumps(remote_probe(json.loads(base64.b64decode(sys.argv[1])))))\n'
    def exchange(request, timeout):
        encoded = base64.b64encode(json.dumps(request).encode()).decode()
        command = shlex.join(['timeout', '-s', 'KILL', '12s', 'env', '-i', 'PATH=/usr/bin:/bin',
                              '/usr/bin/python3', '-B', '-c', source, encoded])
        return run_ssh(prefix + [command], timeout)
    def interrupted(signum, frame):
        raise InterruptedError(f'controller signal {signum}')
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    result = dict(config, status='FAIL', cloud_deletion_verified=False)
    (args.evidence/'configuration.json').write_text(json.dumps(config, indent=2)+'\n')
    try:
        with (args.evidence/'observations.jsonl').open('x') as stream:
            def log(value):
                stream.write(json.dumps(dict(value, observed_at=datetime.now(timezone.utc).isoformat()))+'\n')
                stream.flush()
            supervise(config, exchange, log)
        result['status'] = 'PASS'
    except BaseException as error:
        result['error'] = str(error)
        raise
    finally:
        result['finished_at'] = datetime.now(timezone.utc).isoformat()
        (args.evidence/'controller-status.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
