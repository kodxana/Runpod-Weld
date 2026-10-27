"""Windows-capable control tests: no SSH server, cloud, sealed binary or builder."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('lease-controller.py')
spec = importlib.util.spec_from_file_location('lease_controller', SCRIPT)
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


class Clock:
    def __init__(self):
        self.elapsed = 0
        self.base = datetime.now(timezone.utc)

    def monotonic(self):
        return self.elapsed

    def now(self):
        return self.base + timedelta(seconds=self.elapsed)

    def sleep(self, seconds):
        self.elapsed += seconds


def config(clock):
    return {'pod_id': 'freshpod', 'session_nonce': 'a'*32, 'manifest_sha256': 'b'*64,
            'go_sha256': 'c'*64, 'receipt_sha256': 'd'*64,
            'session': '/var/tmp/weld-xattr-fresh',
            'deadline_utc': (clock.now()+timedelta(seconds=2100)).isoformat()}


class FakeSSH:
    def __init__(self, clock, terminal='PASS'):
        self.clock, self.terminal = clock, terminal
        self.calls = []

    def __call__(self, request, timeout):
        self.calls.append((copy.deepcopy(request), self.clock.elapsed, timeout))
        state = {k: request[k] for k in ('pod_id', 'session_nonce', 'deadline_utc')}
        state.update(pid=123, start_ticks='456')
        result = {k: request[k] for k in ('pod_id', 'session_nonce', 'manifest_sha256', 'challenge')}
        result.update(status='RUNNING', state=state, lease={
            'pod_id': request['pod_id'], 'session_nonce': request['session_nonce'],
            'updated_at': self.clock.now().isoformat(),
            'liveness_deadline_utc': (self.clock.now()+timedelta(seconds=90)).isoformat()})
        if len(self.calls) == 3 and self.terminal:
            result.update(status=self.terminal, supervisor={'status': self.terminal, 'accepted_builds': 4,
                          'pod_id': request['pod_id'], 'manifest_sha256': request['manifest_sha256']})
        return result


class LoopTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.config = config(self.clock)
        self.ssh = FakeSSH(self.clock)

    def run_loop(self, exchange=None):
        controller.supervise(self.config, exchange or self.ssh, lambda value: None,
                             self.clock.monotonic, self.clock.now, self.clock.sleep)

    def test_independent_twenty_second_cadence_one_start_and_terminal_stop(self):
        self.run_loop()
        self.assertEqual([c[1] for c in self.ssh.calls], [0, 20, 40])
        self.assertEqual([c[0]['action'] for c in self.ssh.calls], ['start', 'observe', 'observe'])
        self.assertEqual(len({c[0]['challenge'] for c in self.ssh.calls}), 3)
        self.assertTrue(all(c[2] == 15 for c in self.ssh.calls))

    def test_failure_and_unknown_status_stop_without_retry(self):
        for terminal in ('FAIL', 'surprise'):
            with self.subTest(terminal=terminal):
                self.ssh = FakeSSH(self.clock, terminal)
                with self.assertRaises(RuntimeError):
                    self.run_loop()
                self.assertEqual(len(self.ssh.calls), 3)

    def test_identity_hash_nonce_and_stale_reply_fail_closed(self):
        for key in ('pod_id', 'session_nonce', 'manifest_sha256', 'challenge'):
            with self.subTest(key=key):
                self.ssh = FakeSSH(self.clock)
                def exchange(request, timeout):
                    result = self.ssh(request, timeout)
                    result[key] = 'changed'
                    return result
                with self.assertRaises(RuntimeError):
                    self.run_loop(exchange)
                self.assertEqual(len(self.ssh.calls), 1)

    def test_changed_supervisor_pid_or_expired_or_extended_lease_stops(self):
        for change in ('pid', 'expired', 'extended'):
            with self.subTest(change=change):
                self.ssh = FakeSSH(self.clock)
                def exchange(request, timeout):
                    result = self.ssh(request, timeout)
                    if len(self.ssh.calls) == 2:
                        if change == 'pid':
                            result['state']['pid'] += 1
                        else:
                            seconds = -1 if change == 'expired' else 91
                            result['lease']['liveness_deadline_utc'] = (self.clock.now()+timedelta(seconds=seconds)).isoformat()
                    return result
                with self.assertRaises(RuntimeError):
                    self.run_loop(exchange)
                self.assertEqual(len(self.ssh.calls), 2)

    def test_first_transport_failure_or_interruption_is_final(self):
        for error in (RuntimeError('SSH 255'), subprocess.TimeoutExpired('ssh', 15), KeyboardInterrupt()):
            calls = []
            def exchange(request, timeout):
                calls.append(request)
                raise error
            with self.assertRaises(type(error)):
                self.run_loop(exchange)
            self.assertEqual(len(calls), 1)

    def test_monotonic_deadline_and_wall_clock_jump_stop(self):
        self.ssh.terminal = None
        with self.assertRaisesRegex(RuntimeError, 'deadline'):
            self.run_loop()
        self.assertLessEqual(self.clock.elapsed, 2100)
        self.assertEqual(sum(c[0]['action'] == 'start' for c in self.ssh.calls), 1)
        self.assertLessEqual(len(self.ssh.calls), 105)
        self.clock = Clock()
        self.config = config(self.clock)
        self.ssh = FakeSSH(self.clock)
        def exchange(request, timeout):
            result = self.ssh(request, timeout)
            self.clock.base += timedelta(hours=1)
            return result
        with self.assertRaisesRegex(RuntimeError, 'deadline'):
            self.run_loop(exchange)
        self.assertEqual(len(self.ssh.calls), 1)


class ConfigurationTests(unittest.TestCase):
    def test_fresh_receipt_go_and_paths_without_reading_key(self):
        clock = Clock()
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as folder:
            root = Path(folder)
            receipt = {'source': 'create-pod', 'created_by_this_task': True, 'id': 'freshpod',
                       'created_at': clock.now().isoformat(), 'create_request_id': 'request',
                       'create_mcp': 'MCP', 'cleanup_mcp': 'MCP', 'independent_cleanup_armed': True,
                       'local_backing_verified': True, 'vcpu': 8, 'memory_gib': 32, 'disk_gb': 80,
                       'cpu_class': 'cpu3g'}
            raw = json.dumps(receipt).encode()
            go = dict(controller.FROZEN, approved=True, scope='xattr-scratch-cold-AB-BA',
                      pod_id='freshpod', receipt_sha256=controller.sha(raw), cpu_class='cpu3g',
                      manifest_sha256='b'*64, max_builds=4, per_build_seconds=300,
                      benchmark_seconds=2100, session_nonce='a'*32,
                      pod_delete_deadline_utc=(clock.now()+timedelta(hours=1)).isoformat())
            (root/'receipt').write_bytes(raw)
            (root/'go').write_text(json.dumps(go))
            (root/'ready').write_text(json.dumps({'manifest_sha256': 'b'*64}))
            args = SimpleNamespace(host='203.0.113.1', port=12345, session='/var/tmp/weld-xattr-fresh',
                                   receipt=root/'receipt', go=root/'go', ready=root/'ready',
                                   identity=root/'DOES-NOT-EXIST.key', known_hosts=root/'known_hosts')
            result = controller.configuration(args, clock.now())
            self.assertEqual(result['receipt_sha256'], controller.sha(raw))
            self.assertIn(str(args.identity), controller.ssh_prefix(args))
            for key, value in (('max_builds', 5), ('benchmark_seconds', 2101), ('per_build_seconds', 301),
                               ('receipt_sha256', 'e'*64), ('session_nonce', 'bad'), ('pod_id', 'oldpod')):
                with self.subTest(key=key):
                    (root/'go').write_text(json.dumps(dict(go, **{key: value})))
                    with self.assertRaises(RuntimeError):
                        controller.configuration(args, clock.now())
            (root/'go').write_text(json.dumps(go))
            with self.assertRaisesRegex(RuntimeError, 'receipt'):
                controller.configuration(args, clock.now()+timedelta(minutes=21))
            args.session = '/var/tmp/weld-xattr-fresh/../other'
            with self.assertRaisesRegex(RuntimeError, 'session'):
                controller.configuration(args, clock.now())


class RemoteTests(unittest.TestCase):
    """Exercise the actual one-shot probe against fake files and a fake pulse."""
    def setUp(self):
        clock = Clock()
        self.request = dict(config(clock), action='observe', expires_utc=(clock.now()+timedelta(seconds=12)).isoformat(), challenge='challenge')
        self.state = dict(pid=123, start_ticks='456', **{k: self.request[k] for k in ('pod_id', 'session_nonce', 'deadline_utc')})
        self.request['state'] = self.state
        self.files = {}
        root = self.request['session']
        def write(name, value):
            self.files[root+'/'+name] = json.dumps(value).encode()
        self.write = write
        write('GO.json', {k: self.request[k] for k in ('pod_id', 'session_nonce')})
        write('created-pod.json', {})
        manifest = {}
        for name in ('FREEZE.json', 'harness/common.py', 'harness/pulse.py', 'harness/run.py'):
            raw = b'{}' if name == 'FREEZE.json' else b'fake sealed bytes'
            self.files[root+'/payload/'+name] = raw
            manifest[name] = controller.sha(raw)
        write('payload/PAYLOAD-SHA256.json', manifest)
        for key, name in (('go_sha256', 'GO.json'), ('receipt_sha256', 'created-pod.json'), ('manifest_sha256', 'payload/PAYLOAD-SHA256.json')):
            self.request[key] = controller.sha(self.files[root+'/'+name])
        write('controller-start.json', self.state)
        write('worker-config.json', {'pod_id': 'freshpod', 'deadline_utc': self.request['deadline_utc']})
        write('liveness.json', {'valid': True})
        self.files['/proc/123/stat'] = ('123 (python) S ' + '0 '*18 + '456 0').encode()
        files = self.files
        class FakePath(PurePosixPath):
            def read_bytes(self):
                if str(self) not in files:
                    raise FileNotFoundError(str(self))
                return files[str(self)]
            def read_text(self):
                return self.read_bytes().decode()
            def exists(self):
                return str(self) in files
            def is_symlink(self):
                return False
            def resolve(self, strict=False):
                return self
            def write_text(self, value):
                files[str(self)] = value.encode()
            def open(self, mode):
                if 'x' in mode and self.exists():
                    raise FileExistsError(str(self))
                target = str(self)
                files[target] = b''
                class Output(io.BytesIO if 'b' in mode else io.StringIO):
                    def close(stream):
                        value = stream.getvalue()
                        files[target] = value if isinstance(value, bytes) else value.encode()
                        super().close()
                return Output()
        self.fakepath = FakePath
        self.pulses = []
        def live(value, go, now):
            controller.require(value.get('valid'), 'expired lease')
        self.common = SimpleNamespace(authorize=lambda *args: None, live=live)

    def probe(self):
        with patch('pathlib.Path', self.fakepath), patch.dict(sys.modules, {'common': self.common}), \
                patch.object(sys, 'path', list(sys.path)), patch.object(sys, 'argv', list(sys.argv)), \
                patch('runpy.run_path', side_effect=lambda *a, **kw: self.pulses.append(a)):
            return controller.remote_probe(self.request)

    def test_valid_running_probes_pulse_once(self):
        self.assertEqual(self.probe()['status'], 'RUNNING')
        self.assertEqual(len(self.pulses), 1)

    def test_start_once_then_refuse_reused_session_without_pulse(self):
        self.request['action'] = 'start'
        root = self.request['session']
        for name in ('liveness.json', 'controller-start.json', 'worker-config.json'):
            del self.files[root+'/'+name]
        def pulse(*args, **kwargs):
            self.pulses.append(args)
            self.write('liveness.json', {'valid': True})
        with patch('pathlib.Path', self.fakepath), patch.dict(sys.modules, {'common': self.common}), \
                patch.object(sys, 'path', list(sys.path)), patch.object(sys, 'argv', list(sys.argv)), \
                patch('runpy.run_path', side_effect=pulse), \
                patch('subprocess.Popen', return_value=SimpleNamespace(pid=123)) as spawn:
            result = controller.remote_probe(self.request)
            self.assertEqual(result['status'], 'RUNNING')
            self.assertEqual(spawn.call_count, 1)
            self.assertIn('/payload/harness/run.py', spawn.call_args.args[0][2])
            with self.assertRaises(RuntimeError):
                controller.remote_probe(self.request)
            self.assertEqual(spawn.call_count, 1)
            self.assertEqual(len(self.pulses), 1)
            # Even removing liveness cannot make the exclusive controller marker reusable.
            del self.files[root+'/liveness.json']
            with self.assertRaises(FileExistsError):
                controller.remote_probe(self.request)
            self.assertEqual(spawn.call_count, 1)

    def test_expired_lease_hash_changed_unknown_status_and_dead_pid_never_pulse(self):
        for failure in ('lease', 'hash', 'status', 'pid', 'order', 'state', 'deadline'):
            with self.subTest(failure=failure):
                self.setUp()
                if failure == 'lease':
                    self.write('liveness.json', {'valid': False})
                elif failure == 'hash':
                    self.write('GO.json', {})
                elif failure == 'status':
                    self.write('evidence/status.json', {'status': 'UNKNOWN'})
                elif failure == 'pid':
                    del self.files['/proc/123/stat']
                elif failure == 'order':
                    self.write('evidence/build-attempts.json', [{'ordinal': 1, 'variant': 'candidate'}])
                elif failure == 'state':
                    self.write('controller-start.json', dict(self.state, pid=987))
                else:
                    self.request['deadline_utc'] = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
                with self.assertRaises(RuntimeError):
                    self.probe()
                self.assertFalse(self.pulses)

    def test_terminal_failure_never_renews(self):
        self.write('evidence/status.json', {'status': 'FAIL', 'error': 'oracle'})
        self.assertEqual(self.probe()['status'], 'FAIL')
        self.assertFalse(self.pulses)

    def test_pass_requires_four_abba_and_both_pair_probes(self):
        self.write('supervisor-status.json', {'status': 'PASS', 'accepted_builds': 4,
                   'pod_id': 'freshpod', 'manifest_sha256': self.request['manifest_sha256']})
        self.write('evidence/status.json', {'status': 'PASS', 'builds': 4})
        self.write('evidence/build-attempts.json', [{'ordinal': i+1, 'variant': v} for i, v in enumerate(controller.SEQUENCE)])
        self.write('evidence/results.json', [{'variant': v, 'case': 'cold', 'repetition': i//2} for i, v in enumerate(controller.SEQUENCE)])
        for pair in range(2):
            self.write(f'evidence/r{pair:02d}-completed.json', {'order': controller.SEQUENCE[pair*2:pair*2+2], 'mutable_output_mutation_probe': 'PASS'})
            self.write(f'evidence/pair-{pair:02d}-parity.json', dict.fromkeys(
                ('exact_all_OCI_bytes', 'cross_arm_output_mutation_and_cache_isolation', 'source_immutability'), 'PASS'))
        self.assertEqual(self.probe()['status'], 'PASS')
        self.assertFalse(self.pulses)
        self.write('evidence/pair-01-parity.json', {})
        with self.assertRaises(KeyError):
            self.probe()
        self.assertFalse(self.pulses)


class ProcessTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt' and shutil.which('ssh'), 'Windows OpenSSH regression')
    def test_real_windows_openssh_initializes_with_public_environment(self):
        # -V needs no key/network and writes to stderr. Empty stdout is parsed
        # only after exit zero; missing PROGRAMDATA instead raises SSH 255.
        with self.assertRaises(json.JSONDecodeError):
            controller.run_ssh([shutil.which('ssh'), '-V'], 5)

    def test_fake_ssh_success_failure_timeout_and_reaping(self):
        self.assertEqual(controller.run_ssh([sys.executable, '-c', 'print("{\\"ok\\":true}")'], 3), {'ok': True})
        with self.assertRaisesRegex(RuntimeError, 'sentinel failure'):
            controller.run_ssh([sys.executable, '-c', 'import sys;print("sentinel failure",file=sys.stderr);raise SystemExit(255)'], 3)
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as folder:
            marker = Path(folder)/'orphan'
            code = 'import time,pathlib;time.sleep(0.8);pathlib.Path('+repr(str(marker))+').touch()'
            with self.assertRaisesRegex(RuntimeError, 'timeout'):
                controller.run_ssh([sys.executable, '-c', code], 0.1)
            time.sleep(1)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows kill-on-close Job test')
    def test_forcibly_killed_controller_cannot_leave_ssh_renewer(self):
        with tempfile.TemporaryDirectory(dir=SCRIPT.parent) as folder:
            root = Path(folder)
            ready, leaked = root/'ready', root/'leaked'
            child = ('import time,pathlib;pathlib.Path('+repr(str(ready))+').touch();'
                     'time.sleep(1.5);pathlib.Path('+repr(str(leaked))+').touch()')
            parent = ('import runpy,sys;ns=runpy.run_path('+repr(str(SCRIPT))+');'
                      'ns["run_ssh"]([sys.executable,"-c",'+repr(child)+'],10)')
            process = subprocess.Popen([sys.executable, '-B', '-c', parent])
            try:
                end = time.monotonic()+5
                while not ready.exists() and process.poll() is None and time.monotonic() < end:
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), 'fake SSH did not start')
                process.kill()
                process.wait(timeout=3)
                time.sleep(1.7)
                self.assertFalse(leaked.exists(), 'SSH survived controller termination')
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)


if __name__ == '__main__':
    unittest.main()
