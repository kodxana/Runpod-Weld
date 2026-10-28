"""Portable diagnostic tests; Linux-only sampler lifecycle checks."""
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from proc_stall import ProcStallObserver


def sample(seconds, state='D', ticks=0, start=123, io=0, pid=42):
    fields = [state] + ['0'] * 51
    fields[11], fields[19] = str(ticks), str(start)
    return {'seconds': seconds, 'stat': f'{pid} (name with ) spaces) ' + ' '.join(fields),
            'io': '\n'.join(f'{key}: {io}' for key in
                            ('rchar', 'wchar', 'syscr', 'syscw', 'read_bytes',
                             'write_bytes', 'cancelled_write_bytes'))}


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='weld-stall-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / '42'
        self.proc.mkdir()
        (self.proc / 'stat').write_text(sample(0)['stat'])
        (self.proc / 'wchan').write_text('folio_wait_bit_common\n')
        (self.proc / 'syscall').write_text('74 0xfeedsecret 0xdeadbeef 0 0 0 0 0x1234 0x5678\n')
        self.observer = ProcStallObserver(self.root)

    def trigger(self):
        self.assertIsNone(self.observer.observe(42, sample(0)))
        self.assertIsNone(self.observer.observe(42, sample(.5)))
        return self.observer.observe(42, sample(1))

    def test_trigger_redacts_arguments_and_addresses(self):
        result = self.trigger()
        self.assertEqual(result['syscall'], {'status': 'observed', 'number': 74})
        self.assertEqual(result['wchan']['symbol'], 'folio_wait_bit_common')
        self.assertGreaterEqual(result['capture_seconds'], 0)
        self.assertNotIn('0x', json.dumps(result))
        self.assertNotIn('secret', json.dumps(result))

    def test_progress_state_identity_and_gaps_reset(self):
        for changed in (sample(.5, ticks=1), sample(.5, io=1), sample(.5, state='R'),
                        sample(.5, start=124), sample(3), {}):
            with self.subTest(changed=changed):
                self.observer = ProcStallObserver(self.root)
                self.observer.observe(42, sample(0))
                self.observer.observe(42, changed)
                self.assertIsNone(self.observer.observe(42, sample(1)))
                self.assertIsNone(self.observer.observe(42, sample(1.5)))
                self.assertIsNotNone(self.observer.observe(42, sample(2)))

    def test_nonincreasing_time_starts_a_new_observation_window(self):
        for seconds in (0, .5, .5, 1):
            self.assertIsNone(self.observer.observe(42, sample(seconds)))
        self.assertIsNotNone(self.observer.observe(42, sample(1.5)))

    def test_rate_and_total_capture_caps(self):
        results = [r for n in range(100) if (r := self.observer.observe(42, sample(n / 2)))]
        self.assertEqual(len(results), 16)
        self.assertEqual([r['sample_seconds'] for r in results], list(range(1, 17)))
        self.assertLess(len(json.dumps(results)), 8192)

    def test_unavailable_and_oversized_reads_are_diagnostics(self):
        (self.proc / 'wchan').unlink()
        (self.proc / 'syscall').write_bytes(b'x' * 1025)
        result = self.trigger()
        self.assertEqual(result['wchan'], {'status': 'unavailable', 'errno': errno.ENOENT})
        self.assertEqual(result['syscall'], {'status': 'oversized'})
        self.observer = ProcStallObserver(self.root)
        original = Path.open
        def denied(path, *args, **kwargs):
            if path.name == 'syscall':
                raise PermissionError(errno.EACCES, 'private text must not leak')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', denied):
            result = self.trigger()
        self.assertEqual(result['syscall'], {'status': 'unavailable', 'errno': errno.EACCES})
        self.assertNotIn('private', json.dumps(result))

    def test_pid_reuse_and_process_exit_discard_attribution(self):
        (self.proc / 'stat').write_text(sample(0, start=456)['stat'])
        self.assertEqual(self.trigger()['status'], 'identity_changed')
        self.observer = ProcStallObserver(self.root)
        (self.proc / 'stat').unlink()
        self.assertEqual(self.trigger()['status'], 'identity_unavailable')

    def test_identity_rechecked_after_capture(self):
        original = self.observer._read
        def replace(pid, name, cap):
            data = original(pid, name, cap)
            if name == 'syscall':
                (self.proc / 'stat').write_text(sample(0, start=456)['stat'])
            return data
        with patch.object(self.observer, '_read', replace):
            result = self.trigger()
        self.assertEqual(result['status'], 'identity_changed')
        self.assertNotIn('syscall', result)

    def test_syscall_status_and_bad_symbols(self):
        for raw, status in [('running', 'running'), ('-1 0xbeef 0xfeed', 'not_in_syscall'),
                            ('nonsense 0xbeef', 'malformed'), ('', 'malformed')]:
            with self.subTest(raw=raw):
                self.observer = ProcStallObserver(self.root)
                (self.proc / 'syscall').write_text(raw)
                (self.proc / 'wchan').write_text('0xabcdef')
                result = self.trigger()
                self.assertEqual(result['syscall']['status'], status)
                self.assertEqual(result['wchan']['status'], 'malformed')

    def test_bad_samples_never_read_proc(self):
        malformed = [{}, None, sample(float('nan')), sample(float('inf')), sample(-1),
                     dict(sample(0), stat='invalid'), dict(sample(0), io='x' * 1025),
                     dict(sample(0), io={'unavailable_errno': 13}), sample(0, pid=43)]
        with patch.object(self.observer, '_read', side_effect=AssertionError('unexpected read')):
            for value in malformed:
                self.assertIsNone(self.observer.observe(42, value))


@unittest.skipUnless(sys.platform == 'linux', 'Linux procfs and wait4 required')
class SamplerTests(unittest.TestCase):
    def test_live_proc_capture_is_redacted(self):
        import cold_metrics
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            observer = ProcStallObserver()
            raw = cold_metrics.proc_sample(process.pid)
            start = observer._identity(process.pid, raw['stat'])[0]
            result = observer._capture(process.pid, start)
            self.assertEqual(result['status'], 'sampled')
            self.assertNotIn('0x', json.dumps(result))
            self.assertLess(len(json.dumps(result)), 1024)
        finally:
            process.kill()
            process.wait(timeout=5)

    def test_observer_is_optional_and_tree_walks_are_outside_child(self):
        import cold_metrics
        with tempfile.TemporaryDirectory(prefix='weld-cold-metrics-') as directory:
            root = Path(directory)
            child_active = False
            real_spawn, real_wait4 = subprocess.Popen, os.wait4
            def spawn(*args, **kwargs):
                nonlocal child_active
                child_active = True
                return real_spawn(*args, **kwargs)
            def reap(*args):
                nonlocal child_active
                value = real_wait4(*args)
                child_active = False
                return value
            def usage(*_):
                self.assertFalse(child_active, 'tree walk inside timed child interval')
                return {'allocated_bytes': 0}
            for observer in (None, ProcStallObserver()):
                seen = []
                if observer is not None:
                    original = observer.observe
                    def record(pid, value):
                        seen.append(value)
                        return original(pid, value)
                    observer.observe = record
                with patch('metrics.usage', usage), patch.object(cold_metrics.subprocess, 'Popen', spawn), \
                        patch.object(cold_metrics.os, 'wait4', reap):
                    result = cold_metrics.measure([sys.executable, '-c', 'import time; time.sleep(.6)'],
                        dict(os.environ), [root], root / str(observer is None), stall_observer=observer)
                self.assertEqual(result['returncode'], 0)
                self.assertEqual(result['allocation_sampling'], 'disabled')
                if observer is None:
                    self.assertNotIn('stall_diagnostics', result)
                else:
                    self.assertEqual(result['stall_diagnostics'], [])
                    self.assertTrue(seen)
                    self.assertEqual(seen, result['proc_samples'][:-1])

    def test_timeout_reaps_and_retains_failure_evidence(self):
        import cold_metrics
        with tempfile.TemporaryDirectory(prefix='weld-cold-timeout-') as directory:
            root = Path(directory)
            with self.assertRaises(AssertionError):
                cold_metrics.measure([sys.executable, '-c', 'import time; time.sleep(30)'],
                    dict(os.environ), [root], root / 'logs', timeout=.1,
                    stall_observer=ProcStallObserver())
            result = json.loads((root / 'logs/measurement.json').read_text())
            self.assertTrue(result['timed_out'])
            self.assertEqual(result['returncode'], -9)
            self.assertNotIn('cleanup_error', result)


if __name__ == '__main__':
    unittest.main()
