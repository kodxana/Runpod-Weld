"""Opt-in, bounded diagnostics for an unchanged D-state process sample.

Consumes existing sampler output; never reads payloads, fd targets, arguments,
or stacks. Use one observer per build. Observations are not an atomic snapshot.
"""
import math
from pathlib import Path
import re
import time


class ProcStallObserver:
    MAX_CAPTURES = 16
    STALL_SECONDS = 1.0
    MAX_SAMPLE_GAP = 1.5

    def __init__(self, proc_root=Path('/proc')):
        self.proc_root = Path(proc_root)
        self._previous = None
        self._since = None
        self._last_capture = -math.inf
        self._captures = 0

    @staticmethod
    def _identity(pid, raw):
        if not isinstance(raw, str) or len(raw) > 8192:
            raise ValueError('invalid stat')
        prefix, fields = raw.rsplit(')', 1)
        if int(prefix.split('(', 1)[0]) != pid:
            raise ValueError('different pid')
        fields = fields.split()
        start = int(fields[19])
        ticks = tuple(int(fields[i]) for i in (11, 12, 13, 14))
        if start < 0 or any(n < 0 for n in ticks):
            raise ValueError('negative counter')
        return start, fields[0], ticks

    def _read(self, pid, name, cap):
        try:
            with (self.proc_root / str(pid) / name).open('rb') as stream:
                data = stream.read(cap + 1)
            if len(data) > cap:
                return {'status': 'oversized'}
            return data.decode('ascii').strip()
        except OSError as error:
            return {'status': 'unavailable', 'errno': error.errno}
        except UnicodeError:
            return {'status': 'malformed'}

    def _capture(self, pid, expected_start):
        # Check start time on both sides to avoid attributing a reused PID.
        before = self._read(pid, 'stat', 8192)
        if isinstance(before, dict):
            return {'status': 'identity_unavailable', 'detail': before}
        try:
            if self._identity(pid, before)[0] != expected_start:
                return {'status': 'identity_changed'}
        except (ValueError, IndexError):
            return {'status': 'identity_unavailable'}
        wchan = self._read(pid, 'wchan', 256)
        if isinstance(wchan, str):
            wchan = ({'status': 'observed', 'symbol': wchan}
                     if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,127}', wchan)
                     else {'status': 'unavailable' if wchan == '0' else 'malformed'})
        syscall = self._read(pid, 'syscall', 1024)
        if isinstance(syscall, str):
            first = syscall.split()[0] if syscall.split() else ''
            if syscall == 'running':
                syscall = {'status': 'running'}
            elif first == '-1':
                syscall = {'status': 'not_in_syscall'}
            elif re.fullmatch(r'[0-9]{1,10}', first) and int(first) <= 2**31 - 1:
                syscall = {'status': 'observed', 'number': int(first)}
            else:
                syscall = {'status': 'malformed'}
        after = self._read(pid, 'stat', 8192)
        try:
            if self._identity(pid, after)[0] != expected_start:
                return {'status': 'identity_changed'}
        except (ValueError, IndexError):
            return {'status': 'identity_unavailable'}
        return {'status': 'sampled', 'wchan': wchan, 'syscall': syscall}

    def observe(self, pid, sample):
        """Return a redacted diagnostic or None; unsupported samples reset detection.

        sample uses the existing cold sampler's seconds, stat and io fields.
        No diagnostic failure changes the builder's result or acceptance checks.
        """
        if self._captures >= self.MAX_CAPTURES:
            return None
        try:
            if type(pid) is not int or pid <= 0:
                raise ValueError('invalid pid')
            seconds = sample['seconds']
            if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0:
                raise ValueError('invalid elapsed time')
            start, state, ticks = self._identity(pid, sample['stat'])
            raw_io = sample['io']
            if not isinstance(raw_io, str) or len(raw_io) > 1024:
                raise ValueError('invalid io')
            io = dict(line.split(':', 1) for line in raw_io.splitlines())
            counters = tuple(int(io[key]) for key in
                             ('rchar', 'wchar', 'syscr', 'syscw', 'read_bytes',
                              'write_bytes', 'cancelled_write_bytes'))
            if state != 'D' or any(n < 0 for n in counters):
                raise ValueError('not an unchanged disk wait')
        except (ValueError, KeyError, IndexError, TypeError, AttributeError, OverflowError):
            self._previous = self._since = None
            return None
        signature = (pid, start, ticks, counters)
        if (self._previous is None or self._previous[1] != signature
                or not 0 < seconds - self._previous[0] <= self.MAX_SAMPLE_GAP):
            self._since = seconds
        self._previous = (seconds, signature)
        if seconds - self._since < self.STALL_SECONDS or seconds - self._last_capture < 1:
            return None
        self._captures += 1
        self._last_capture = seconds
        began = time.monotonic()
        diagnostic = self._capture(pid, start)
        return {'sample_seconds': seconds, 'unchanged_since_seconds': self._since,
                'capture_seconds': time.monotonic() - began, **diagnostic}
