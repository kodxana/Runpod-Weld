#!/usr/bin/env python3
"""Opt-in runner output regression using an Ubuntu/Python OCI layout, as root."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--binary', required=True)
p.add_argument('--layout', required=True)
a = p.parse_args()
with tempfile.TemporaryDirectory(prefix='weld-output-') as temporary:
    root = Path(temporary)
    for name, verbose, failure in [('normal', False, False), ('verbose', True, False), ('failure', False, True)]:
        context = root/name
        context.mkdir()
        command = "python3 -c 'import os,subprocess; assert not any(k.startswith(\"RPWELD_\") for k in os.environ); subprocess.run([\"hello\"],check=True)'"
        (context/'Dockerfile').write_text('FROM testbase\nRUN ' + command + '\nRUN ' + ('exit 7' if failure else command) + '\n')
        argv = [a.binary, 'build', '--base', 'testbase='+a.layout,
                '--output', str(root/(name+'-image')), '--work-dir', str(root/(name+'-work')),
                '--max-rootfs-bytes', '2147483648', '--max-layer-bytes', '2147483648',
                '--metadata-budget', '67108864']
        if verbose:
            argv.append('--verbose')
        result = subprocess.run(argv+[str(context)], capture_output=True, text=True, timeout=120, cwd='/')
        output = result.stdout + result.stderr
        assert (result.returncode != 0) == failure, output
        assert output.count('Note: Weld runs trusted Dockerfiles only;') == 1, output
        assert 'trace_root:' not in output, output
        assert ('debug: close_range fallback' in output) == verbose, output
        assert 'Hello, world!' in output, output
        if failure:
            assert 'RUN worker failed' in output, output
            assert not (root/(name+'-image')).exists()
        print('PASS runner output: '+name, flush=True)