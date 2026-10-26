#!/usr/bin/env python3
"""Offline installer/runtime smoke. Run inside disposable Linux containers."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--weld', type=Path, required=True)
    parser.add_argument('--busybox', type=Path, required=True)
    args = parser.parse_args()
    weld = str(args.weld.resolve())
    assert not Path('/usr/bin/skopeo').exists(), 'test must run without system Skopeo'
    assert '0.1.0 (build ' in subprocess.check_output([weld, '--version'], text=True)
    with tempfile.TemporaryDirectory(prefix='weld-offline-') as directory:
        root = Path(directory)
        env = dict(os.environ, HOME=str(root), RPWELD_HOME=str(root/'store'))
        context = root/'context'
        context.mkdir()
        (context/'busybox').write_bytes(args.busybox.read_bytes())
        (context/'busybox').chmod(0o755)
        (context/'message').write_text('offline-package\n')
        (context/'Dockerfile').write_text('''FROM scratch AS base
COPY busybox /bin/busybox
COPY busybox /bin/sh
SHELL ["/bin/busybox", "sh", "-c"]
RUN /bin/busybox mkdir -p /tmp && /bin/busybox chmod 1777 /tmp
FROM base
COPY message /message
USER 65534:65534
RUN /bin/busybox test "$(/bin/busybox id -u)" = 65534 && /bin/busybox cat /message > /tmp/result
CMD ["/bin/busybox", "cat", "/tmp/result"]
''')
        output = root/'image'
        subprocess.run([weld, 'build', '--no-cache', '--no-host-dns', '-t', 'offline:check',
                        '--output', str(output), '--work-dir', str(root/'work'), str(context)],
                       env=env, check=True, timeout=120)
        index = json.loads((output/'index.json').read_text())
        def blob(desc):
            data = (output/'blobs/sha256'/desc['digest'].split(':')[1]).read_bytes()
            assert len(data) == desc['size'] and hashlib.sha256(data).hexdigest() == desc['digest'].split(':')[1]
            return data
        manifest = json.loads(blob(index['manifests'][0]))
        assert len(manifest['layers']) >= 2, 'layered output must preserve the parent prefix'
        config = json.loads(blob(manifest['config']))
        assert config['config']['User'] == '65534:65534'
        assert config['config']['Cmd'] == ['/bin/busybox', 'cat', '/tmp/result']
        found = None
        for layer, diff in zip(manifest['layers'], config['rootfs']['diff_ids'], strict=True):
            data = blob(layer)
            assert 'sha256:'+hashlib.sha256(data).hexdigest() == diff
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                for member in tar:
                    if member.name.lstrip('./') == 'tmp/result':
                        found = tar.extractfile(member).read()
                        assert member.uid == member.gid == 65534
        assert found == b'offline-package\n'
        subprocess.run([weld, 'doctor', '--json'], env=env, check=True, stdout=subprocess.DEVNULL)
    print('PASS offline bundled install, layered build, real nonroot RUN and OCI contents')


if __name__ == '__main__':
    main()
