#!/usr/bin/env python3
"""Offline installer/runtime smoke. Run inside disposable Linux containers."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_install(weld, info):
    prefix = weld.parent.parent
    metadata = prefix/'share/doc/rpweld/build-info.json'
    assert json.loads(metadata.read_text()) == info, 'installed metadata differs from artifact'
    executables = {'bin/rpweld', 'lib/rpweld/skopeo', 'lib/rpweld/ld-linux-x86-64.so.2'}
    for name, checksum in info['files'].items():
        path = prefix/name
        assert path.is_relative_to(prefix) and '..' not in path.parts
        assert path.is_file() and not path.is_symlink(), name
        assert digest(path) == checksum, f'installed payload hash mismatch: {name}'
        assert stat.S_IMODE(path.stat().st_mode) == (0o755 if name in executables else 0o644), name
        for parent in path.parents:
            if not parent.is_relative_to(prefix):
                break
            assert not parent.is_symlink() and stat.S_IMODE(parent.stat().st_mode) == 0o755, parent
    assert not metadata.is_symlink() and stat.S_IMODE(metadata.stat().st_mode) == 0o644
    expected = f'rpweld {info["version"]} (build {info["commit"]})'
    assert subprocess.check_output([str(weld), '--version'], text=True).strip() == expected
    # The package must remain executable/readable to ordinary users as well as root.
    assert subprocess.check_output([str(weld), '--version'], text=True,
                                   user=65534, group=65534, extra_groups=[]).strip() == expected
    backend = prefix/'lib/rpweld'
    loader = [str(backend/'ld-linux-x86-64.so.2'), '--inhibit-cache', '--library-path', str(backend)]
    listed = subprocess.check_output([*loader, '--list', str(backend/'skopeo')], text=True)
    for line in listed.splitlines():
        if '=>' in line:
            assert str(backend) + '/' in line, listed
    assert subprocess.check_output([*loader, str(backend/'skopeo'), '--version'], text=True).strip() == info['skopeo']


def read_image(output, compression, secret):
    index = json.loads((output/'index.json').read_text())

    def blob(desc):
        algorithm, checksum = desc['digest'].split(':')
        assert algorithm == 'sha256'
        data = (output/'blobs/sha256'/checksum).read_bytes()
        assert len(data) == desc['size'] and hashlib.sha256(data).hexdigest() == checksum
        assert secret not in data
        return data

    assert len(index['manifests']) == 1
    manifest = json.loads(blob(index['manifests'][0]))
    assert len(manifest['layers']) >= 2, 'layered output must preserve the parent prefix'
    config = json.loads(blob(manifest['config']))
    assert config['rootfs']['type'] == 'layers'
    assert sum(not item.get('empty_layer', False) for item in config['history']) == len(manifest['layers'])
    files = {}
    for layer, diff in zip(manifest['layers'], config['rootfs']['diff_ids'], strict=True):
        data = blob(layer)
        media = 'application/vnd.oci.image.layer.v1.tar'
        assert layer['mediaType'] == media + ('+gzip' if compression == 'gzip' else '')
        raw = gzip.decompress(data) if compression == 'gzip' else data
        assert 'sha256:'+hashlib.sha256(raw).hexdigest() == diff
        assert secret not in raw and b'package-cache-only' not in raw
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
            for member in tar:
                name = member.name.removeprefix('./').rstrip('/')
                assert name != 'cache' and not name.startswith('cache/'), name
                assert name != 'run/secrets/token', name
                if member.isfile():
                    files[name] = (tar.extractfile(member).read(), member.uid, member.gid)
    return config, files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--weld', type=Path, required=True)
    parser.add_argument('--busybox', type=Path, required=True)
    parser.add_argument('--build-info', type=Path, required=True)
    args = parser.parse_args()
    weld = args.weld.resolve()
    assert not Path('/usr/bin/skopeo').exists(), 'test must run without system Skopeo'
    verify_install(weld, json.loads(args.build_info.read_text()))
    weld = str(weld)
    with tempfile.TemporaryDirectory(prefix='weld-offline-') as directory:
        root = Path(directory)
        env = dict(os.environ, HOME=str(root), RPWELD_HOME=str(root/'store'))
        context = root/'context'
        context.mkdir()
        (context/'busybox').write_bytes(args.busybox.read_bytes())
        (context/'busybox').chmod(0o755)
        (context/'message').write_text('offline-package\n')
        secret = b'package-secret-canary-78231\n'
        secret_path = root/'secret'
        secret_path.write_bytes(secret)
        secret_path.chmod(0o600)
        (context/'Dockerfile').write_text('''FROM scratch AS base
COPY busybox /bin/busybox
COPY busybox /bin/sh
SHELL ["/bin/busybox", "sh", "-c"]
RUN /bin/busybox mkdir -p /tmp && /bin/busybox chmod 1777 /tmp
FROM base
COPY message /message
RUN --mount=type=cache,id=offline,target=/cache set -eu; count=0; if [ -f /cache/count ]; then count=$(/bin/busybox cat /cache/count); fi; echo $((count + 1)) > /cache/count; echo package-cache-only > /cache/private; /bin/busybox cat /cache/count > /tmp/cache-count
USER 65534:65534
RUN --mount=type=secret,id=token,required=true,uid=65534,gid=65534 /bin/busybox test "$(/bin/busybox stat -c %a /run/secrets/token)" = 400 && /bin/busybox cat /run/secrets/token
RUN /bin/busybox test ! -e /run/secrets/token && /bin/busybox test ! -e /cache
RUN /bin/busybox test "$(/bin/busybox id -u)" = 65534 && /bin/busybox cat /message > /tmp/result
CMD ["/bin/busybox", "cat", "/tmp/result"]
''')
        checkpoints = None
        for case, compression, count in [('cold', None, 1), ('warm', None, 1),
                                         ('gzip-cold', 'gzip', 2), ('gzip-warm', 'gzip', 2),
                                         ('no-cache', 'gzip', 3)]:
            output = root/('image-'+case)
            command = [weld, 'build', '--no-host-dns', '-t', 'offline:check',
                       '--secret', f'id=token,src={secret_path}', '--output', str(output),
                       '--work-dir', str(root/('work-'+case))]
            if compression:
                command += ['--compression', compression]
            if case == 'no-cache':
                command += ['--no-cache']
            result = subprocess.run([*command, str(context)], env=env, capture_output=True, timeout=120)
            assert result.returncode == 0, result.stderr.decode(errors='replace')
            log = result.stdout + result.stderr
            assert secret not in log
            if case in ('warm', 'gzip-warm'):
                assert b'CACHED instruction' in log and b'stdout/stderr suppressed' not in log
            else:
                assert b'CACHED' not in log and b'stdout/stderr suppressed' in log
            config, files = read_image(output, compression, secret)
            assert config['config']['User'] == '65534:65534'
            assert config['config']['Cmd'] == ['/bin/busybox', 'cat', '/tmp/result']
            assert files['tmp/result'] == (b'offline-package\n', 65534, 65534)
            assert files['tmp/cache-count'][0] == f'{count}\n'.encode()
            current = {str(p.relative_to(root/'store')): digest(p)
                       for p in (root/'store/cache-v2').rglob('*') if p.is_file()}
            assert current, 'managed instruction checkpoints were not published'
            if checkpoints is not None:
                assert all(current.get(name) == checksum for name, checksum in checkpoints.items()), 'existing checkpoint changed'
                # Compression participates in instruction identity; its first build adds entries.
                if case != 'gzip-cold':
                    assert current == checkpoints, 'warm/no-cache build changed checkpoints'
            checkpoints = current
            assert (root/'store/run-cache-v1/owner.json').is_file()
            print(f'PASS {case}: layered OCI, diff IDs, nonroot RUN, secret exclusion, package cache', flush=True)
        subprocess.run([weld, 'doctor', '--json'], env=env, check=True, stdout=subprocess.DEVNULL)
    print('PASS offline install hashes/version/permissions, private backend, managed checkpoints and gzip')


if __name__ == '__main__':
    main()
