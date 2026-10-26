#!/usr/bin/env python3
"""Collect exact corresponding sources. Requires matching deb-src repositories."""
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    args = parser.parse_args()
    out = args.artifacts.resolve()
    info = json.loads((out/'build-info.json').read_text())
    repo = Path(__file__).resolve().parent.parent
    os.chdir(repo)
    with tempfile.TemporaryDirectory(prefix='weld-sources-') as directory:
        root = Path(directory)/f'rpweld-{info["version"]}-sources'
        app = root/'weld'
        app.mkdir(parents=True)
        archive = subprocess.run(['git', 'archive', info['commit']], check=True, stdout=subprocess.PIPE).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(app, filter='data')
        config = subprocess.check_output(['cargo', 'vendor', '--locked', str(app/'vendor')], text=True)
        config = config.replace(str(app/'vendor'), 'vendor')
        (app/'.cargo').mkdir(exist_ok=True)
        (app/'.cargo/config.toml').write_text(config)
        sources = root/'distribution'
        sources.mkdir()
        for source, version in sorted({(p['source'], p['source_version']) for p in info['packages']}):
            subprocess.run(['apt-get', 'source', '--download-only', '--only-source', f'{source}={version}'],
                           cwd=sources, check=True)
        (root/'README.txt').write_text(
            'Exact sources for this release. Weld dependencies are vendored in weld/vendor.\n'
            'Use Rust 1.90.0 and RUSTFLAGS="-C target-feature=+crt-static" with\n'
            'cargo build --offline --locked --release --target x86_64-unknown-linux-gnu.\n'
            'Distribution source packages include upstream source and Debian/Ubuntu patches.\n'
            'Extract a .dsc with dpkg-source -x; debian/rules and debian/control contain\n'
            'the distribution build instructions and build dependencies. Private backend\n'
            'shared libraries are replaceable; no signature restricts modified versions.\n'
            'Weld is not a security sandbox and does not apply setuid bits.\n')
        (root/'build-info.json').write_text(json.dumps(info, indent=2)+'\n')
        target = out/f'rpweld-{info["version"]}-sources.tar.xz'
        assert not target.exists(), 'refusing to replace source archive'
        subprocess.run(['tar', '--sort=name', f'--mtime=@{info["source_date_epoch"]}', '--owner=0', '--group=0',
                        '--numeric-owner', '-C', directory, '-cJf', str(target), root.name], check=True)
        with target.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        with (out/'SHA256SUMS').open('a') as stream:
            stream.write(f'{checksum}  {target.name}\n')


if __name__ == '__main__':
    main()
