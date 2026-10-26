#!/usr/bin/env python3
"""Package a tested static Weld and the distribution Skopeo ELF dependency closure.

Run on Ubuntu 24.04 amd64. No network access or code downloads in this step.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def copy(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def dependencies(binary):
    output = run('ldd', str(binary))
    assert 'not found' not in output, output
    result = {Path('/usr/bin/skopeo')}
    for line in output.splitlines():
        match = re.search(r'(?:=>\s+)?(/\S+)\s+\(', line)
        if match:
            result.add(Path(match.group(1)))
    assert any(p.name == 'ld-linux-x86-64.so.2' for p in result), output
    return sorted(result)


def package_owner(path):
    # Ubuntu's merged-/usr layout may register either spelling.
    for name in [str(path), str(path.resolve()), '/usr' + str(path)]:
        found = subprocess.run(['dpkg-query', '-S', name], text=True, capture_output=True)
        if found.returncode == 0:
            owners = {line.split(': ', 1)[0] for line in found.stdout.splitlines()
                      if not line.startswith('diversion ')}
            if not owners:
                continue
            assert len(owners) == 1, owners
            return owners.pop()
    raise RuntimeError(f'No distribution package owns {path}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    os.chdir(repo)
    version = tomllib.loads((repo/'Cargo.toml').read_text())['package']['version']
    assert re.fullmatch(r'\d+\.\d+\.\d+', version), 'release version must be X.Y.Z'
    commit = run('git', 'rev-parse', 'HEAD')
    assert re.fullmatch('[0-9a-f]{40}', commit)
    assert run('dpkg', '--print-architecture') == 'amd64'
    assert args.binary.is_file()
    headers = run('readelf', '-l', str(args.binary))
    dynamic = run('readelf', '-d', str(args.binary))
    assert 'INTERP' not in headers and '(NEEDED)' not in dynamic, 'Weld must be static'
    assert run(str(args.binary.resolve()), '--version') == f'rpweld {version} (build {commit})'
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', run('git', 'show', '-s', '--format=%ct', 'HEAD')))
    os.environ['SOURCE_DATE_EPOCH'] = str(epoch)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = [f'rpweld-{version}-linux-amd64.tar.gz', f'rpweld_{version}_amd64.deb',
             'build-info.json', 'SHA256SUMS']
    assert not any((out/name).exists() for name in names), 'refusing to replace release artifacts'
    with tempfile.TemporaryDirectory(prefix='weld-package-') as tmp:
        stage = Path(tmp)/f'rpweld-{version}-linux-amd64'
        backend = stage/'lib/rpweld'
        doc = stage/'share/doc/rpweld'
        notices = doc/'third-party'
        copy(args.binary, stage/'bin/rpweld', 0o755)
        paths = dependencies(Path('/usr/bin/skopeo'))
        packages = {'ca-certificates', package_owner(Path('/usr/lib/x86_64-linux-gnu/libc.a')),
                    package_owner(Path(run('cc', '-print-libgcc-file-name')))}
        for path in paths:
            copy(path, backend/path.name, 0o755 if path.name in ('skopeo', 'ld-linux-x86-64.so.2') else 0o644)
            packages.add(package_owner(path))
        copy('/etc/ssl/certs/ca-certificates.crt', backend/'ca-certificates.crt')
        copy(repo/'packaging/policy.json', backend/'policy.json')
        components = []
        for package in sorted(packages):
            fields = run('dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}', package).split('\t')
            name, binary_version, source, source_version = fields
            components.append(dict(name=name, version=binary_version, source=source, source_version=source_version))
            copy(Path('/usr/share/doc')/name.split(':')[0]/'copyright', notices/'debian'/name/'copyright')
        shutil.copytree('/usr/share/common-licenses', notices/'common-licenses', symlinks=False)
        metadata = json.loads(run('cargo', 'metadata', '--offline', '--locked', '--format-version=1'))
        crates = []
        for crate in metadata['packages']:
            if crate['source'] is None:
                continue
            crates.append({k: crate[k] for k in ('name', 'version', 'license', 'source')})
            crate_dir = Path(crate['manifest_path']).parent
            for path in crate_dir.rglob('*'):
                if path.is_file() and re.match(r'(?i)(licen[sc]e|copying|copyright|notice)', path.name):
                    copy(path, notices/'rust'/(crate['name']+'-'+crate['version'])/path.relative_to(crate_dir))
        rust_doc = Path(run('rustc', '--print', 'sysroot'))/'share/doc/rust'
        for name in ['COPYRIGHT.html', 'COPYRIGHT-library.html']:
            copy(rust_doc/name, notices/'rust-toolchain'/name)
        shutil.copytree(rust_doc/'licenses', notices/'rust-toolchain/licenses', symlinks=False)
        copy(repo/'README.md', doc/'README.md')
        copy(repo/'LICENSE', doc/'copyright')
        shutil.copytree(repo/'docs', doc/'docs', ignore=shutil.ignore_patterns('planning'))
        copy(repo/f'docs/releases/v{version}.md', doc/'RELEASE-NOTES.md')
        for path in stage.rglob('*'):
            assert not path.is_symlink(), f'unexpected release symlink: {path}'
            if path.is_dir():
                path.chmod(0o755)
            elif path not in (stage/'bin/rpweld', backend/'skopeo', backend/'ld-linux-x86-64.so.2'):
                path.chmod(0o644)
        info = dict(version=version, commit=commit, target='x86_64-unknown-linux-gnu', crt_static=True,
                    rustc=run('rustc', '-Vv'), skopeo=run('/usr/bin/skopeo', '--version'),
                    source_date_epoch=epoch, distribution=Path('/etc/os-release').read_text(),
                    packages=components, crates=crates,
                    files={str(p.relative_to(stage)): digest(p) for p in sorted(stage.rglob('*')) if p.is_file()})
        (doc/'build-info.json').write_text(json.dumps(info, indent=2)+'\n')
        # ld.so must resolve every shared object inside the package, not the build host.
        listed = run(str(backend/'ld-linux-x86-64.so.2'), '--inhibit-cache', '--library-path', str(backend), '--list', str(backend/'skopeo'))
        for line in listed.splitlines():
            if '=>' in line:
                assert str(backend) in line, listed
        assert run(str(backend/'ld-linux-x86-64.so.2'), '--inhibit-cache', '--library-path', str(backend), str(backend/'skopeo'), '--version') == info['skopeo']
        # Fixed ownership, mtimes and order; gzip has no original filename/time.
        tar = subprocess.Popen(['tar', '--sort=name', f'--mtime=@{epoch}', '--owner=0', '--group=0', '--numeric-owner', '-C', tmp, '-cf', '-', stage.name], stdout=subprocess.PIPE)
        with (out/names[0]).open('xb') as stream:
            subprocess.run(['gzip', '-n', '-9'], stdin=tar.stdout, stdout=stream, check=True)
        tar.stdout.close()
        assert tar.wait() == 0
        deb = Path(tmp)/'deb'
        (deb/'DEBIAN').mkdir(parents=True)
        shutil.copytree(stage, deb/'usr')
        checksums = []
        for path in sorted((deb/'usr').rglob('*')):
            if path.is_file():
                with path.open('rb') as stream:
                    checksums.append(f'{hashlib.file_digest(stream, "md5").hexdigest()}  {path.relative_to(deb)}\n')
        (deb/'DEBIAN/md5sums').write_text(''.join(checksums))
        size = (sum(p.stat().st_size for p in stage.rglob('*') if p.is_file())+1023)//1024
        (deb/'DEBIAN/control').write_text(f'''Package: rpweld
Version: {version}
Section: devel
Priority: optional
Architecture: amd64
Maintainer: Runpod Weld contributors <16674412+kodxana@users.noreply.github.com>
Installed-Size: {size}
Homepage: https://github.com/kodxana/Runpod-Weld
Description: Linux OCI image builder with an offline registry backend bundle
 Includes Weld, Skopeo, private shared libraries and CA certificates.
 Builds trusted Dockerfiles without a Docker daemon. Linux amd64 only.
''')
        # No maintainer scripts, downloads, system policy changes, or user-data removal.
        for path in sorted(deb.rglob('*'), reverse=True):
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '--build', str(deb), str(out/names[1])], check=True)
        copy(doc/'build-info.json', out/'build-info.json')
    (out/'SHA256SUMS').write_text(''.join(f'{digest(out/name)}  {name}\n' for name in names[:-1]))
    print(json.dumps({'version': version, 'commit': commit, 'artifacts': names}, indent=2))


if __name__ == '__main__':
    main()
