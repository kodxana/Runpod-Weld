#!/usr/bin/env python3
"""Opt-in real TLS/auth registry roundtrip; no user credentials or public ports.

python3 tests/registry_https.py --weld /absolute/rpweld --registry /absolute/docker-registry
Needs openssl, htpasswd, skopeo, and a distribution registry binary on Linux.
"""
import argparse
import base64
import hashlib
import json
import os
import pty
import select
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tarfile
import tempfile
import termios
import signal
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--weld', required=True)
    parser.add_argument('--registry', required=True)
    args = parser.parse_args()
    weld = str(Path(args.weld).resolve())
    registry = str(Path(args.registry).resolve())
    password = secrets.token_urlsafe(32)
    auth_encoded = base64.b64encode(('test:' + password).encode()).decode()
    with tempfile.TemporaryDirectory(prefix='weld-registry-test-') as directory:
        root = Path(directory)
        home = root / 'home'
        home.mkdir(mode=0o700)
        certs = root / 'certs'
        certs.mkdir()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root/'key.pem'), '-out', str(certs/'ca.crt'),
                        '-days', '1', '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['htpasswd', '-Bci', str(root/'htpasswd'), 'test'],
                       input=password+'\n', text=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        host = f'localhost:{port}'
        config = root / 'registry.yml'
        config.write_text(f'''version: 0.1
log:
  level: info
  formatter: json
storage:
  filesystem:
    rootdirectory: {root}/registry-data
http:
  addr: 127.0.0.1:{port}
  secret: {secrets.token_hex(32)}
  tls:
    certificate: {certs}/ca.crt
    key: {root}/key.pem
auth:
  htpasswd:
    realm: weld-test
    path: {root}/htpasswd
''')
        registry_log = root/'registry.log'
        with registry_log.open('wb') as log:
            proc = subprocess.Popen([registry, 'serve', str(config)], stdout=log, stderr=log)
        env = dict(os.environ, HOME=str(home), RPWELD_HOME=str(home/'store'),
                   NO_PROXY='localhost,127.0.0.1', no_proxy='localhost,127.0.0.1')
        def run(arguments, *, stdin=None, success=True):
            result = subprocess.run([weld, *arguments], input=stdin, env=env,
                                    capture_output=True, text=True, timeout=60)
            combined = result.stdout + result.stderr
            assert password not in combined and auth_encoded not in combined, 'credential disclosure'
            assert (result.returncode == 0) == success, combined
            return result
        def layer_gets():
            events = []
            for line in registry_log.read_text().splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if (event.get('http.request.method') == 'GET'
                        and '/blobs/' in event.get('http.request.uri', '')):
                    events.append(event)
            return len(events)
        try:
            context = ssl.create_default_context(cafile=str(certs/'ca.crt'))
            for _ in range(100):
                try:
                    urllib.request.urlopen(f'https://localhost:{port}/v2/', context=context, timeout=1)
                except urllib.error.HTTPError as error:
                    if error.code == 401:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                if proc.poll() is not None:
                    raise AssertionError('test registry exited before readiness')
                time.sleep(.1)
            else:
                raise AssertionError('test registry readiness timeout')
            login = ['login', host, '-u', 'test', '--password-stdin']
            # Unknown certificates must fail, even with correct credentials.
            result = run(login, stdin=password+'\n', success=False)
            assert 'TLS certificate' in result.stderr
            auth = home / '.config/rpweld/auth.json'
            assert not auth.exists()
            login += ['--cert-dir', str(certs)]
            run(login, stdin=password+'\n')
            assert auth.stat().st_mode & 0o777 == 0o600
            saved = auth.read_bytes()
            run(login, stdin='wrong-password\n', success=False)
            assert auth.read_bytes() == saved, 'failed login changed valid credentials'
            print('PASS verified TLS, password-stdin, private permissions, failed-login preservation', flush=True)
            source = root / 'source'
            source.mkdir()
            (source/'payload').write_text('registry-roundtrip\n')
            (source/'Dockerfile').write_text('FROM scratch\nCOPY payload /payload\nCMD ["/payload"]\n')
            tag = f'{host}/private/base:v1'
            progress = run(['build', '-t', tag, '--push', '--cert-dir', str(certs), str(source)])
            assert 'Copying blob' in progress.stderr and '\x1b[' not in progress.stderr
            print('PASS tagged build and authenticated push', flush=True)
            child = root / 'child'
            child.mkdir()
            (child/'Dockerfile').write_text(f'FROM {tag}\nENV ROUNDTRIP=ok\n')
            output = root/'output'
            run(['build', '-t', f'{host}/private/child:v1', '--push', '--cert-dir', str(certs),
                 '--output', str(output), str(child)])
            index = json.loads((output/'index.json').read_text())
            def blob(descriptor):
                path = output/'blobs'/descriptor['digest'].replace(':', '/')
                assert hashlib.sha256(path.read_bytes()).hexdigest() == descriptor['digest'].split(':')[1]
                return path
            manifest = json.loads(blob(index['manifests'][0]).read_text())
            cfg = json.loads(blob(manifest['config']).read_text())
            assert 'ROUNDTRIP=ok' in cfg['config']['Env']
            payload_seen = False
            for layer in manifest['layers']:
                with tarfile.open(blob(layer)) as archive:
                    for member in archive.getmembers():
                        if member.isfile():
                            data = archive.extractfile(member).read()
                            assert password.encode() not in data and auth_encoded.encode() not in data
                            if member.name.lstrip('./') == 'payload':
                                assert data == b'registry-roundtrip\n'
                                payload_seen = True
            assert payload_seen
            run(['push', f'{host}/private/child:v1', '--cert-dir', str(certs)])
            print('PASS private FROM pull, independent payload/config verification, push retry', flush=True)
            # Both pull and push must retain the backend's terminal layer bars.
            master, slave = pty.openpty()
            import fcntl
            import struct
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 100, 0, 0))
            transfer = subprocess.Popen([weld, 'build', '-t', f'{host}/private/tty:v1',
                                         '--push', '--pull', '--cert-dir', str(certs), str(child)],
                                        env=env, stdin=subprocess.DEVNULL, stdout=slave, stderr=slave)
            os.close(slave)
            transcript = b''
            try:
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    if select.select([master], [], [], .1)[0]:
                        try:
                            block = os.read(master, 4096)
                        except OSError:
                            break
                        if not block:
                            break
                        transcript += block
                assert transfer.wait(timeout=5) == 0, transcript
                assert transcript.count(b'Copying blob') >= 2, transcript
                assert b'done' in transcript and b'\x1b[' in transcript, transcript
                assert password.encode() not in transcript and auth_encoded.encode() not in transcript
            finally:
                if transfer.poll() is None:
                    transfer.kill()
                    transfer.wait()
                os.close(master)
            print('PASS terminal pull/push layer bars and plain redirected progress', flush=True)
            # Each invocation has fresh output/work directories but shares only the
            # managed store. Inspect bytes, not a cache-hit diagnostic.
            cache_case = 0
            def cached_build(reference, expected, *flags):
                nonlocal cache_case
                cache_case += 1
                build_context = root/f'cache-context-{cache_case}'
                build_context.mkdir()
                (build_context/'Dockerfile').write_text(f'FROM {reference}\nENV CACHE_CHECK=ok\n')
                layout = root/f'cache-output-{cache_case}'
                result = run(['build', '--output', str(layout), *flags, str(build_context)])
                def verified(descriptor):
                    path = layout/'blobs'/descriptor['digest'].replace(':', '/')
                    data = path.read_bytes()
                    assert len(data) == descriptor['size']
                    assert hashlib.sha256(data).hexdigest() == descriptor['digest'].split(':')[1]
                    return path
                idx = json.loads((layout/'index.json').read_text())
                image = json.loads(verified(idx['manifests'][0]).read_bytes())
                cfg = json.loads(verified(image['config']).read_bytes())
                assert 'CACHE_CHECK=ok' in cfg['config']['Env']
                payloads = []
                for layer in image['layers']:
                    with tarfile.open(verified(layer)) as archive:
                        for member in archive:
                            if member.isfile() and member.name.lstrip('./') == 'payload':
                                payloads.append(archive.extractfile(member).read())
                assert payloads == [expected], payloads
                return result

            original = b'registry-roundtrip\n'
            changed = b'registry-refreshed\n'
            before = layer_gets()
            assert before > 0, 'registry request log did not observe the cold pull'
            warm = cached_build(tag, original)
            assert 'Copying blob' not in warm.stderr
            assert layer_gets() == before, 'warm build transferred base layers'
            print('PASS warm build reuses verified base without layer GETs', flush=True)

            # Publish a one-platform index over the original manifest. Its digest
            # differs from the selected OCI manifest cached by the pull backend.
            def registry_manifest(reference, data=None, media_type=None):
                headers = {'Authorization': 'Basic ' + auth_encoded,
                           'Accept': 'application/vnd.oci.image.manifest.v1+json'}
                if media_type:
                    headers['Content-Type'] = media_type
                request = urllib.request.Request(
                    f'https://{host}/v2/private/base/manifests/{reference}',
                    data=data, headers=headers, method='PUT' if data is not None else 'GET')
                with urllib.request.urlopen(request, context=context, timeout=10) as response:
                    return response.read(), response.headers
            raw, headers = registry_manifest('v1')
            manifest_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            assert headers['Docker-Content-Digest'] == manifest_digest
            index_type = 'application/vnd.oci.image.index.v1+json'
            raw_index = json.dumps({'schemaVersion': 2, 'mediaType': index_type, 'manifests': [{
                'mediaType': json.loads(raw)['mediaType'], 'digest': manifest_digest,
                'size': len(raw), 'platform': {'os': 'linux', 'architecture': 'amd64'},
            }]}).encode()
            registry_manifest('indexed', raw_index, index_type)
            index_digest = 'sha256:' + hashlib.sha256(raw_index).hexdigest()
            assert index_digest != manifest_digest
            pinned = f'{host}/private/base@{index_digest}'
            cached_build(pinned, original, '--cert-dir', str(certs))

            (source/'payload').write_bytes(changed)
            run(['build', '-t', tag, '--push', '--cert-dir', str(certs), str(source)])
            cached_build(tag, original)
            before = layer_gets()
            cached_build(tag, changed, '--pull', '--cert-dir', str(certs))
            assert layer_gets() > before, 'refresh did not fetch the changed image'
            cached_build(tag, changed)
            print('PASS mutable tag stays cached until --pull selects changed payload', flush=True)
            # Fallback Docker/containers credentials must not undo Weld logout.
            (home/'.docker').mkdir()
            (home/'.docker/config.json').write_bytes(saved)
            (home/'.config/containers').mkdir()
            (home/'.config/containers/auth.json').write_bytes(saved)
            run(['logout', host])
            run(['push', tag, '--cert-dir', str(certs)], success=False)
            cached_build(tag, changed)
            run(['build', '-t', 'failed-private-pull', '--pull', '--cert-dir', str(certs), str(child)], success=False)
            cached_build(tag, changed, '--no-cache')
            # The indexed tag exists but only its digest reference has been warmed.
            (child/'Dockerfile').write_text(f'FROM {host}/private/base:indexed\n')
            run(['build', '--cert-dir', str(certs), str(child)], success=False)
            (child/'Dockerfile').write_text(f'FROM {tag}\nENV ROUNDTRIP=ok\n')
            print('PASS logout cache reuse, failed refresh preserves base, uncached auth refusal', flush=True)
            # Exercise the actual TTY password prompt, checking that the secret
            # never appears in the terminal transcript (echo must be disabled).
            master, slave = pty.openpty()
            interactive = subprocess.Popen([weld, 'login', host, '-u', 'test', '--cert-dir', str(certs)],
                                           env=env, stdin=slave, stdout=slave, stderr=slave)
            os.close(slave)
            transcript = b''
            sent = False
            deadline = time.monotonic()+20
            try:
                while time.monotonic() < deadline:
                    if select.select([master], [], [], .1)[0]:
                        try:
                            block = os.read(master, 4096)
                        except OSError:
                            break
                        transcript += block
                        if b'Password:' in transcript and not sent:
                            os.write(master, (password+'\n').encode())
                            sent = True
                    if interactive.poll() is not None:
                        break
                assert sent, 'hidden password prompt was not visible'
                assert interactive.wait(timeout=5) == 0, 'interactive login failed'
                assert password.encode() not in transcript, 'terminal echoed password'
            finally:
                if interactive.poll() is None:
                    interactive.kill()
                    interactive.wait()
                os.close(master)
            print('PASS interactive hidden-password login', flush=True)
            run(['logout', host])
            master, slave = pty.openpty()
            cancelled = subprocess.Popen([weld, 'login', host, '-u', 'test', '--cert-dir', str(certs)],
                                         env=env, stdin=slave, stdout=slave, stderr=slave)
            os.close(slave)
            try:
                observed = b''
                deadline = time.monotonic()+10
                while b'Password:' not in observed and time.monotonic()<deadline:
                    if select.select([master], [], [], .1)[0]:
                        observed += os.read(master,4096)
                assert b'Password:' in observed
                assert not termios.tcgetattr(master)[3] & termios.ECHO
                cancelled.send_signal(signal.SIGINT)
                assert cancelled.wait(timeout=5) != 0
                assert termios.tcgetattr(master)[3] & termios.ECHO, 'cancel left terminal echo disabled'
            finally:
                if cancelled.poll() is None:
                    cancelled.kill(); cancelled.wait()
                os.close(master)
            print('PASS login cancellation restores terminal echo', flush=True)
            # Root-only helper contract test; no real keyring or user credentials.
            if os.geteuid() == 0:
                suffix = 'weld-test-' + secrets.token_hex(8)
                helper = Path('/usr/local/bin/docker-credential-' + suffix)
                helper_store = root/'helper-store.json'
                helper_source = '''#!/usr/bin/python3
import json, os, pathlib, sys
path = pathlib.Path(STORE)
operation = sys.argv[1]
if operation == 'store':
    value = json.load(sys.stdin)
    path.write_text(json.dumps(value)); path.chmod(0o600)
elif operation == 'get':
    server = sys.stdin.read().strip()
    if not path.exists():
        print('credentials not found in native keychain'); sys.exit(1)
    value = json.loads(path.read_text())
    if value['ServerURL'] != server: sys.exit(1)
    print(json.dumps({'Username':value['Username'], 'Secret':value['Secret']}))
elif operation == 'erase':
    server = sys.stdin.read().strip()
    if path.exists(): path.unlink()
else: sys.exit(1)
'''.replace('STORE', repr(str(helper_store)))
                created = False
                try:
                    with helper.open('x') as f:
                        created = True
                        f.write(helper_source)
                    helper.chmod(0o700)
                    auth.write_text(json.dumps({'auths':{}, 'credHelpers':{host:suffix}}))
                    auth.chmod(0o600)
                    run(login, stdin=password+'\n')
                    assert helper_store.exists()
                    assert auth_encoded not in auth.read_text()
                    run(['push', tag, '--cert-dir', str(certs)])
                    run(['logout', host])
                    assert not helper_store.exists()
                    print('PASS credential-helper store/get/erase', flush=True)
                finally:
                    if created:
                        helper.unlink(missing_ok=True)
            # No listening registry, no usable auth, and no trusted certificate:
            # these builds must not initialize Transport or fall back to a pull.
            proc.terminate()
            proc.wait(timeout=5)
            invalid_auth = root/'invalid-auth.json'
            invalid_auth.write_text('deliberately invalid JSON')
            invalid_auth.chmod(0o600)
            cached_build(tag, changed, '--no-cache', '--authfile', str(invalid_auth))
            cached_build(pinned, original, '--pull', '--no-cache', '--authfile', str(invalid_auth))
            # Also fail a real network refresh, then prove the last good entry survives.
            run(['build', '--pull', '--cert-dir', str(certs), str(child)], success=False)
            cached_build(tag, changed, '--no-cache', '--authfile', str(invalid_auth))
            print('PASS offline base reuse without Transport, pinned index --pull reuse, failed network refresh preservation', flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    subprocess.run(['python3', str(Path(__file__).with_name('registry_preflight_https.py')),
                    '--weld', weld], check=True)
    print('REGISTRY_HTTPS_PASS', flush=True)


if __name__ == '__main__':
    main()
