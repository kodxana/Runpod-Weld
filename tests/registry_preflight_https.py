#!/usr/bin/env python3
"""Generated, authenticated loopback HTTPS fixtures; no registry writes or image pulls.

python3 tests/registry_preflight_https.py --weld /absolute/rpweld
Requires Linux, packaged Skopeo, openssl and Python's standard library.
"""
import argparse
import base64
import copy
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import secrets
import signal
import ssl
import subprocess
import tarfile
import tempfile
import threading


MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
INDEX = 'application/vnd.oci.image.index.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
LAYER = 'application/vnd.oci.image.layer.v1.tar+gzip'


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode()


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def descriptor(data, media_type):
    return dict(mediaType=media_type, digest=digest(data), size=len(data))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--weld', required=True)
    weld = str(Path(parser.parse_args().weld).resolve())
    with tempfile.TemporaryDirectory(prefix='weld-preflight-') as directory:
        root = Path(directory)
        home = root/'home'
        home.mkdir(mode=0o700)
        certs = root/'certs'
        certs.mkdir()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root/'key.pem'), '-out', str(certs/'ca.crt'),
                        '-days', '1', '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        secret = secrets.token_urlsafe(32)
        encoded_auth = base64.b64encode(('test:' + secret).encode()).decode()
        manifests, blobs, layer_digests, requests = {}, {}, set(), []
        moving, stall = {}, {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_HEAD(self):
                self.do_GET()

            def do_GET(self):
                try:
                    self.respond()
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass  # Cancellation/metadata caps intentionally close the connection early.

            def respond(self):
                requests.append((self.command, self.path))
                if self.headers.get('Authorization') != 'Basic ' + encoded_auth:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="fixture"')
                    self.end_headers()
                    self.wfile.write(encode({'errors': [{'code': 'UNAUTHORIZED', 'message': secret}]}))
                    return
                if self.path in stall:
                    entered, release = stall[self.path]
                    entered.set()
                    release.wait(15)
                if self.path.rstrip('/') == '/v2':
                    data, media = b'{}', 'application/json'
                elif '/manifests/' in self.path:
                    key = self.path.split('/manifests/', 1)[1]
                    data = manifests.get(key)
                    if key in moving:
                        manifests[key] = moving.pop(key)
                    media = json.loads(data).get('mediaType', MANIFEST) if data else MANIFEST
                elif '/blobs/' in self.path:
                    data = blobs.get(self.path.split('/blobs/', 1)[1])
                    media = 'application/octet-stream'
                else:
                    data, media = None, 'application/json'
                if data is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header('Docker-Distribution-Api-Version', 'registry/2.0')
                self.send_header('Docker-Content-Digest', digest(data))
                self.send_header('Content-Type', media)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                if self.command != 'HEAD':
                    try:
                        self.wfile.write(data)
                    except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                        pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(certs/'ca.crt'), str(root/'key.pem'))
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host = f'localhost:{server.server_port}'
        auth = root/'auth.json'
        auth.write_bytes(encode({'auths': {host: {'auth': encoded_auth}}}))
        auth.chmod(0o600)
        env = dict(os.environ, HOME=str(home), RPWELD_HOME=str(home/'store'),
                   NO_PROXY='localhost,127.0.0.1', no_proxy='localhost,127.0.0.1')

        def publish(tag, value):
            data = encode(value)
            manifests[tag] = data
            manifests[digest(data)] = data
            return descriptor(data, value['mediaType'])

        def image(payload, arch='amd64'):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                entry = tarfile.TarInfo('payload')
                entry.size, entry.mode = len(payload), 0o644
                archive.addfile(entry, io.BytesIO(payload))
            raw = stream.getvalue()
            compressed = gzip.compress(raw, mtime=0)
            layer = descriptor(compressed, LAYER)
            blobs[layer['digest']] = compressed
            layer_digests.add(layer['digest'])
            config = encode({'architecture': arch, 'os': 'linux', 'config': {},
                             'rootfs': {'type': 'layers', 'diff_ids': [digest(raw)]}})
            cfg = descriptor(config, CONFIG)
            blobs[cfg['digest']] = config
            return dict(schemaVersion=2, mediaType=MANIFEST, config=cfg, layers=[layer])

        original = image(b'original\n')
        changed = image(b'changed!\n')
        original_desc = publish('original', original)
        changed_desc = publish('changed', changed)
        counter = 0

        def arguments(tag, flags=(), trusted=True, authfile=auth):
            nonlocal counter
            counter += 1
            context = root/f'context-{counter}'
            context.mkdir()
            reference = f'{host}/fixture:{tag}' if not tag.startswith('sha256:') else f'{host}/fixture@{tag}'
            (context/'Dockerfile').write_text(f'FROM {reference}\n')
            output = root/f'output-{counter}'
            args = [weld, 'build', '--authfile', str(authfile), '--output', str(output)]
            if trusted:
                args += ['--cert-dir', str(certs)]
            return [*args, *flags, str(context)], output

        def run(tag, *flags, success=True, trusted=True, authfile=auth):
            args, output = arguments(tag, flags, trusted, authfile)
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=40)
            combined = result.stdout + result.stderr
            assert secret not in combined and encoded_auth not in combined, 'credential disclosure'
            assert (result.returncode == 0) == success, combined
            return result, output

        def layer_gets():
            return [path for method, path in requests if method == 'GET'
                    and '/blobs/' in path and path.rsplit('/', 1)[1] in layer_digests]

        def reject(tag, value, expected, *flags):
            publish(tag, value)
            before = len(layer_gets())
            result, _ = run(tag, *flags, success=False)
            assert expected in result.stderr, result.stderr
            assert len(layer_gets()) == before, f'{tag}: rejected image fetched a layer'
            print(f'PASS {tag}: zero layer GET', flush=True)

        def payload(output):
            def blob(d):
                data = (output/'blobs'/d['digest'].replace(':', '/')).read_bytes()
                assert len(data) == d['size'] and digest(data) == d['digest']
                return data
            index = json.loads((output/'index.json').read_bytes())
            manifest = json.loads(blob(index['manifests'][0]))
            with tarfile.open(fileobj=io.BytesIO(blob(manifest['layers'][0]))) as archive:
                return archive.extractfile('payload').read()

        try:
            huge = copy.deepcopy(original)
            huge['layers'][0]['size'] = 10 * 1024**3
            reject('per-layer', huge, 'manifest compressed layer bytes', '--max-layer-bytes', '1024')
            total = copy.deepcopy(original)
            total['layers'] *= 2
            reject('aggregate', total, 'manifest total compressed layer bytes',
                   '--max-layer-bytes', str(original['layers'][0]['size'] + 1))
            overflow = copy.deepcopy(original)
            overflow['layers'] = [dict(original['layers'][0], size=2**63-1)] * 3
            reject('overflow', overflow, 'overflow', '--max-layer-bytes', str(2**64-1))
            for media in [LAYER.replace('gzip', 'zstd'), LAYER + '+encrypted']:
                unsupported = copy.deepcopy(original)
                unsupported['layers'][0]['mediaType'] = media
                reject('compression-' + str(len(media)), unsupported, 'unsupported registry layer compression')
            foreign = copy.deepcopy(original)
            foreign['layers'][0]['urls'] = ['https://outside.invalid/never-follow']
            reject('external-url', foreign, 'external/embedded')
            reject('wrong-config-platform', image(b'arm\n', 'arm64'), 'platform')
            arm = publish('arm', image(b'arm\n', 'arm64'))
            index = dict(schemaVersion=2, mediaType=INDEX, manifests=[
                dict(arm, platform=dict(os='linux', architecture='arm64')),
                dict(original_desc, platform=dict(os='linux', architecture='amd64'))])
            publish('indexed', index)
            before = len(layer_gets())
            index_start = len(requests)
            _, output = run('indexed')
            assert payload(output) == b'original\n'
            assert len(layer_gets()) > before
            assert not any('/manifests/' + arm['digest'] in p for _, p in requests[index_start:])
            print('PASS index selects only linux/amd64', flush=True)
            reject('no-platform', dict(index, manifests=index['manifests'][:1]), 'no supported linux/amd64')
            reject('ambiguous', dict(index, manifests=[index['manifests'][1]] * 2), 'ambiguous')
            reject('nested', dict(index, manifests=[dict(original_desc, mediaType=INDEX,
                   platform=dict(os='linux', architecture='amd64'))]), 'nested indexes')
            reject('index-count', dict(index, manifests=index['manifests'] * 3000), 'descriptor count')
            reject('layer-count', dict(original, layers=original['layers'] * 5000), 'descriptor count')
            bad_size = copy.deepcopy(index)
            bad_size['manifests'][1]['size'] += 1
            reject('descriptor-size', bad_size, 'digest or size mismatch')
            tampered = copy.deepcopy(original)
            tampered['layers'][0]['digest'] = 'sha256:' + 'f' * 64
            assert len(encode(tampered)) == original_desc['size']
            manifests[original_desc['digest']] = encode(tampered)
            reject('descriptor-digest', index, 'digest or size mismatch')
            before = len(layer_gets())
            result, _ = run(original_desc['digest'], success=False)
            assert 'digest or size mismatch' in result.stderr and len(layer_gets()) == before
            manifests[original_desc['digest']] = encode(original)
            metadata = dict(original, annotations={'fixture': 'x' * 2000})
            reject('metadata-stdout', metadata, 'preflight byte limit', '--metadata-budget', '1500')
            cfg = encode({'architecture': 'amd64', 'os': 'linux', 'padding': 'x' * 1700})
            blobs[digest(cfg)] = cfg
            reject('metadata-aggregate', dict(metadata, config=descriptor(cfg, CONFIG)),
                   'preflight byte limit', '--metadata-budget', '3000')
            cfg_large = copy.deepcopy(original)
            cfg_large['config']['size'] = 4 * 1024**2 + 1
            reject('metadata-hard-cap', cfg_large, 'preflight byte limit', '--metadata-budget', str(2**32))
            # Supported Docker v2 metadata still converts to OCI after the pinned copy.
            docker = copy.deepcopy(original)
            docker['mediaType'] = 'application/vnd.docker.distribution.manifest.v2+json'
            docker['config']['mediaType'] = 'application/vnd.docker.container.image.v1+json'
            docker['layers'][0]['mediaType'] = 'application/vnd.docker.image.rootfs.diff.tar.gzip'
            docker_desc = publish('docker', docker)
            docker_index = dict(schemaVersion=2,
                                mediaType='application/vnd.docker.distribution.manifest.list.v2+json',
                                manifests=[dict(docker_desc, platform=dict(os='linux', architecture='amd64'))])
            pinned_index = publish('docker-index', docker_index)
            _, output = run(pinned_index['digest'])
            assert payload(output) == b'original\n'
            print('PASS pinned Docker v2 index/manifest conversion to OCI', flush=True)
            args, output = arguments('original', ['--target', 'chosen'])
            (Path(args[-1])/'Dockerfile').write_text(
                f'FROM localhost:1/unreachable:unused AS unused\n'
                f'FROM {host}/fixture:original AS selected\nFROM selected AS chosen\n')
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=40)
            assert result.returncode == 0, result.stderr
            assert payload(output) == b'original\n'
            assert secret not in result.stdout + result.stderr
            print('PASS selected target pulls only its dependency bases', flush=True)
            # The registry moves the tag as soon as its initial bytes are returned.
            publish('moving', original)
            moving['moving'] = encode(changed)
            _, output = run('moving')
            assert payload(output) == b'original\n'
            tag_gets = [p for m, p in requests if m == 'GET' and p.endswith('/manifests/moving')]
            assert len(tag_gets) == 1, tag_gets
            assert any(p.endswith('/manifests/' + original_desc['digest']) for _, p in requests)
            _, output = run('moving', '--pull')
            assert payload(output) == b'changed!\n'
            print('PASS moving tag pins original digest; explicit refresh selects new content', flush=True)
            publish('tls-fail', original)
            before = len(layer_gets())
            result, _ = run('tls-fail', success=False, trusted=False)
            assert 'TLS certificate' in result.stderr and len(layer_gets()) == before
            bad_auth = root/'bad-auth.json'
            bad_auth.write_bytes(encode({'auths': {}}))
            bad_auth.chmod(0o600)
            result, _ = run('tls-fail', success=False, authfile=bad_auth)
            assert 'authentication' in result.stderr and len(layer_gets()) == before
            print('PASS TLS and authentication failures with redacted diagnostics', flush=True)
            publish('cancel', original)
            entered, release = threading.Event(), threading.Event()
            stall['/v2/fixture/manifests/cancel'] = (entered, release)
            args, _ = arguments('cancel')
            process = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                assert entered.wait(10), 'preflight did not reach stalled metadata request'
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=10)
                assert process.returncode != 0 and b'cancelled' in stderr, stderr
                assert secret.encode() not in stdout + stderr
                assert len(layer_gets()) == before
                assert not list(root.rglob('.rpweld-registry-*')), 'transport credentials survived cancellation'
            finally:
                release.set()
                if process.poll() is None:
                    process.kill()
                    process.wait()
            print('PASS cancellation during metadata request with zero layer GET', flush=True)
            # Valid cached content works with the server stopped and malformed auth.
            server.shutdown()
            server.server_close()
            invalid = root/'invalid-auth.json'
            invalid.write_text('invalid ' + secret)
            invalid.chmod(0o600)
            before = len(requests)
            _, output = run('moving', '--no-cache', trusted=False, authfile=invalid)
            assert payload(output) == b'changed!\n' and len(requests) == before
            _, output = run(pinned_index['digest'], '--pull', '--no-cache', trusted=False, authfile=invalid)
            assert payload(output) == b'original\n' and len(requests) == before
            run('moving', '--pull', success=False)
            _, output = run('moving', '--no-cache', trusted=False, authfile=invalid)
            assert payload(output) == b'changed!\n'
            print('PASS offline cache without credentials and failed refresh preservation', flush=True)
        finally:
            for _, release in stall.values():
                release.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print('REGISTRY_PREFLIGHT_HTTPS_PASS', flush=True)


if __name__ == '__main__':
    main()
