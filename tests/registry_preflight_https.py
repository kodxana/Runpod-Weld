#!/usr/bin/env python3
"""Generated, authenticated loopback HTTPS fixtures; no registry writes or image pulls.

python3 tests/registry_preflight_https.py --weld /absolute/rpweld
Requires Linux, packaged Skopeo, openssl and Python's standard library.
Policy tests require a private mount namespace (root); no host policy is modified.
Optional --transport-driver runs callback/legacy API checks using the Rust fixture driver.
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
import sys
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
    parser.add_argument('--transport-driver')
    options = parser.parse_args()
    weld = str(Path(options.weld).resolve())
    driver = str(Path(options.transport_driver).resolve()) if options.transport_driver else None
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

        def publish(tag, value, media=MANIFEST):
            data = encode(value)
            manifests[tag] = data
            manifests[digest(data)] = data
            return descriptor(data, value.get('mediaType', media))

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

        def run(tag, *flags, success=True, trusted=True, authfile=auth, policy=None):
            args, output = arguments(tag, flags, trusted, authfile)
            if policy is not None:
                policy_path = root/f'policy-{counter}.json'
                policy_path.write_bytes(encode(policy))
                args = ['unshare', '--mount', '--propagation', 'private', 'python3',
                        str(Path(__file__).resolve()), '--policy-exec', str(policy_path), *args]
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=40)
            combined = result.stdout + result.stderr
            assert secret not in combined and encoded_auth not in combined, 'credential disclosure'
            assert (result.returncode == 0) == success, combined
            return result, output

        def layer_gets():
            return [path for method, path in requests if method == 'GET'
                    and '/blobs/' in path and path.rsplit('/', 1)[1] in layer_digests]

        def drive(mode, tag, *, policy=None, success=False):
            nonlocal counter
            counter += 1
            output = root/f'driver-output-{counter}'
            reference = f'{host}/fixture:{tag}' if not tag.startswith('sha256:') else f'{host}/fixture@{tag}'
            args = [driver, mode, reference, str(auth), str(certs), str(output),
                    str(original['layers'][0]['size']), '1']
            if policy is not None:
                policy_path = root/f'driver-policy-{counter}.json'
                policy_path.write_bytes(encode(policy))
                args = ['unshare', '--mount', '--propagation', 'private', 'python3',
                        str(Path(__file__).resolve()), '--policy-exec', str(policy_path), *args]
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=40)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            assert secret not in result.stdout + result.stderr
            assert not list(root.rglob('.rpweld-registry-*')), 'transport files survived return'
            return result

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
            # Go's JSON decoder folds struct keys and accepts last-wins collisions.
            for case, key in enumerate(['Size', 'SIZE', '\u017fize']):
                collision = copy.deepcopy(original)
                collision['layers'][0]['size'] = 1
                collision['layers'][0][key] = 5000000
                reject('size-alias-' + str(case), collision, 'noncanonical', '--max-layer-bytes', '1024')
            collision = copy.deepcopy(original)
            collision['layers'] = []
            collision['Layers'] = [dict(original['layers'][0], size=5000000)]
            reject('layers-alias', collision, 'noncanonical', '--max-layer-bytes', '1024')
            duplicate = encode(original).replace(b'"size":', b'"size":1,"size":', 1)
            manifests['exact-duplicate'] = duplicate
            before = len(layer_gets())
            result, _ = run('exact-duplicate', success=False)
            assert 'duplicate field' in result.stderr and len(layer_gets()) == before
            duplicate = encode(original).replace(b'"layers":', b'"layers":[],"layers":', 1)
            manifests['duplicate-layers'] = duplicate
            result, _ = run('duplicate-layers', success=False)
            assert 'duplicate field' in result.stderr and len(layer_gets()) == before
            reject('platform-alias', dict(schemaVersion=2, mediaType=INDEX, manifests=[
                dict(original_desc, platform=dict(os='linux', architecture='amd64', Architecture='arm64'))]),
                'noncanonical')
            for key, value in [('Architecture', 'arm64'), ('Rootfs', {'type': 'layers', 'diff_ids': []})]:
                config = json.loads(blobs[original['config']['digest']])
                config[key] = value
                raw_config = encode(config)
                blobs[digest(raw_config)] = raw_config
                reject('config-alias-' + key, dict(original, config=descriptor(raw_config, CONFIG)), 'noncanonical')
            medialess = copy.deepcopy(original)
            del medialess['mediaType']
            medialess_desc = publish('no-media-type', medialess)
            _, output = run('no-media-type')
            assert payload(output) == b'original\n'
            publish('selected-no-media', dict(schemaVersion=2, mediaType=INDEX, manifests=[
                dict(medialess_desc, platform=dict(os='linux', architecture='amd64'))]))
            _, output = run('selected-no-media')
            assert payload(output) == b'original\n'
            reject('explicit-type-mismatch', dict(original, mediaType=INDEX), 'media type mismatch')
            config = json.loads(blobs[original['config']['digest']])
            config['config'] = {'Env': ['UNICODE=zażółć'], 'Labels': {'ſize': '雪'}}
            raw_config = encode(config)
            blobs[digest(raw_config)] = raw_config
            publish('unicode-values', dict(original, config=descriptor(raw_config, CONFIG)))
            _, output = run('unicode-values')
            assert payload(output) == b'original\n'
            print('PASS canonical structural fields, exact duplicates, optional mediaType, Unicode values', flush=True)
            accept, deny = [{'type': 'insecureAcceptAnything'}], [{'type': 'reject'}]
            block_tag = {'default': accept, 'transports': {'docker': {
                f'{host}/fixture': accept, f'{host}/fixture:policy-blocked': deny}}}
            publish('policy-blocked', original)
            before = len(layer_gets())
            result, _ = run('policy-blocked', policy=block_tag, success=False)
            assert 'rejected by registry signature policy' in result.stderr and len(layer_gets()) == before
            allow_tag = {'default': deny, 'transports': {'docker': {
                f'{host}/fixture': deny, f'{host}/fixture:policy-allowed': accept}}}
            publish('policy-allowed', original)
            _, output = run('policy-allowed', policy=allow_tag)
            assert payload(output) == b'original\n'
            signed = {'default': accept, 'transports': {'docker': {f'{host}/fixture:policy-signed': [{
                'type': 'signedBy', 'keyType': 'GPGKeys', 'keyPath': '/nonexistent-fixture-key'}]}}}
            publish('policy-signed', original)
            before = len(layer_gets())
            result, _ = run('policy-signed', policy=signed, success=False)
            assert 'signed tag/index policies are unsupported' in result.stderr and len(layer_gets()) == before
            signed_index = publish('signed-index', dict(schemaVersion=2, mediaType=INDEX, manifests=[
                dict(original_desc, platform=dict(os='linux', architecture='amd64'))]))
            for ref in ['signed-index', signed_index['digest']]:
                result, _ = run(ref, policy={'default': signed['transports']['docker'][f'{host}/fixture:policy-signed']},
                                success=False)
                assert 'signed tag/index policies are unsupported' in result.stderr and len(layer_gets()) == before
            publish('policy-large', original)
            result, _ = run('policy-large', policy={'default': accept, 'padding': 'x' * 1024**2}, success=False)
            assert 'signature policy exceeds byte limit' in result.stderr and len(layer_gets()) == before
            publish('policy-invalid', original)
            result, _ = run('policy-invalid', policy={'default': accept, 'unknown': True}, success=False)
            assert len(layer_gets()) == before
            print('PASS original tag reject/allow scopes and unsupported signing policy: zero rejected layer GET', flush=True)
            pinned_scope = f'{host}/fixture@{original_desc["digest"]}'
            malformed_collision = {'default': accept, 'transports': {'docker': {
                pinned_scope: [{'type': 'unsupported-fixture-policy'}]}}}
            publish('policy-malformed-collision', original)
            before = len(layer_gets())
            if driver:
                drive('old', 'policy-malformed-collision', policy=malformed_collision)
                assert len(layer_gets()) == before
            result, _ = run('policy-malformed-collision', policy=malformed_collision, success=False)
            assert 'pinned-digest policy scope collision' in result.stderr and len(layer_gets()) == before
            valid_collision = {'default': accept, 'transports': {'docker': {pinned_scope: deny}}}
            publish('policy-valid-collision', original)
            # The original tag policy allows this, but adapting the existing digest scope
            # without complete policy validation is intentionally unsupported.
            if driver:
                drive('old', 'policy-valid-collision', policy=valid_collision, success=True)
            before = len(layer_gets())
            result, _ = run('policy-valid-collision', policy=valid_collision, success=False)
            assert 'pinned-digest policy scope collision' in result.stderr and len(layer_gets()) == before
            equal_scope = {'default': accept, 'transports': {'docker': {pinned_scope: accept}}}
            publish('policy-equal-scope', original)
            _, output = run('policy-equal-scope', policy=equal_scope)
            assert payload(output) == b'original\n'
            equal_with_invalid = copy.deepcopy(equal_scope)
            equal_with_invalid['transports']['docker'][f'{host}/other'] = [{'type': 'unsupported-fixture-policy'}]
            publish('policy-equal-invalid', original)
            before = len(layer_gets())
            result, _ = run('policy-equal-invalid', policy=equal_with_invalid, success=False)
            assert 'scope collision' not in result.stderr and len(layer_gets()) == before
            if driver:
                drive('old', 'policy-equal-invalid', policy=equal_with_invalid)
                assert len(layer_gets()) == before
                result = drive('checked', original_desc['digest'], policy=malformed_collision)
                assert 'scope collision' not in result.stderr and len(layer_gets()) == before
                drive('checked', original_desc['digest'], policy=equal_scope, success=True)
            print('PASS pinned policy collisions fail closed; equal and unchanged scopes retain complete policy', flush=True)
            if driver:
                for mode, expected in [('abort', 'fixture pre-copy rejected'), ('cancel', 'cancelled')]:
                    before = len(layer_gets())
                    result = drive(mode, 'original')
                    assert expected in result.stderr and len(layer_gets()) == before, result.stderr
                # Both APIs hide caller HOME policy and use the system policy in their private HOME.
                caller_policy = home/'.config/containers/policy.json'
                caller_policy.parent.mkdir(parents=True, exist_ok=True)
                caller_policy.write_bytes(encode({'default': deny}))
                drive('old', 'original', success=True)
                drive('checked', 'original', success=True)
                before = len(layer_gets())
                drive('old', 'policy-blocked', policy=block_tag)
                assert len(layer_gets()) == before
                drive('old', 'policy-allowed', policy=allow_tag, success=True)
                signed_digest = {'default': [{'type': 'signedBy', 'keyType': 'GPGKeys',
                                              'keyPath': '/nonexistent-fixture-key'}]}
                before = len(layer_gets())
                result = drive('checked', original_desc['digest'], policy=signed_digest)
                assert 'unsupported' not in result.stderr and len(layer_gets()) == before
                print('PASS pre-copy callback abort/cancel, private snapshot cleanup, old/new HOME lookup, unchanged digest signature enforcement', flush=True)
            huge = copy.deepcopy(original)
            huge['layers'][0]['size'] = 10 * 1024**3
            reject('per-layer', huge, 'manifest compressed layer bytes', '--max-layer-bytes', '1024')
            # Declared sizes can fit explicit workload ceilings but not current
            # download + verified-cache storage. Refuse before a layer GET.
            capacity = copy.deepcopy(original)
            capacity['layers'][0]['size'] = 300 * 1024**2
            publish('disk-capacity', capacity)
            resource_store = root/'bounded-store'
            resource_store.mkdir(mode=0o700)
            args, output = arguments('disk-capacity', [
                '-t', 'test/preflight-capacity', '--no-cache',
                '--max-layer-bytes', str(1024**3), '--max-rootfs-bytes', str(1024**3),
                '--metadata-budget', str(64 * 1024**2), '--max-entries', '100000'])
            before = len(layer_gets())
            result = subprocess.run([
                'unshare', '--mount', '--propagation', 'private', 'python3',
                str(Path(__file__).resolve()), '--resource-exec', str(resource_store), *args
            ], env=dict(env, RPWELD_HOME=str(resource_store)), capture_output=True, text=True, timeout=40)
            assert result.returncode != 0 and 'downloading and storing declared compressed base blobs' in result.stderr, result.stderr
            assert 'additional/reserved bytes' in result.stderr and len(layer_gets()) == before
            assert not output.exists() and secret not in result.stdout + result.stderr
            print('PASS measured download capacity refusal: zero layer GET', flush=True)
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
            # A malicious digest endpoint must not substitute a same-sized manifest
            # during --raw --config or the later copy's independent reopen.
            replacement = copy.deepcopy(original)
            replacement['layers'][0]['digest'] = changed['layers'][0]['digest']
            replacement = encode(replacement)
            assert len(replacement) == original_desc['size']
            for phase in ['config', 'copy']:
                publish('immutable-race-' + phase, original)
                if phase == 'config':
                    manifests[original_desc['digest']] = replacement
                else:
                    moving[original_desc['digest']] = replacement
                before = len(layer_gets())
                result, _ = run('immutable-race-' + phase, success=False)
                assert len(layer_gets()) == before, f'{phase} digest reopen fetched a substituted layer: {result.stderr}'
                manifests[original_desc['digest']] = encode(original)
                moving.pop(original_desc['digest'], None)
            print('PASS same-sized manifest substitution at config/copy digest reopen: zero layer GET', flush=True)
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
    if len(sys.argv) > 1 and sys.argv[1] == '--resource-exec':
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=512m,nr_inodes=16384,mode=0700',
                        'tmpfs', sys.argv[2]], check=True)
        os.execv(sys.argv[3], sys.argv[3:])
    elif len(sys.argv) > 1 and sys.argv[1] == '--policy-exec':
        # Only inside a private mount namespace: never replace the host policy.
        subprocess.run(['mount', '--bind', sys.argv[2], '/etc/containers/policy.json'], check=True)
        os.execv(sys.argv[3], sys.argv[3:])
    else:
        main()
