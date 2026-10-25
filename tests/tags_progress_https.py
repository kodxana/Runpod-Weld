"""Local Linux/root acceptance: generated HTTPS registry, multi-tag push and RUN output.
Usage: python3 tests/tags_progress_https.py /absolute/rpweld
Requires existing skopeo, openssl and gcc; no downloads or user credentials.
"""
import gzip
import hashlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.parse


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='weld-tags-progress-') as directory:
        root = Path(directory)
        cert = root / 'cert'
        cert.mkdir()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(root/'key'),
                        '-out', str(cert/'ca.crt')], check=True, capture_output=True)
        blobs, uploads, manifests = {}, {}, {}
        denied = {'fail'}
        attempted = []

        class Registry(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def reply(self, status, body=b'', **headers):
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Docker-Distribution-Api-Version', 'registry/2.0')
                for key, value in headers.items():
                    self.send_header(key.replace('_', '-'), value)
                self.end_headers()
                if body and self.command != "HEAD":
                    self.wfile.write(body)

            def body(self):
                if self.headers.get('Transfer-Encoding') != 'chunked':
                    return self.rfile.read(int(self.headers.get('Content-Length', 0)))
                data = bytearray()
                while True:
                    size = int(self.rfile.readline().split(b';')[0], 16)
                    if size == 0:
                        assert self.rfile.readline() == b'\r\n'
                        return bytes(data)
                    data.extend(self.rfile.read(size))
                    assert self.rfile.read(2) == b'\r\n'

            def do_GET(self):
                self.reply(200, b'{}')

            def do_HEAD(self):
                digest = self.path.rsplit('/', 1)[-1]
                if digest in blobs:
                    self.reply(200, blobs[digest], Docker_Content_Digest=digest)
                else:
                    self.reply(404)

            def do_POST(self):
                self.body()
                location = urllib.parse.urlsplit(self.path).path + str(len(uploads))
                uploads[location] = bytearray()
                self.reply(202, Location=location, Docker_Upload_UUID=location.rsplit('/', 1)[-1])

            def do_PATCH(self):
                path = urllib.parse.urlsplit(self.path).path
                uploads[path].extend(self.body())
                self.reply(202, Location=path, Range=f'0-{max(0, len(uploads[path])-1)}')

            def do_PUT(self):
                url = urllib.parse.urlsplit(self.path)
                body = self.body()
                if '/uploads/' in url.path:
                    uploads[url.path].extend(body)
                    digest = urllib.parse.parse_qs(url.query)['digest'][0]
                    data = bytes(uploads[url.path])
                    assert digest == 'sha256:' + hashlib.sha256(data).hexdigest()
                    blobs[digest] = data
                    self.reply(201, Location='/v2/test/image/blobs/'+digest, Docker_Content_Digest=digest)
                else:
                    ref = url.path.rsplit('/', 1)[-1]
                    attempted.append(ref)
                    if ref in denied:
                        self.reply(403, b'{"errors":[{"code":"DENIED","message":"fixture refusal"}]}', Content_Type='application/json')
                    else:
                        manifest = json.loads(body)
                        assert all(item['digest'] in blobs for item in [manifest['config'], *manifest['layers']])
                        manifests[ref] = body
                        self.reply(201, Docker_Content_Digest='sha256:'+hashlib.sha256(body).hexdigest())

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Registry)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert/'ca.crt', root/'key')
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = dict(os.environ, HOME=str(root), RPWELD_HOME=str(root/'store'),
                   NO_PROXY='localhost,127.0.0.1', no_proxy='localhost,127.0.0.1')

        def run(args, success=True):
            result = subprocess.run([binary, *map(str, args)], env=env, capture_output=True,
                                    text=True, timeout=90)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            return result

        try:
            context = root/'context'
            context.mkdir()
            (context/'payload').write_text('multi-tag fixture\n')
            (context/'Dockerfile').write_text('FROM scratch\nCOPY payload /payload\nUSER 123:456\n')
            host = f'localhost:{server.server_port}/test/image'
            refs = [host+':'+tag for tag in ('first', 'fail', 'last')]
            result = run(['build', '-t', refs[0], '--tag='+refs[1], '--tag', refs[2],
                          '--push', '--cert-dir', cert, context], success=False)
            assert attempted == ['first', 'fail', 'last'], attempted
            assert manifests['first'] == manifests['last'], (manifests['first'], manifests['last'])
            assert 'Push failed for '+refs[1] in result.stdout
            assert 'Pushed '+refs[0] in result.stdout and 'Pushed '+refs[2] in result.stdout
            records = [json.loads(p.read_text()) for p in (root/'store').glob('tag-*.json')]
            assert len(records) == 3 and len({r['image'] for r in records}) == 1
            image = Path(records[0]['image'])
            descriptor = json.loads((image/'index.json').read_text())['manifests'][0]
            local_manifest = json.loads((image/'blobs'/descriptor['digest'].replace(':', '/')).read_bytes())
            uploaded = json.loads(manifests['first'])
            assert uploaded['config'] == local_manifest['config']
            config = json.loads(blobs[uploaded['config']['digest']])
            assert config['config']['User'] == '123:456'
            assert ['sha256:'+hashlib.sha256(gzip.decompress(blobs[layer['digest']])).hexdigest()
                    for layer in uploaded['layers']] == config['rootfs']['diff_ids']
            record = json.loads((image.parent/'build-record.json').read_text())
            assert record['push'] == 'failed', record
            denied.clear()
            run(['push', refs[1], '--cert-dir', cert])
            assert manifests['fail'] == manifests['first']
            result = run(['build', '--tag='+host+':all1', '--tag='+host+':all2', '--push',
                          '--progress=quiet', '--cert-dir', cert, context])
            assert 'Stage ' not in result.stderr
            assert manifests['all1'] == manifests['all2']
            print('PASS real TLS: same verified manifest, success/failure/success, retained tags, retry, quiet push')

            # A static fake shell exercises the real RUN worker without a downloaded base.
            source = root/'runner.c'
            source.write_text('#include <stdio.h>\n#include <string.h>\nint main(int n,char**v){puts("RUN_STDOUT");fputs("RUN_STDERR\\n",stderr);return n>1 && strstr(v[n-1],"fail")!=0 ? 7 : 0;}\n')
            subprocess.run(['gcc', '-static', '-O2', '-o', str(context/'runner'), str(source)], check=True)
            for mode in ['auto', 'plain', 'quiet']:
                for fail in [False, True]:
                    (context/'Dockerfile').write_text('FROM scratch\nCOPY runner /bin/sh\nRUN '+('fail' if fail else 'pass')+'\n')
                    result = run(['build', '--no-cache', '--progress='+mode, context], success=not fail)
                    assert 'RUN_STDOUT' in result.stdout and 'RUN_STDERR' in result.stderr
                    assert ('Stage ' in result.stderr) == (mode != 'quiet')
                    if fail:
                        assert 'RUN worker failed' in result.stderr
            print('PASS real RUN stdout/stderr and failures remain visible in auto/plain/quiet')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    main()
