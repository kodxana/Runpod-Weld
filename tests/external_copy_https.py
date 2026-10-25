#!/usr/bin/env python3
"""Local read-only HTTPS registry fixture. No internet, credentials or publication.

Run as Linux root: python3 tests/external_copy_https.py /absolute/path/to/rpweld
Requires local skopeo and openssl. All state and generated TLS keys are temporary.
"""
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


def main():
    weld = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="weld-external-https-") as tmp:
        root = Path(tmp)
        env = dict(os.environ, HOME=str(root), RPWELD_HOME=str(root / "store"),
                   NO_PROXY="localhost,127.0.0.1", no_proxy="localhost,127.0.0.1")

        def run(*args, success=True):
            result = subprocess.run([weld, *map(str, args)], env=env,
                                    capture_output=True, text=True, timeout=60)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            return result

        source = root / "source"
        source.mkdir()
        (source / "Dockerfile").write_text('FROM scratch\nCOPY payload /payload\nENV SOURCE=hidden\nUSER 123:456\n')
        layouts = []
        for n, text in enumerate(["original", "refreshed"]):
            (source / "payload").write_text(text)
            layout = root / f"layout-{n}"
            run("build", "--output", layout, source)
            layouts.append(layout)

        selected = [0]
        requests = []

        def manifest(layout):
            return json.loads((layout / "index.json").read_bytes())["manifests"][0]

        original_digest = manifest(layouts[0])["digest"]

        class Registry(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                requests.append(self.path)
                media = "application/json"
                if self.path in ("/v2/", "/v2"):
                    data = b"{}"
                else:
                    layout = layouts[selected[0]]
                    if "/manifests/" in self.path:
                        ref = self.path.rsplit("/", 1)[1]
                        if ref == original_digest:
                            layout = layouts[0]
                        elif ref != "v1":
                            self.send_error(404)
                            return
                        descriptor = manifest(layout)
                        media = descriptor["mediaType"]
                        digest = descriptor["digest"]
                    elif "/blobs/sha256:" in self.path:
                        digest = self.path.rsplit("/", 1)[1]
                        media = "application/octet-stream"
                    else:
                        self.send_error(404)
                        return
                    paths = [layout / "blobs" / digest.replace(":", "/")]
                    paths += [p / "blobs" / digest.replace(":", "/") for p in layouts]
                    path = next((p for p in paths if p.is_file()), None)
                    if path is None:
                        self.send_error(404)
                        return
                    data = path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", media)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
                self.send_header("Docker-Content-Digest", "sha256:" + hashlib.sha256(data).hexdigest())
                self.end_headers()
                self.wfile.write(data)

        certs = root / "certs"
        certs.mkdir()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(root / "key.pem"), "-out", str(certs / "ca.crt"),
                        "-days", "1", "-subj", "/CN=localhost", "-addext",
                        "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certs / "ca.crt", root / "key.pem")
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        reference = f"localhost:{server.server_port}/fixture/source:v1"
        pinned = reference.rsplit(":", 1)[0] + "@" + original_digest
        target = root / "target"
        target.mkdir()
        counter = 0

        def build(ref, expected=None, *flags, success=True):
            nonlocal counter
            counter += 1
            (target / "Dockerfile").write_text(
                "FROM scratch AS unused\nCOPY --from=unreachable.invalid/unused /x /x\n"
                f"FROM scratch\nCOPY --from={ref} /payload /result\n")
            work = root / f"work-{counter}"
            result = run("build", "--work-dir", work, *flags, target, success=success)
            if success:
                assert (work / "rootfs/result").read_text() == expected
            return result

        try:
            build(reference, success=False)
            build(reference, "original", "--cert-dir", certs)
            assert any("/manifests/" in p for p in requests)
            before = len(requests)
            build(reference, "original")
            assert len(requests) == before
            build(pinned, "original", "--cert-dir", certs)
            selected[0] = 1
            build(reference, "original")
            build(reference, "refreshed", "--pull", "--cert-dir", certs)
            before = len(requests)
            build(pinned, "original", "--pull")
            assert len(requests) == before
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        build(reference, "refreshed")
        build(reference, None, "--pull", "--cert-dir", certs, success=False)
        build(reference, "refreshed", "--no-cache")
        print("PASS external COPY HTTPS cold pull, TLS rejection, warm/offline reuse, refresh, digest pin, selected dependencies")


if __name__ == "__main__":
    main()
