"""Linux root, local-only production RUN and Skopeo handoff regression.

python3 tests/store_lease_integration.py target/debug/rpweld
Requires gcc (static libc), openssl and packaged /usr/bin/skopeo. Retains fixture
trees for inspection. No user credentials, downloads, cloud, or cleanup deletion.
"""
import ctypes
import fcntl
import http.server
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def until(predicate, timeout=30):
    end = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < end, 'timed out'
        time.sleep(.02)


def children(pid):
    try:
        return [int(n) for n in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
    except FileNotFoundError:
        return []


def tree(pid):
    result = children(pid)
    for child in list(result):
        result += tree(child)
    return result


def exclusive(store):
    with (store/'store.lock').open('rb') as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False


def no_leak(store, pids):
    identity = (store/'store.lock').stat()
    for pid in pids:
        for fd in Path(f'/proc/{pid}/fd').iterdir():
            try:
                st = fd.stat()
                assert (st.st_dev, st.st_ino) != (identity.st_dev, identity.st_ino), (pid, fd)
            except FileNotFoundError:
                pass


def reap_guard(pid, store):
    status = []
    def done():
        child, value = os.waitpid(pid, os.WNOHANG)
        if child:
            status.append(value)
        return bool(child)
    until(done)
    assert exclusive(store), 'lease not released after final reap'


def main():
    assert os.geteuid() == 0
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0  # adopt orphan guard
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(tempfile.mkdtemp(prefix='weld-store-integration-'))
    print('Evidence:', root, flush=True)
    home = root/'home'
    home.mkdir(mode=0o700)
    store = home/'store'
    env = dict(os.environ, HOME=str(home), RPWELD_HOME=str(store), NO_PROXY='localhost,127.0.0.1', no_proxy='localhost,127.0.0.1')
    context = root/'context'
    context.mkdir()
    # A static fixture stands in for the image shell; the actual trace worker
    # runs it and tracks a detached child, without needing an external base image.
    c = root/'fixture.c'
    c.write_text('''#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
int main(void) {
  int child = fork();
  if (child < 0) return 2;
  if (!child) {
    setsid(); close(open("/ready", O_CREAT|O_WRONLY, 0600));
    while (access("/release", F_OK)) usleep(20000);
    return 0;
  }
  int status; waitpid(child, &status, 0); return 0;
}
''')
    subprocess.run(['gcc', '-static', '-O2', str(c), '-o', str(context/'shell')], check=True)
    (context/'Dockerfile').write_text('FROM scratch\nCOPY shell /bin/sh\nRUN fixture\n')
    work = root/'work'
    log = (root/'run.log').open('wb')
    cli = subprocess.Popen([binary, 'build', '--host-dns', '--work-dir', str(work), str(context)], env=env, stdout=log, stderr=log)
    until(lambda: (work/'rootfs/ready').exists())
    guard, = children(cli.pid)
    workload = tree(guard)
    assert len(workload) >= 3, workload
    no_leak(store, workload)
    assert not exclusive(store)
    cli.kill(); cli.wait()
    assert not exclusive(store), 'CLI SIGKILL released RUN lease'
    assert all(Path(f'/proc/{pid}').exists() for pid in workload)
    (work/'rootfs/release').touch()
    reap_guard(guard, store)
    assert all(not Path(f'/proc/{pid}').exists() for pid in workload)
    log.close()
    print('PASS real RUN: parent SIGKILL, detached child alive, no fd leak, final grant', flush=True)

    # Cancellation must wait for every process before restoring injected DNS.
    work = root/'cancel-work'
    log = (root/'cancel.log').open('wb')
    cli = subprocess.Popen([binary, 'build', '--host-dns', '--work-dir', str(work), '--output', str(root/'cancel-image'), str(context)], env=env, stdout=log, stderr=log)
    until(lambda: (work/'rootfs/ready').exists())
    workload = tree(cli.pid)
    cli.send_signal(signal.SIGTERM)
    assert cli.wait(timeout=20) != 0
    assert all(not Path(f'/proc/{pid}').exists() for pid in workload)
    assert not (work/'rootfs/etc/resolv.conf').exists(), 'DNS teardown did not finish'
    log.close()
    print('PASS unmanaged RUN cancellation: descendants reaped before DNS restore', flush=True)

    cert = root/'cert'
    cert.mkdir()
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(root/'key'), '-out', str(cert/'ca.crt')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    entered = threading.Event()
    release = threading.Event()
    class Registry(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args): pass
        def reply(self, status, body=b'', **headers):
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Docker-Distribution-Api-Version', 'registry/2.0')
            for key, value in headers.items(): self.send_header(key.replace('_', '-'), value)
            self.end_headers()
            if body: self.wfile.write(body)
        def do_GET(self): self.reply(200, b'{}')
        def do_HEAD(self): self.reply(404)
        def do_POST(self): self.reply(202, Location='/v2/test/image/blobs/uploads/fixture', Docker_Upload_UUID='fixture')
        def do_PATCH(self):
            if self.headers.get('Transfer-Encoding') == 'chunked':
                while True:
                    n = int(self.rfile.readline().split(b';')[0], 16)
                    if not n:
                        self.rfile.readline(); break
                    self.rfile.read(n); self.rfile.read(2)
            else:
                self.rfile.read(int(self.headers.get('Content-Length', '0')))
            entered.set()
            assert release.wait(30)
            self.reply(400)
        do_PUT = do_PATCH
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Registry)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(cert/'ca.crt'), str(root/'key'))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tag = f'localhost:{server.server_port}/test/image:latest'
    (context/'Dockerfile').write_text('FROM scratch\nCOPY shell /payload\n')
    result = subprocess.run([binary, 'build', '-t', tag, str(context)], env=env, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    log = (root/'push.log').open('wb')
    with (store/'store.lock').open('rb') as maintenance:
        fcntl.flock(maintenance, fcntl.LOCK_EX)
        cli = subprocess.Popen([binary, 'push', tag, '--cert-dir', str(cert)], env=env, stdout=log, stderr=log)
        time.sleep(.2)
        assert cli.poll() is None and not children(cli.pid) and not entered.is_set()
    assert entered.wait(30), (root/'push.log').read_text()
    guard, = children(cli.pid)
    workload = tree(guard)
    assert workload
    no_leak(store, workload)
    cli.kill(); cli.wait()
    assert not exclusive(store), 'CLI SIGKILL released transfer lease'
    assert all(Path(f'/proc/{pid}').exists() for pid in workload)
    release.set()
    reap_guard(guard, store)
    assert all(not Path(f'/proc/{pid}').exists() for pid in workload)
    log.close()
    server.shutdown(); server.server_close()
    print('PASS real Skopeo TLS blob transfer: parent SIGKILL, backend alive, no fd leak, final grant', flush=True)


if __name__ == '__main__': main()
