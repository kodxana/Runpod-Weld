#!/usr/bin/env python3
"""Root-only real Ubuntu multi-stage/cache test. Retains owned corpus and logs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--binary', required=True)
p.add_argument('--layout', required=True)
a = p.parse_args()
root = Path(tempfile.mkdtemp(prefix='weld-multistage-', dir='/var/tmp'))
context = root/'context'
context.mkdir()
home = root/'home'
home.mkdir(mode=0o700)
env = dict(os.environ, HOME=str(home), RPWELD_HOME=str(home/'store'))
(context/'Dockerfile').write_text('''FROM ubuntu:24.04 AS dependencies
ARG MODE=verified
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y hello python3-venv
RUN python3 -m venv /opt/venv
FROM dependencies AS builder
WORKDIR /src
COPY app.py /src/app.py
RUN printf '%s' "$MODE" > /src/value && touch /builder-only && /opt/venv/bin/python -m py_compile /src/app.py && echo BUILD_STAGE_EXECUTED
FROM dependencies AS unused
RUN exit 7
FROM dependencies AS runtime
WORKDIR /app
ENV WELD_TEST=multi-stage
COPY --from=builder /src/app.py /app/app.py
COPY --from=1 /src/value /app/value
RUN /opt/venv/bin/python /app/app.py
CMD ["/opt/venv/bin/python", "/app/app.py"]
''')
app = '''import json,os,subprocess,sys
from pathlib import Path
print(json.dumps(dict(cwd=os.getcwd(),hello=subprocess.check_output(['hello'],text=True).strip(),marker=os.getenv('WELD_TEST'),venv=sys.prefix,value=Path('/app/value').read_text(),revision=REVISION)))
'''
(context/'app.py').write_text(app.replace('REVISION', '1'))
print('CORPUS '+str(root), flush=True)
def build(name, extra=(), success=True):
    # This fixture independently unpacks one full-tree layer below.
    command = [a.binary, 'build', '--export-mode', 'flattened', '-t', 'local/multistage:test', '--base', 'ubuntu:24.04='+a.layout,
               '--output', str(root/(name+'-image')), '--work-dir', str(root/(name+'-work')),
               '--run-timeout-seconds', '180', *extra, str(context)]
    r = subprocess.run(command, env=env, capture_output=True, text=True, timeout=240, cwd='/')
    output = r.stdout+r.stderr
    (root/(name+'.log')).write_text(output)
    assert (r.returncode == 0) == success, output
    print('PASS '+name+' cached='+str(output.count('CACHED (')), flush=True)
    return output
first = build('first')
assert first.count('Note: Weld runs trusted Dockerfiles only;') == 1
assert 'BUILD_STAGE_EXECUTED' in first and 'CACHED (' not in first
second = build('second')
assert second.count('CACHED (') == 3, second
assert 'BUILD_STAGE_EXECUTED' not in second and 'Note: Weld' not in second
(context/'app.py').write_text(app.replace('REVISION', '2'))
changed = build('changed')
assert changed.count('CACHED (') == 1 and 'BUILD_STAGE_EXECUTED' in changed, changed
selected = build('selected', ('--target', 'builder'))
assert selected.count('CACHED (') == 2, selected
failure = build('failure', ('--target', 'unused'), success=False)
assert 'RUN worker failed' in failure and not (root/'failure-image').exists()
failure2 = build('failure2', ('--target', 'unused'), success=False)
assert failure2.count('CACHED (') == 1 and 'RUN worker failed' in failure2
image = root/'changed-image'
config = json.loads(subprocess.check_output(['/usr/bin/skopeo','inspect','--config','oci:'+str(image)], text=True))
assert config['config']['Cmd'] == ['/opt/venv/bin/python','/app/app.py']
assert config['config']['WorkingDir'] == '/app'
assert 'WELD_TEST=multi-stage' in config['config']['Env']
index = json.loads((image/'index.json').read_text())
def blob(d):
    f = image/'blobs'/d['digest'].replace(':','/')
    assert hashlib.sha256(f.read_bytes()).hexdigest() == d['digest'].split(':')[1]
    return f
manifest = json.loads(blob(index['manifests'][0]).read_text())
assert len(manifest['layers']) == 1
layer = blob(manifest['layers'][0])
assert config['rootfs']['diff_ids'] == [manifest['layers'][0]['digest']]
unpack = root/'independent-root'
unpack.mkdir()
subprocess.run(['/usr/bin/tar','-xf',str(layer),'-C',str(unpack)],check=True,cwd='/')
assert not (unpack/'builder-only').exists() and not (unpack/'src').exists()
assert not (unpack/'etc/resolv.conf').exists() or not (unpack/'etc/resolv.conf').read_bytes()
runtime_env = dict(e.split('=',1) for e in config['config']['Env'])
result = subprocess.check_output(['/usr/sbin/chroot',str(unpack),'/bin/sh','-c','cd /app && exec /opt/venv/bin/python /app/app.py'],env=runtime_env,text=True,cwd='/')
value = json.loads(result)
assert value == dict(cwd='/app',hello='Hello, world!',marker='multi-stage',venv='/opt/venv',value='verified',revision=2), value
(root/'independent-output.json').write_text(result)
print(result.strip(), flush=True)
print('MULTISTAGE_UBUNTU_PASS', flush=True)
