#!/usr/bin/env python3
"""Read-only, sequential acceptance of the sealed Nemotron fixture (no extraction).

Run after the builder exits, with the store quiescent and all earlier public
outputs retained. --run is the actual STORE/build-* directory, not evidence.
Deploy the reference/ directory alongside this file. No .git is required.
The acceptance JSON is evidence, not a reusable verification cache: every new
invocation rereads bytes. Only this invocation may reuse a verified inode.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import zlib

COMMIT = '91ee1316e21f624082c90cc07fcbbec1d9499550'
DOCKERFILE_SHA = 'b7774d1df6a47c8f5c542741257aee729e6d3b7992f8871ffa9e4d325cf2b81e'
REFERENCE_HASHES = {
    'context-91ee1316.tar.gz': '13d7ef64e39070a3e4f64b74597a66627d2837aed0edc112b40336ffa31a81e0',
    'assets.lock.json': 'a05f24d7f2078c67b59a38f3b9b648502e919863688bcd261e729082d4ba0104',
    'image-verification.json': 'd33b2e1bdb5e5dfe1f0bcdc4b994ce2ef823dd78e86b20eb5bb996d7e188640a',
}
CHUNK = 4 * 1024 * 1024
JSON_LIMIT = 16 * 1024 * 1024
RECORD_LIMIT = 16 * 1024
MAX_FILES = 100_000
MAX_LAYERS = 256
MAX_ENTRIES = 2_000_000
MAX_TAR_METADATA = 128 * 1024 * 1024
MAX_LAYER = 64 * 1024**3
MAX_UNPACKED = 128 * 1024**3
MAX_IO = 2 * 1024**4
MODEL_ROOT = 'runpod-volume/models'
MODEL_COUNT, MODEL_BYTES = 117, 25082020070
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
LAYER_TYPES = {
    'application/vnd.oci.image.layer.v1.tar': False,
    'application/vnd.oci.image.layer.v1.tar+gzip': True,
    'application/vnd.docker.image.rootfs.diff.tar.gzip': True,
}
HEX = re.compile(r'[0-9a-f]{64}\Z')


class Rejected(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def digest(value):
    require(isinstance(value, str) and value.startswith('sha256:') and
            HEX.fullmatch(value[7:]), 'invalid SHA256 digest')
    return value[7:]


def parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise Rejected('non-finite JSON number: ' + value)
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, RecursionError) as error:
        raise Rejected('invalid/beyond-depth JSON') from error


def path_name(name, *, posix=False):
    require(isinstance(name, str) and len(name.encode('utf-8', 'surrogateescape')) <= 4096,
            'path exceeds limit')
    # Layer names are POSIX strings, never host extraction destinations.
    require(not name.startswith('/') and (posix or '\\' not in name) and '\x00' not in name,
            'unsafe path: ' + repr(name))
    parts = [p for p in name.split('/') if p not in ('', '.')]
    require('..' not in parts, 'parent traversal: ' + repr(name))
    return '/'.join(parts)


def identity(path):
    s = path.lstat()
    return {'device': s.st_dev, 'inode': s.st_ino}


def signature(s):
    # atime/ctime/nlink change on reads and legitimate new cache aliases.
    return {'device': s.st_dev, 'inode': s.st_ino, 'uid': s.st_uid,
            'gid': s.st_gid, 'mode': s.st_mode, 'size': s.st_size,
            'mtime_ns': s.st_mtime_ns}


def real_path(path, directory=False):
    path = Path(os.path.abspath(path))
    for ancestor in reversed((path, *path.parents)):
        require(not ancestor.is_symlink(), 'symlink in input path: ' + str(ancestor))
    s = path.lstat()
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode),
            'wrong file type: ' + str(path))
    return s


def names(path):
    real_path(path, True)
    result = []
    with os.scandir(path) as entries:
        for entry in entries:
            require(len(result) < MAX_FILES, 'directory count exceeds limit')
            result.append(entry.name)
    return sorted(result)


def exact_names(path, expected):
    require(set(names(path)) == set(expected), 'unexpected directory contents: ' + str(path))


def walk(root):
    pending, count = [root], 0
    while pending:
        path = pending.pop()
        s = path.lstat()
        require(not stat.S_ISLNK(s.st_mode), 'symlink in evidence tree: ' + str(path))
        require(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode),
                'special file in evidence tree: ' + str(path))
        count += 1
        require(count <= MAX_FILES, 'tree count exceeds limit')
        yield path, s
        if stat.S_ISDIR(s.st_mode):
            pending.extend(path / name for name in reversed(names(path)))


class Files:
    def __init__(self):
        self.verified = {}
        self.bytes_read = 0

    def charge(self, size):
        self.bytes_read += size
        require(self.bytes_read <= MAX_IO, 'acceptance IO budget exceeded')

    def read(self, path, limit=JSON_LIMIT):
        before = real_path(path)
        require(before.st_size <= limit, 'file exceeds size limit: ' + str(path))
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            require(signature(os.fstat(stream.fileno())) == signature(before), 'file replaced before read')
            data = stream.read(limit + 1)
            require(signature(os.fstat(stream.fileno())) == signature(before), 'file mutated during read')
        self.charge(len(data))
        require(len(data) == before.st_size and len(data) <= limit, 'file changed/oversized')
        require(signature(path.lstat()) == signature(before), 'path changed during read')
        self.verified[tuple(signature(before).values())] = sha(data)
        return data

    def hash(self, path, limit=MAX_LAYER):
        before = real_path(path)
        require(before.st_size <= limit, 'file exceeds hash limit: ' + str(path))
        key = tuple(signature(before).values())
        if key in self.verified:
            return self.verified[key]
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        h, count = hashlib.sha256(), 0
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            require(signature(os.fstat(stream.fileno())) == signature(before), 'file replaced before hash')
            while data := stream.read(CHUNK):
                count += len(data)
                self.charge(len(data))
                require(count <= limit, 'growing file exceeds hash limit')
                h.update(data)
            require(signature(os.fstat(stream.fileno())) == signature(before), 'file mutated during hash')
        require(count == before.st_size and signature(path.lstat()) == signature(before), 'file changed during hash')
        self.verified[key] = h.hexdigest()
        return h.hexdigest()

    def document(self, path, limit=JSON_LIMIT):
        return parse(self.read(path, limit))

    def fingerprint(self, root):
        result = {}
        for path, s in walk(root):
            if stat.S_ISREG(s.st_mode):
                item = signature(s)
                item['sha256'] = self.hash(path)
                result[path.relative_to(root).as_posix()] = item
        return result


def references(files):
    root = Path(__file__).resolve().parent / 'reference'
    for name, expected in REFERENCE_HASHES.items():
        require(files.hash(root / name, JSON_LIMIT) == expected, 'reference seal mismatch: ' + name)
    old = files.document(root / 'image-verification.json')
    lock = files.document(root / 'assets.lock.json')
    require(old['pass'] is True and old['source_commit'] == COMMIT, 'invalid prior acceptance')
    source, contents = {}, {}
    with tarfile.open(root / 'context-91ee1316.tar.gz', 'r:gz', tarinfo=BoundedInfo) as archive:
        total = 0
        for member in archive:
            name = path_name(member.name)
            require(name and name not in source and len(source) < 1024, 'invalid source archive path')
            require(member.isfile() or member.isdir(), 'source archive special file')
            require(member.size <= JSON_LIMIT, 'source archive file too large')
            data = archive.extractfile(member).read(JSON_LIMIT + 1) if member.isfile() else b''
            total += len(data)
            require(total <= JSON_LIMIT and len(data) == member.size, 'source archive too large')
            source[name] = {'type': 'file' if member.isfile() else 'directory',
                            'mode': member.mode, 'size': member.size, 'sha256': sha(data)}
            if member.isfile():
                contents[name] = data
    require(sha(contents['Dockerfile']) == DOCKERFILE_SHA, 'canonical Dockerfile mismatch')
    require(parse(contents['assets.lock.json']) == lock, 'source archive/lock mismatch')
    return old, lock, source, contents


def verify_source(files, root, phase, sealed, contents):
    actual = {}
    for path, s in walk(root):
        if path == root:
            continue
        name = path.relative_to(root).as_posix()
        require(name in sealed, 'unexpected source path: ' + name)
        expected = sealed[name]
        require(stat.S_ISREG(s.st_mode) == (expected['type'] == 'file'), 'source type mismatch: ' + name)
        if os.name == 'posix':
            require(stat.S_IMODE(s.st_mode) == expected['mode'], 'source mode mismatch: ' + name)
        if expected['type'] == 'file':
            data = files.read(path)
            want = contents[name] + (b' \n' if phase == 'edit' and name == 'local_model_args.json' else b'')
            require(data == want, 'source content mismatch: ' + name)
            actual[name] = {'size': len(data), 'sha256': sha(data), 'mode': expected['mode']}
        else:
            actual[name] = expected
    require(actual.keys() == sealed.keys(), 'source paths missing')
    return actual


def expectations(lock, old, contents, phase):
    expected = {}
    count = total = 0
    for group in ('model', 'draft'):
        spec = lock[group]
        prefix = MODEL_ROOT + '/' + path_name(spec['directory']) + '/'
        for item in spec['files']:
            name = prefix + path_name(item['path'])
            require(name not in expected, 'duplicate locked model path')
            prior = old['verified_expected_files'][name]
            require(prior['regular'] is True and prior['size'] == item['size'] and
                    prior['uid'] == prior['gid'] == 0 and int(prior['mode'], 8) & 0o222 == 0,
                    'invalid prior model observation')
            pinned = item.get('sha256') or prior['sha256']
            require(HEX.fullmatch(pinned) and prior['sha256'] == pinned, 'prior/lock model hash mismatch')
            expected[name] = {'size': item['size'], 'sha256': pinned, 'readonly': True}
            count += 1
            total += item['size']
        revision = (spec['revision'] + '\n').encode()
        expected[prefix + '.revision'] = {'size': len(revision), 'sha256': sha(revision), 'readonly': True}
    require((count, total) == (MODEL_COUNT, MODEL_BYTES), 'model file count/bytes mismatch')
    copies = {'assets.lock.json': 'app/assets.lock.json', 'LICENSE': 'app/LICENSE',
              'NOTICE': 'app/NOTICE', 'handler.py': 'src/handler.py',
              'inference-overlay.lock': 'app/inference-overlay.lock',
              'requirements.lock': 'app/requirements.lock',
              'scripts/build_checks.py': 'app/scripts/build_checks.py',
              'local_model_args.json': 'local_model_args.json'}
    copies.update((name, 'app/' + name) for name in contents if name.startswith('licenses/'))
    for name, destination in copies.items():
        data = contents[name] + (b' \n' if phase == 'edit' and name == 'local_model_args.json' else b'')
        expected[destination] = {'size': len(data), 'sha256': sha(data), 'readonly': False}
    return expected


class BoundedInfo(tarfile.TarInfo):
    # tarfile reads extended headers before yielding members; cap them there.
    def _proc_pax(self, archive):
        require(self.size <= 1024 * 1024, 'PAX header exceeds limit')
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        require(self.size <= 4096, 'GNU long name exceeds limit')
        return super()._proc_gnulong(archive)

    def _proc_sparse(self, archive):
        raise Rejected('sparse tar entries unsupported')


class HashReader:
    def __init__(self, stream, limit, files):
        self.stream, self.limit, self.files = stream, limit, files
        self.hash, self.count = hashlib.sha256(), 0

    def read(self, size=-1):
        require(0 <= size <= CHUNK, 'unbounded stream read')
        data = self.stream.read(size)
        self.count += len(data)
        self.files.charge(len(data))
        require(self.count <= self.limit, 'layer streaming byte limit exceeded')
        self.hash.update(data)
        return data


class Layers:
    def __init__(self, files, expected):
        self.files, self.expected = files, expected
        self.memo = {}
        self.parents = {''}
        for name in [*expected, MODEL_ROOT, 'run/secrets/HF_TOKEN']:
            parts = name.split('/')
            self.parents.update('/'.join(parts[:i]) for i in range(1, len(parts)))

    def relevant(self, name):
        return (name in self.expected or name in self.parents or name == MODEL_ROOT or
                name.startswith(MODEL_ROOT + '/') or name == 'run/secrets/HF_TOKEN' or
                any(name.startswith(target + '/') for target in self.expected))

    def scan(self, path, descriptor, diff):
        before = real_path(path)
        key = tuple(signature(before).values())
        require(before.st_size == descriptor['size'], 'layer size mismatch')
        if key in self.memo:
            previous_desc, previous_diff, result = self.memo[key]
            require(descriptor == previous_desc and diff == previous_diff, 'same inode, inconsistent layer claim')
            return result
        require(descriptor['mediaType'] in LAYER_TYPES, 'unsupported layer compression')
        digest(diff)
        operations, whiteouts, entries, metadata_bytes = [], [], 0, 0
        only_local = True
        metadata_only, local_json_writes = True, 0
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        with os.fdopen(os.open(path, flags), 'rb') as file:
            require(signature(os.fstat(file.fileno())) == signature(before), 'layer replaced before read')
            raw = HashReader(file, MAX_LAYER, self.files)
            decompressor = gzip.GzipFile(fileobj=raw, mode='rb') if LAYER_TYPES[descriptor['mediaType']] else raw
            unpacked = HashReader(decompressor, MAX_UNPACKED, self.files)
            with tarfile.open(fileobj=unpacked, mode='r|', tarinfo=BoundedInfo) as archive:
                for member in archive:
                    archive.members.clear()
                    entries += 1
                    metadata_bytes += len(member.name.encode('utf-8', 'surrogateescape')) + 512
                    metadata_bytes += sum(len(k) + len(v) for k, v in member.pax_headers.items())
                    require(entries <= MAX_ENTRIES and metadata_bytes <= MAX_TAR_METADATA,
                            'layer entry/metadata budget exceeded')
                    require(member.sparse is None, 'sparse member unsupported')
                    require(integer(member.size, 0, MAX_LAYER), 'member size exceeds limit')
                    name = path_name(member.name, posix=True)
                    parent, _, leaf = name.rpartition('/')
                    if leaf.startswith('.wh.'):
                        require(member.isfile() and member.size == 0, 'invalid whiteout')
                        target = parent if leaf == '.wh..wh..opq' else (parent + '/' if parent else '') + leaf[4:]
                        require(leaf == '.wh..wh..opq' or leaf not in ('.wh.', '.wh..', '.wh...'), 'invalid whiteout name')
                        if self.relevant(target):
                            whiteouts.append((target, leaf == '.wh..wh..opq'))
                        only_local = False
                        metadata_only = False
                        continue
                    only_local &= name == 'local_model_args.json' or (not name and member.isdir())
                    metadata_only &= not name and member.isdir() and member.size == 0
                    local_json_writes += int(name == 'local_model_args.json' and member.isfile())
                    if not self.relevant(name):
                        continue
                    kind = 'file' if member.isfile() else 'directory' if member.isdir() else 'other'
                    item = {'type': kind, 'size': member.size, 'uid': member.uid, 'gid': member.gid, 'mode': member.mode}
                    if member.isfile():
                        stream = archive.extractfile(member)
                        h, count = hashlib.sha256(), 0
                        while data := stream.read(CHUNK):
                            h.update(data)
                            count += len(data)
                        require(count == member.size, 'truncated tar member')
                        item['sha256'] = h.hexdigest()
                    operations.append((name, item))
            while unpacked.read(CHUNK):
                pass
            while raw.read(CHUNK):
                pass
            require(raw.count == descriptor['size'] and raw.hash.hexdigest() == digest(descriptor['digest']),
                    'layer compressed hash/size mismatch')
            require(unpacked.hash.hexdigest() == digest(diff), 'layer diffID mismatch')
            require(signature(os.fstat(file.fileno())) == signature(before), 'layer mutated during scan')
        require(signature(path.lstat()) == signature(before), 'layer path changed during scan')
        result = {'operations': operations, 'whiteouts': whiteouts, 'entries': entries,
                  'uncompressed_bytes': unpacked.count, 'only_local_json': only_local,
                  'local_json_writes': local_json_writes, 'metadata_only': metadata_only}
        self.files.verified[key] = raw.hash.hexdigest()
        self.memo[key] = descriptor, diff, result
        print(json.dumps({'event': 'layer_verified', 'digest': descriptor['digest'], 'entries': entries}), flush=True)
        return result


def apply_layer(state, layer, number):
    def erase(target, children_only=False):
        for name in list(state):
            if (name == target and not children_only) or not target or name.startswith(target + '/'):
                del state[name]
    # Whiteouts affect lower layers, even if tar order places them after additions.
    for target, opaque in layer['whiteouts']:
        erase(target, opaque)
    for name, value in layer['operations']:
        parts = name.split('/')
        for i in range(1, len(parts)):
            parent = '/'.join(parts[:i])
            require(parent not in state or state[parent]['type'] == 'directory',
                    'member traverses non-directory parent: ' + name)
            state.setdefault(parent, {'type': 'directory', 'implicit': True})
        if value['type'] != 'directory' or (name in state and state[name]['type'] != 'directory'):
            erase(name)
        state[name] = dict(value, layer=number)
        require(len(state) <= MAX_FILES, 'tracked filesystem exceeds limit')


def verify_targets(state, expected):
    actual_models = {name for name, value in state.items()
                     if name.startswith(MODEL_ROOT + '/') and value['type'] != 'directory'}
    want_models = {name for name in expected if name.startswith(MODEL_ROOT + '/')}
    require(actual_models == want_models, 'model tree has missing or extra files')
    for name, wanted in expected.items():
        require(name in state, 'required file missing: ' + name)
        item = state[name]
        require(item['type'] == 'file', 'required path is not regular: ' + name)
        require(item['uid'] == item['gid'] == 0, 'required file not root owned: ' + name)
        require(item['size'] == wanted['size'] and item['sha256'] == wanted['sha256'],
                'required file bytes mismatch: ' + name)
        require(not wanted['readonly'] or item['mode'] & 0o222 == 0, 'writable model file: ' + name)
    for name, item in state.items():
        if name == MODEL_ROOT or name.startswith(MODEL_ROOT + '/'):
            if item['type'] == 'directory' and not item.get('implicit'):
                require(item['uid'] == item['gid'] == 0 and item['mode'] & 0o222 == 0,
                        'model directory ownership/mode mismatch: ' + name)
    require('run/secrets/HF_TOKEN' not in state, 'secret present in final image')


def descriptor_path(layout, desc):
    require(isinstance(desc, dict) and integer(desc.get('size'), 0, MAX_LAYER), 'invalid blob descriptor')
    return layout / 'blobs/sha256' / digest(desc.get('digest'))


def image(files, layers, layout, replay=False):
    require(files.document(layout / 'oci-layout', RECORD_LIMIT) == {'imageLayoutVersion': '1.0.0'}, 'invalid OCI layout')
    index = files.document(layout / 'index.json')
    require(index.get('schemaVersion') == 2 and isinstance(index.get('manifests'), list) and
            len(index['manifests']) == 1, 'expected exactly one OCI manifest')
    selected = index['manifests'][0]
    def document(desc, media):
        require(desc.get('mediaType') == media, 'unexpected descriptor media type')
        data = files.read(descriptor_path(layout, desc))
        require(len(data) == desc['size'] and sha(data) == digest(desc['digest']), 'JSON blob digest mismatch')
        return parse(data)
    manifest = document(selected, MANIFEST)
    require(manifest.get('schemaVersion') == 2 and manifest.get('mediaType') == MANIFEST, 'invalid manifest')
    config = document(manifest['config'], CONFIG)
    require(config.get('os') == 'linux' and config.get('architecture') == 'amd64' and
            isinstance(config.get('config'), dict), 'wrong image platform/config')
    require(config.get('rootfs', {}).get('type') == 'layers', 'invalid rootfs type')
    diff_ids = config['rootfs']['diff_ids']
    descs = manifest['layers']
    require(isinstance(descs, list) and isinstance(diff_ids, list) and
            len(descs) == len(diff_ids) and len(descs) <= MAX_LAYERS, 'layer/diffID count mismatch')
    history = config.get('history')
    require(isinstance(history, list) and len(history) <= 4096 and
            all(isinstance(h, dict) and type(h.get('empty_layer', False)) is bool for h in history), 'invalid history')
    require(sum(not h.get('empty_layer', False) for h in history) == len(descs), 'history/layer count mismatch')
    state, summaries = {}, []
    for number, (desc, diff) in enumerate(zip(descs, diff_ids)):
        result = layers.scan(descriptor_path(layout, desc), desc, diff)
        if replay:
            apply_layer(state, result, number)
        summaries.append({key: value for key, value in result.items() if key not in ('operations', 'whiteouts')})
    return {'manifest': selected, 'manifest_document': manifest, 'config': config,
            'layers': summaries, 'files': state}


def validate_image_contract(final, runtime, base, old):
    n = old['base_layers']
    pinned = [layer['descriptor'] for layer in old['layers'][:n]]
    require(base['manifest'] == old['base_manifest'], 'base manifest differs from pinned observation')
    require(base['manifest_document']['layers'] == pinned, 'base layer descriptors changed')
    require(base['config']['rootfs']['diff_ids'] == old['config']['rootfs']['diff_ids'][:n], 'base diffIDs changed')
    old_history = old['config']['history'][:-2]
    require(base['config']['history'] == old_history, 'base history changed')
    require({k: v for k, v in final['config'].items() if k not in ('rootfs', 'history')} ==
            {k: v for k, v in old['config'].items() if k not in ('rootfs', 'history')}, 'full final image config changed')
    for lower, upper in ((base, runtime), (runtime, final)):
        ll = lower['manifest_document']['layers']
        require(len(upper['manifest_document']['layers']) >= len(ll) and
                upper['manifest_document']['layers'][:len(ll)] == ll, 'image descriptor prefix changed')
        ld = lower['config']['rootfs']['diff_ids']
        require(upper['config']['rootfs']['diff_ids'][:len(ld)] == ld, 'image diffID prefix changed')
        lh = lower['config']['history']
        require(upper['config']['history'][:len(lh)] == lh, 'image history prefix changed')
    require(len(final['manifest_document']['layers']) > len(runtime['manifest_document']['layers']), 'missing final filesystem delta')


def private(path, directory=False, metadata=False):
    s = real_path(path, directory)
    if os.name == 'posix':
        require(s.st_uid == os.geteuid() and s.st_mode & (0o022 if directory else 0o077) == 0,
                'cache permissions/owner mismatch: ' + str(path))
    if metadata:
        require(s.st_nlink == 1, 'cache metadata is hardlinked')
    return s


def audit_cache(files, layers, store):
    root = store / 'cache-v2'
    # Bound the entire namespace before per-entry traversal, not just each directory.
    for path, s in walk(root):
        private(path, directory=stat.S_ISDIR(s.st_mode))
    exact_names(root, ['weld-cache-owner.json', 'publication.lock', 'entries', 'content', 'objects'])
    exact_names(root / 'content', ['blobs'])
    exact_names(root / 'content/blobs', ['sha256'])
    def record(path):
        private(path, metadata=True)
        return files.document(path, RECORD_LIMIT)
    owner = record(root / 'weld-cache-owner.json')
    expected_owner = {'version': 2}
    for name, path in {'store': store, 'root': root, 'entries': root / 'entries', 'content': root / 'content',
                       'blobs': root / 'content/blobs', 'sha256': root / 'content/blobs/sha256',
                       'objects': root / 'objects', 'lock': root / 'publication.lock'}.items():
        private(path, directory=name != 'lock', metadata=name == 'lock')
        expected_owner[name] = identity(path)
    require(owner == expected_owner, 'cache namespace identity mismatch')
    objects, aliases, ids = {}, {}, set()
    for key in names(root / 'objects'):
        require(HEX.fullmatch(key), 'unexpected cache object/staging')
        obj = root / 'objects' / key
        private(obj, True)
        exact_names(obj, ['weld-cache-blob.json', 'blobs'])
        exact_names(obj / 'blobs', ['sha256'])
        exact_names(obj / 'blobs/sha256', [key])
        blob = obj / 'blobs/sha256' / key
        s = private(blob)
        wanted = {'version': 1, 'namespace': owner['root'], 'directory': identity(obj),
                  'inode': identity(blob), 'digest': 'sha256:' + key, 'size': s.st_size}
        require(record(obj / 'weld-cache-blob.json') == wanted, 'blob provenance mismatch')
        ident = (s.st_dev, s.st_ino)
        require(ident not in ids, 'cache objects alias each other')
        ids.add(ident)
        objects[key] = ident
        aliases[key] = [1, s.st_nlink]
    def alias(path, key):
        s = private(path)
        require(key in objects and (s.st_dev, s.st_ino) == objects[key], 'cache alias not owned pool inode')
        aliases[key][0] += 1
    exact_names(root / 'content/blobs/sha256', objects)
    for key in objects:
        alias(root / 'content/blobs/sha256' / key, key)
    entries = {}
    for key in names(root / 'entries'):
        require(HEX.fullmatch(key), 'unexpected cache entry/staging')
        entry = root / 'entries' / key
        private(entry, True)
        exact_names(entry, ['weld-cache-entry.json', 'weld-copy-targets.json', 'oci-layout', 'index.json', 'blobs'])
        exact_names(entry / 'blobs', ['sha256'])
        saved = record(entry / 'weld-cache-entry.json')
        require(set(saved) == {'version', 'store', 'namespace', 'directory', 'key', 'manifest', 'receipt', 'instructions'}, 'cache entry fields changed')
        require(saved['version'] == 1 and saved['store'] == owner['store'] and
                saved['namespace'] == owner['root'] and saved['directory'] == identity(entry) and saved['key'] == key,
                'cache entry identity mismatch')
        for name in ('weld-copy-targets.json', 'oci-layout', 'index.json'):
            private(entry / name, metadata=True)
        receipt_data = files.read(entry / 'weld-copy-targets.json')
        receipt = parse(receipt_data)
        require(integer(saved['instructions'], 0, 4096) and isinstance(receipt, list) and
                len(receipt) == saved['instructions'], 'receipt instruction count mismatch')
        paths = 0
        for instruction in receipt:
            require(isinstance(instruction, list), 'invalid receipt instruction')
            for target in instruction:
                paths += 1
                require(paths <= MAX_FILES and isinstance(target, list) and len(target) <= 4096 and
                        all(integer(byte, 0, 255) for byte in target), 'invalid receipt byte path')
                value = bytes(target).decode('utf-8', 'surrogateescape')
                path_name(value.lstrip('/'))
        canonical = json.dumps(receipt, separators=(',', ':')).encode()
        require(sha(canonical) == saved['receipt'], 'cache receipt hash mismatch')
        loaded = image(files, layers, entry)
        require(loaded['manifest']['digest'] == saved['manifest'], 'cache entry manifest mismatch')
        descriptors = [loaded['manifest'], loaded['manifest_document']['config'], *loaded['manifest_document']['layers']]
        wanted = {digest(d['digest']) for d in descriptors}
        exact_names(entry / 'blobs/sha256', wanted)
        for key_digest in wanted:
            alias(entry / 'blobs/sha256' / key_digest, key_digest)
        entries[key] = {'manifest': saved['manifest'], 'instructions': saved['instructions']}
    require(entries, 'no managed cache entries')
    require(all(actual == expected for actual, expected in aliases.values()), 'unaccounted cache hardlink alias')
    fingerprints = files.fingerprint(root)
    for name, fp in fingerprints.items():
        if '/blobs/sha256/' in '/' + name:
            require(fp['sha256'] == name.rsplit('/', 1)[-1], 'cache blob hash mismatch')
    return {'entries': entries, 'objects': len(objects), 'fingerprints': fingerprints}


def audit_base(files, layers, store, old):
    root = store / 'base-cache-v1'
    for path, s in walk(root):
        private(path, directory=stat.S_ISDIR(s.st_mode))
    matches = []
    generations = {}
    for name in names(root / 'generations'):
        require(re.fullmatch(r'gen-[A-Za-z0-9-]{1,124}', name), 'unexpected base generation')
        loaded = image(files, layers, root / 'generations' / name)
        generations[name] = loaded
        if loaded['manifest'] == old['base_manifest']:
            matches.append(loaded)
    require(len(matches) == 1, 'expected one pinned base generation')
    for name in names(root / 'refs'):
        require(re.fullmatch(r'[0-9a-f]{64}\.(json|lock)', name), 'unexpected base ref')
        if name.endswith('.json'):
            ref = files.document(root / 'refs' / name, RECORD_LIMIT)
            require(ref['version'] == 1 and ref['platform'] == 'linux/amd64' and
                    ref['generation'] in generations and ref['selected'] == generations[ref['generation']]['manifest'],
                    'base reference mismatch')
            require(sha((ref['reference'] + '\nlinux/amd64').encode()) == name[:-5], 'base ref key mismatch')
            require(ref['source_digest'] == ref['reference'].split('@', 1)[1], 'base source digest mismatch')
    # Include every blob, including pool objects not reached by the selected base.
    fingerprints = files.fingerprint(root)
    for name, fp in fingerprints.items():
        if '/blobs/sha256/' in '/' + name:
            require(fp['sha256'] == name.rsplit('/', 1)[-1], 'base blob hash mismatch')
    return matches[0], fingerprints


def public_outputs(store):
    outputs = []
    for name in names(store):
        if not name.startswith('build-'):
            continue
        run = store / name
        real_path(run, True)
        if (run / 'image').exists():
            outputs.append(run / 'image')
        if (run / 'stages').exists():
            for stage in names(run / 'stages'):
                if re.fullmatch(r'stage-\d+-image', stage):
                    outputs.append(run / 'stages' / stage)
        require(len(outputs) <= 1024, 'too many public outputs')
    return sorted(outputs)


def isolation(files, store, cache_fps, base_fps):
    cache_ids = {(f['device'], f['inode']) for fp in (cache_fps, base_fps) for f in fp.values()}
    outputs, seen = {}, {}
    for output in public_outputs(store):
        snapshot = files.fingerprint(output)
        for name, fp in snapshot.items():
            if '/blobs/sha256/' in '/' + name:
                require(fp['sha256'] == name.rsplit('/', 1)[-1], 'public blob hash mismatch')
            ident = fp['device'], fp['inode']
            require(ident not in cache_ids, 'public output aliases cache: ' + str(output / name))
            require(ident not in seen, 'public output aliases another public file: ' + str(output / name))
            seen[ident] = str(output / name)
        outputs[output.relative_to(store).as_posix()] = snapshot
    return outputs


def retained(previous, current, message):
    for key, value in previous.items():
        require(current.get(key) == value, message + ': ' + key)


def phase_contract(phase, current, previous):
    if phase == 'cold':
        require(previous is None, 'cold must not have previous acceptance')
        return
    require(previous is not None and previous.get('pass') is True and previous.get('schema') == 1,
            'missing/invalid previous acceptance')
    require(previous['phase'] == ('cold' if phase == 'warm' else 'warm'), 'phase predecessor mismatch')
    require(previous['source_commit'] == COMMIT and previous['store'] == current['store'] and
            previous['store_identity'] == current['store_identity'], 'previous store/source identity mismatch')
    require(previous['run'] != current['run'], 'phase reused previous run')
    retained(previous['cache']['fingerprints'], current['cache']['fingerprints'], 'prior cache file changed')
    retained(previous['base_fingerprints'], current['base_fingerprints'], 'prior base cache file changed')
    retained(previous['public_outputs'], current['public_outputs'], 'prior public output changed')
    before, after = previous['image'], current['image']
    if phase == 'warm':
        require(before['manifest'] == after['manifest'] and before['manifest_document'] == after['manifest_document'] and
                before['config'] == after['config'], 'warm image/config not exactly equal')
    else:
        old_layers, new_layers = before['manifest_document']['layers'], after['manifest_document']['layers']
        def json_boundary(image):
            summaries = image['layers']
            require(len(summaries) == len(image['manifest_document']['layers']), 'missing layer scope evidence')
            candidates = [i for i, layer in enumerate(summaries) if layer.get('local_json_writes', 0)]
            require(candidates, 'no local JSON layer found')
            boundary = candidates[-1]
            require(summaries[boundary]['local_json_writes'] == 1 and summaries[boundary]['only_local_json'],
                    'local JSON layer changed unrelated paths')
            require(image['files']['local_model_args.json']['layer'] == boundary,
                    'local JSON final file not from identified layer')
            require(all(layer.get('metadata_only') is True for layer in summaries[boundary + 1:]),
                    'post-JSON suffix contains payload, non-root entries or whiteouts')
            return boundary
        boundary = json_boundary(before)
        require(json_boundary(after) == boundary, 'edit moved local JSON layer')
        require(len(old_layers) == len(new_layers) and old_layers[:boundary] == new_layers[:boundary] and
                old_layers[boundary] != new_layers[boundary], 'edit did not retain exact pre-JSON layer prefix')
        old_config, new_config = before['config'], after['config']
        require(old_config['rootfs']['diff_ids'][:boundary] == new_config['rootfs']['diff_ids'][:boundary] and
                old_config['rootfs']['diff_ids'][boundary] != new_config['rootfs']['diff_ids'][boundary],
                'edit pre-JSON diffID prefix mismatch')
        require({k: v for k, v in old_config.items() if k != 'rootfs'} ==
                {k: v for k, v in new_config.items() if k != 'rootfs'}, 'edit changed image config/history')


def accept(source, store, run, phase, previous_path=None):
    require(os.name == 'posix', 'real acceptance requires Linux inode/ownership semantics')
    for root in (source, store, run):
        real_path(root, True)
    require(run.parent == store and run.name.startswith('build-'), '--run must be STORE/build-*')
    files = Files()
    old, lock, sealed, contents = references(files)
    source_snapshot = verify_source(files, source, phase, sealed, contents)
    expected = expectations(lock, old, contents, phase)
    layers = Layers(files, expected)
    previous = files.document(previous_path, 32 * 1024 * 1024) if previous_path else None
    record = files.document(run / 'build-record.json', 64 * 1024)
    require(record['phase'] == 'complete' and record['store'] == identity(store) and
            record['run'] == identity(run) and record['run_id'] == run.name, 'build record incomplete/identity mismatch')
    base, base_fps = audit_base(files, layers, store, old)
    cache = audit_cache(files, layers, store)
    runtime = image(files, layers, run / 'stages/stage-0-image')
    final = image(files, layers, run / 'image', replay=True)
    require(all(final['manifest'][key] == record['manifest'][key] for key in ('digest', 'size', 'mediaType')),
            'build record manifest mismatch')
    validate_image_contract(final, runtime, base, old)
    verify_targets(final['files'], expected)
    for root in (run / 'work/rootfs', run / 'stages/stage-1-work/rootfs'):
        require(not os.path.lexists(root / 'run/secrets/HF_TOKEN'), 'secret remains in work root')
    for output in public_outputs(store):
        image(files, layers, output)
    output_snapshots = isolation(files, store, cache['fingerprints'], base_fps)
    result = {'schema': 1, 'pass': True, 'phase': phase, 'source_commit': COMMIT,
              'source_archive_sha256': REFERENCE_HASHES['context-91ee1316.tar.gz'],
              'source': str(source), 'source_files': source_snapshot,
              'store': str(store), 'store_identity': identity(store), 'run': str(run),
              'image': final, 'base_manifest': base['manifest'], 'cache': cache,
              'base_fingerprints': base_fps, 'public_outputs': output_snapshots,
              'model_pinned_file_count': MODEL_COUNT, 'model_pinned_bytes': MODEL_BYTES,
              'bytes_read': files.bytes_read, 'inference_tested': False}
    phase_contract(phase, result, previous)
    # Quiescent-store contract: detect metadata changes since each verified read.
    for root, fingerprints in ((store / 'cache-v2', cache['fingerprints']), (store / 'base-cache-v1', base_fps)):
        for name, fp in fingerprints.items():
            require(signature((root / name).lstat()) == {k: v for k, v in fp.items() if k != 'sha256'},
                    'cache changed during acceptance: ' + name)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'store', 'run', 'phase', 'output'):
        parser.add_argument('--' + name, required=True, **({'choices': ('cold', 'warm', 'edit')} if name == 'phase' else {'type': Path}))
    parser.add_argument('--previous', type=Path)
    args = parser.parse_args(argv)
    started = time.monotonic()
    output = Path(os.path.abspath(args.output))
    require(not output.exists() and not output.is_symlink(), '--output must be a fresh file')
    for root in (args.source, args.store):
        require(not output.is_relative_to(Path(os.path.abspath(root))), '--output must be outside source and store')
    try:
        result = accept(*(Path(os.path.abspath(p)) for p in (args.source, args.store, args.run)),
                        args.phase, args.previous)
        code = 0
    except (Rejected, OSError, KeyError, TypeError, ValueError, IndexError, tarfile.TarError, EOFError, zlib.error) as error:
        result = {'schema': 1, 'pass': False, 'phase': args.phase,
                  'error': type(error).__name__ + ': ' + str(error), 'inference_tested': False}
        code = 1
    result['elapsed_seconds'] = time.monotonic() - started
    encoded = json.dumps(result, indent=2, sort_keys=True).encode() + b'\n'
    if len(encoded) >= 32 * 1024 * 1024:
        result = {'schema': 1, 'pass': False, 'phase': args.phase, 'error': 'acceptance output exceeds 32 MiB limit'}
        encoded = json.dumps(result).encode() + b'\n'
        code = 1
    with output.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps({'pass': result['pass'], 'output': str(output), 'elapsed_seconds': time.monotonic() - started}), flush=True)
    return code


if __name__ == '__main__':
    sys.exit(main())
