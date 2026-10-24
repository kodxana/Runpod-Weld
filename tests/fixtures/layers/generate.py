"""Independent Python tarfile fixtures; run explicitly, never during cargo test."""
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile

ROOT = Path(__file__).resolve().parent
manifest = {}
LONG = 'deep/' + 'p' * 140
TARGET = '../' + 't' * 140


def header(name, kind=tarfile.REGTYPE, size=0, link='', fmt=tarfile.USTAR_FORMAT, **kw):
    info = tarfile.TarInfo(name)
    info.type, info.size, info.linkname = kind, size, link
    info.mode, info.uid, info.gid, info.mtime = 0o644, 123, 456, 789
    for key, value in kw.items():
        setattr(info, key, value)
    return info.tobuf(format=fmt)


def padded(data):
    return data + bytes((-len(data)) % 512)


def record(key, value):
    body = key + b'=' + value + b'\n'
    length = len(body) + 2
    while len(str(length)) + 1 + len(body) != length:
        length = len(str(length)) + 1 + len(body)
    return str(length).encode() + b' ' + body


def extension(body, kind=tarfile.XHDTYPE):
    return header('metadata', kind, len(body)) + padded(body)


def file(name='sentinel', data=b'SENTINEL'):
    return header(name, size=len(data)) + padded(data)


def save(name, data, expected):
    assert len(data) <= 32768, name
    (ROOT / (name + '.tar')).write_bytes(data)
    manifest[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), expected=expected)


def archive(name, members, fmt):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=fmt) as tf:
        for info, content in members:
            tf.addfile(info, io.BytesIO(content))
    save(name, output.getvalue(), [dict(path=i.name, link=i.linkname, kind=i.type.decode(),
         size=i.size, uid=i.uid, gid=i.gid, mtime=str(i.mtime), pax=i.pax_headers) for i, _ in members])


def member(name, data=b'', kind=tarfile.REGTYPE, link='', **kw):
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.size = kind, link, len(data)
    info.mode, info.uid, info.gid, info.mtime = 0o644, 123, 456, 789
    for key, value in kw.items():
        setattr(info, key, value)
    return info, data


archive('pax', [member(LONG, b'PAX payload', uid=1 << 40, gid=(1 << 40) + 7,
    pax_headers={'mtime': '-1.250000001'}), member('symlink', kind=tarfile.SYMTYPE, link=TARGET,
    pax_headers={'mtime': '-0.000000001'}),
    member('sentinel', b'SENTINEL')], tarfile.PAX_FORMAT)
archive('gnu', [member('ordinary', b'GNU', mtime=-2), member(LONG, b'LONG', uid=1 << 40, gid=(1 << 40) + 7),
    member('symlink', kind=tarfile.SYMTYPE, link=TARGET), member('sentinel', b'SENTINEL')], tarfile.GNU_FORMAT)
archive('hardlinks', [member('forward', kind=tarfile.LNKTYPE, link='later'),
    member('lower', kind=tarfile.LNKTYPE, link='lower-layer/file'), member('later', b'TARGET'),
    member('backward', kind=tarfile.LNKTYPE, link='later')], tarfile.PAX_FORMAT)
END = bytes(1024)
body = record(b'size', b'513') + record(b'path', b'effective')
save('pax-size', extension(body) + header('raw', size=1) + padded(b'A' * 513) + file() + END,
     {'effective': {'raw_size': 1, 'size': 513, 'data_offset': 1536}, 'sentinel_offset': 3072})
binary = b'line1\nline2\x00key=value\xff'
save('pax-binary-xattr', extension(record(b'SCHILY.xattr.user.binary', binary)) + file() + END,
     {'xattr_name': 'user.binary', 'xattr_value_hex': binary.hex(), 'path': 'sentinel'})
for name, body in {'zero': b'0 path=x\n', 'short': b'3 path=x\n', 'overrun': b'99 path=x\n',
                   'nondigit': b'xx path=x\n', 'overflow': b'18446744073709551616 path=x\n',
                   'no-newline': b'9 path=xx', 'no-equals': b'9 pathxx\n'}.items():
    save('bad-pax-' + name, extension(body) + file() + END, 'reject malformed PAX record')
for kind in [b'x', b'L', b'K']:
    body = record(b'path', b'unused') if kind == b'x' else b'unused\x00'
    save('dangling-' + kind.decode(), extension(body, kind) + END, 'reject dangling extension')
save('global-semantic', extension(record(b'path', b'global'), b'g') + file() + END, 'reject global path')
save('pax-sparse', extension(record(b'GNU.sparse.map', b'0,1')) + file() + END, 'reject sparse metadata')
save('gnu-sparse', header('sparse', b'S', fmt=tarfile.GNU_FORMAT) + END, 'reject GNU sparse type')
for field, start in [('size', 124), ('mtime', 136)]:
    block = bytearray(header('overflow', fmt=tarfile.GNU_FORMAT))
    block[start:start + 12] = b'\x80\x00\x00\x01' + bytes(8)  # 2**64, NOT zero
    block[148:156] = b'        '
    block[148:156] = ('%06o\x00 ' % sum(block)).encode()
    save('base256-overflow-' + field, bytes(block) + END, 'reject full-width 2**64 numeric overflow')
save('metadata-flood', extension(b''.join(record(b'comment', b'x' * 100) for _ in range(100))) + file() + END,
     'accept with ample metadata budget; reject with 4096-byte metadata budget')
assert sum(x['bytes'] for x in manifest.values()) <= 131072
(ROOT / 'manifest.json').write_text(json.dumps({'producer': 'CPython ' + platform.python_version() +
    ' stdlib tarfile (PAX_FORMAT/GNU_FORMAT/USTAR_FORMAT); explicit byte mutations for adversarial cases',
    'fixtures': manifest}, indent=2) + '\n')
