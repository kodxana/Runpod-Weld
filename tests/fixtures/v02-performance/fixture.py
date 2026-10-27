#!/usr/bin/env python3
"""Deterministic offline synthetic dependency workload; no language/model downloads."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "layered-export"))
from fixture_tar import FixtureInfo

ATIME, MTIME = 2000000001, 2000000000
TIMES = (ATIME * 10**9, MTIME * 10**9)
LAYER = "application/vnd.oci.image.layer.v1.tar"
CONFIG = "application/vnd.oci.image.config.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOATIME", 0))
    with os.fdopen(fd, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pin(path):
    os.utime(path, ns=TIMES, follow_symlinks=False)


def blob(layout, data, media):
    checksum = hashlib.sha256(data).hexdigest()
    (layout / "blobs/sha256" / checksum).write_bytes(data)
    return {"digest": "sha256:" + checksum, "size": len(data), "mediaType": media}


def make_base(busybox, layout):
    """Use an existing static amd64 BusyBox; its hash is part of the evidence."""
    binary = busybox.read_bytes()
    assert binary[:4] == b"\x7fELF" and binary[4:6] == b"\x02\x01"
    assert int.from_bytes(binary[18:20], "little") == 62, "amd64 BusyBox required"
    # PT_INTERP means this binary needs an unbundled dynamic loader.
    offset = int.from_bytes(binary[32:40], "little")
    size = int.from_bytes(binary[54:56], "little")
    count = int.from_bytes(binary[56:58], "little")
    assert all(int.from_bytes(binary[offset+i*size:offset+i*size+4], "little") != 3
               for i in range(count)), "BusyBox must be static"
    (layout / "blobs/sha256").mkdir(parents=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        entries = [(n, tarfile.DIRTYPE, b"") for n in (".", "bin", "etc", "tmp", "deps", "config", "app")]
        entries += [("bin/busybox", tarfile.REGTYPE, binary), ("bin/sh", tarfile.SYMTYPE, b"busybox"),
                    ("etc/passwd", tarfile.REGTYPE, b"root:x:0:0:root:/:/bin/sh\n"),
                    ("etc/group", tarfile.REGTYPE, b"root:x:0:\n")]
        for name, kind, content in entries:
            item = FixtureInfo(name)
            item.type, item.uid, item.gid, item.mtime = kind, 0, 0, MTIME
            item.mode = 0o755 if kind == tarfile.DIRTYPE or name == "bin/busybox" else 0o644
            if name == "tmp":
                item.mode = 0o1777
            item.pax_headers = {"atime": str(ATIME)}
            if kind == tarfile.SYMTYPE:
                item.mode, item.linkname = 0o777, content.decode()
            if kind == tarfile.REGTYPE:
                item.size = len(content)
            archive.addfile(item, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    layer = blob(layout, buffer.getvalue(), LAYER)
    config = blob(layout, json.dumps({"architecture": "amd64", "os": "linux",
        "config": {"Env": ["PATH=/bin"], "WorkingDir": "/"},
        "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]},
        "history": [{"created_by": "offline pinned static BusyBox fixture"}]}).encode(), CONFIG)
    manifest = blob(layout, json.dumps({"schemaVersion": 2, "mediaType": MANIFEST,
        "config": config, "layers": [layer]}).encode(), MANIFEST)
    write_json(layout / "index.json", {"schemaVersion": 2, "manifests": [manifest]})
    write_json(layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})
    return hashlib.sha256(binary).hexdigest()


def normalize_command(paths):
    return (f"/bin/busybox touch -h -a -d @{ATIME} {paths} && "
            f"/bin/busybox touch -h -m -d @{MTIME} {paths}")


def make_context(context, mib=256, small_files=2048):
    assert mib >= 1 and small_files >= 1
    for name in ("dep/small", "config", "app"):
        (context / name).mkdir(parents=True)
    # SHAKE block stream is deterministic and not sparse/zero-filled/compressible.
    with (context / "dep/payload.bin").open("wb") as output:
        for index in range(mib):
            output.write(hashlib.shake_256(f"v02-dependency-{index}".encode()).digest(1024**2))
    for index in range(small_files):
        (context / "dep/small" / f"{index:06d}.dat").write_bytes(
            hashlib.shake_256(f"v02-small-{index}".encode()).digest(1024))
    (context / "config/settings").write_bytes(b"offline-setting=v1\n")
    (context / "config/settings").chmod(0o640)
    os.setxattr(context / "config/settings", "user.v02", b"preserve-exactly")
    (context / "app/main.txt").write_bytes(b"application-v1\n")
    dockerfile = "\n".join([
        "FROM fixture",
        "COPY dep/ /deps/",
        "RUN /bin/busybox test -s /deps/payload.bin && printf 'dependencies-ok\\n' > /deps/checked && "
        + normalize_command("/deps/checked /deps /") + " && echo V02_EXEC_dependencies",
        "COPY config/ /config/",
        "RUN /bin/busybox cat /config/settings > /config/generated && "
        + normalize_command("/config/generated /config /") + " && echo V02_EXEC_config",
        "COPY app/ /app/",
        "RUN /bin/busybox cat /app/main.txt /config/generated > /app/result && "
        "/bin/busybox ln -f /app/main.txt /app/alias && "
        "/bin/busybox ln -sf main.txt /app/link && /bin/busybox chmod 640 /app/result && "
        + normalize_command("/app/main.txt /app/alias /app/link /app/result /app /")
        + " && echo V02_EXEC_application",
        "ENV V02_FIXTURE=synthetic",
        "LABEL org.rpweld.fixture=v02-performance",
        'CMD ["/bin/busybox", "cat", "/app/result"]', ""])
    (context / "Dockerfile").write_text(dockerfile)
    for path in sorted(context.rglob("*"), reverse=True):
        pin(path)
    pin(context)


def edit_app(context):
    (context / "app/main.txt").write_bytes(b"application-v2\n")
    pin(context / "app/main.txt")
    pin(context / "app")
    pin(context)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--busybox", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--dependency-mib", type=int, default=256)
    parser.add_argument("--small-files", type=int, default=2048)
    args = parser.parse_args()
    os.umask(0o022)
    args.destination.mkdir(parents=True, exist_ok=False)
    busybox_hash = make_base(args.busybox, args.destination / "base")
    make_context(args.destination / "context", args.dependency_mib, args.small_files)
    write_json(args.destination / "fixture.json", {"kind": "synthetic-offline", "busybox_sha256": busybox_hash,
        "dependency_mib": args.dependency_mib, "small_files": args.small_files,
        "atime": ATIME, "mtime": MTIME})


if __name__ == "__main__":
    main()
