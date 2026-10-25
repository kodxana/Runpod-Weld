#!/usr/bin/env python3
"""Independent OCI verifier/replayer for trusted, test-generated Linux fixtures."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
from decimal import Decimal


def verified(layout, descriptor):
    algorithm, digest = descriptor["digest"].split(":")
    assert algorithm == "sha256"
    data = (layout / "blobs" / algorithm / digest).read_bytes()
    assert len(data) == descriptor["size"], descriptor
    assert hashlib.sha256(data).hexdigest() == digest, descriptor
    return data


def load(layout):
    index = json.loads((layout / "index.json").read_bytes())
    assert len(index["manifests"]) == 1
    manifest = json.loads(verified(layout, index["manifests"][0]))
    config = json.loads(verified(layout, manifest["config"]))
    assert len(manifest["layers"]) == len(config["rootfs"]["diff_ids"])
    for desc, diff in zip(manifest["layers"], config["rootfs"]["diff_ids"]):
        data = verified(layout, desc)
        if desc["mediaType"].endswith("+gzip"):
            data = gzip.decompress(data)
        assert "sha256:" + hashlib.sha256(data).hexdigest() == diff
    return manifest, config


def remove(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def replay(layout, destination):
    manifest, config = load(layout)
    destination.mkdir()
    for desc in manifest["layers"]:
        data = verified(layout, desc)
        if desc["mediaType"].endswith("+gzip"):
            data = gzip.decompress(data)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members = archive.getmembers()
            # Whiteouts apply to lower layers before extracting this layer.
            for member in members:
                path = Path(member.name)
                assert not path.is_absolute() and ".." not in path.parts
                if path.name == ".wh..wh..opq":
                    parent = destination / path.parent
                    if parent.exists():
                        for child in parent.iterdir():
                            remove(child)
                elif path.name.startswith(".wh."):
                    remove(destination / path.parent / path.name[4:])
            # GNU tar is independent of rpweld's importer, preserves PAX metadata,
            # and restores directories after their children.
            for member in members:
                if Path(member.name).name.startswith(".wh."):
                    continue
                path = destination / member.name
                if (path.exists() or path.is_symlink()) and not (
                        member.isdir() and path.is_dir() and not path.is_symlink()):
                    remove(path)
        subprocess.run(["tar", "--extract", "--file=-", "--directory", str(destination),
                        "--same-owner", "--same-permissions", "--xattrs", "--xattrs-include=*",
                        "--delay-directory-restore", "--exclude=.wh.*", "--exclude=*/.wh.*"],
                       input=data, check=True, capture_output=True)
        # GNU tar restores mtime but not PAX atime. Restore explicit timestamps
        # independently, after extraction, including the root directory entry.
        for member in reversed(members):
            if Path(member.name).name.startswith(".wh."):
                continue
            path = destination / member.name
            s = path.lstat()
            ns = lambda value: int(Decimal(str(value)) * 1_000_000_000)
            os.utime(path, ns=(ns(member.pax_headers["atime"]) if "atime" in member.pax_headers else s.st_atime_ns,
                               ns(member.pax_headers.get("mtime", member.mtime))), follow_symlinks=False)
    return manifest, config


def snapshot(root):
    result = {}
    inodes = {}
    def walk(path):
        yield path
        if path.is_dir() and not path.is_symlink():
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME)
            try:
                with os.scandir(fd) as entries:
                    names = sorted(e.name for e in entries)
                for name in names:
                    yield from walk(path / name)
            finally:
                os.close(fd)
    paths = walk(root)
    for path in paths:
        s = path.lstat()
        relative = str(path.relative_to(root))
        item = {"mode": s.st_mode, "uid": s.st_uid, "gid": s.st_gid,
                "mtime_ns": s.st_mtime_ns, "atime_ns": s.st_atime_ns,
                "xattrs": {k: os.getxattr(path, k, follow_symlinks=False).hex()
                           for k in sorted(os.listxattr(path, follow_symlinks=False))}}
        if stat.S_ISREG(s.st_mode):
            fd = os.open(path, os.O_RDONLY | os.O_NOATIME)
            with os.fdopen(fd, "rb") as f:
                item["sha256"] = hashlib.file_digest(f, "sha256").hexdigest()
            identity = (s.st_dev, s.st_ino)
            item["hardlink_group"] = inodes.setdefault(identity, relative)
        elif stat.S_ISLNK(s.st_mode):
            item["target"] = os.readlink(path)
        result[relative] = item
    return result


def self_test():
    with tempfile.TemporaryDirectory(prefix="layered-oracle-") as directory:
        root = Path(directory)
        layout = root / "oci"
        blobs = layout / "blobs/sha256"
        blobs.mkdir(parents=True)
        def blob(data, media):
            digest = hashlib.sha256(data).hexdigest()
            (blobs / digest).write_bytes(data)
            return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media}
        def layer(entries):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, kind, content in entries:
                    entry = tarfile.TarInfo(name)
                    entry.uid, entry.gid, entry.mode, entry.mtime = 123, 456, 0o750, 1700000000
                    entry.type = kind
                    if kind == tarfile.REGTYPE:
                        entry.size = len(content)
                        entry.pax_headers = {"SCHILY.xattr.user.fixture": "preserved", "atime": "1700000000.125"}
                    elif kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                        entry.linkname = content.decode()
                    archive.addfile(entry, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
            return blob(data.getvalue(), "application/vnd.oci.image.layer.v1.tar")
        layers = [layer([(".", tarfile.DIRTYPE, b""), ("removed", tarfile.REGTYPE, b"old"),
                         ("replace", tarfile.REGTYPE, b"old"), ("opaque", tarfile.DIRTYPE, b""),
                         ("opaque/lower", tarfile.REGTYPE, b"old")]),
                  layer([(".wh.removed", tarfile.REGTYPE, b""), (".wh.replace", tarfile.REGTYPE, b""),
                         ("replace", tarfile.DIRTYPE, b""), ("replace/file", tarfile.REGTYPE, b"new"),
                         ("replace/link", tarfile.LNKTYPE, b"replace/file"),
                         ("opaque/.wh..wh..opq", tarfile.REGTYPE, b""),
                         ("opaque/upper", tarfile.SYMTYPE, b"../replace/file")])]
        config = blob(json.dumps({"rootfs": {"diff_ids": [d["digest"] for d in layers]}}).encode(),
                      "application/vnd.oci.image.config.v1+json")
        manifest = blob(json.dumps({"layers": layers, "config": config}).encode(),
                        "application/vnd.oci.image.manifest.v1+json")
        (layout / "index.json").write_text(json.dumps({"manifests": [manifest]}))
        replay(layout, root / "replay")
        tree = snapshot(root / "replay")
        assert "removed" not in tree and "opaque/lower" not in tree
        assert tree["replace/file"]["hardlink_group"] == tree["replace/link"]["hardlink_group"]
        assert tree["replace/file"]["uid"] == 123 and tree["replace/file"]["gid"] == 456
        assert tree["replace/file"]["mode"] == stat.S_IFREG | 0o750
        assert tree["replace/file"]["mtime_ns"] == 1700000000000000000
        assert tree["replace/file"]["atime_ns"] == 1700000000125000000
        assert tree["replace/file"]["xattrs"]["user.fixture"] == b"preserved".hex()
        assert tree["opaque/upper"]["target"] == "../replace/file"
        (blobs / layers[0]["digest"].split(":")[1]).write_bytes(b"corrupt")
        try:
            load(layout)
        except AssertionError:
            pass
        else:
            raise AssertionError("corrupt layer accepted")


if __name__ == "__main__":
    self_test()
    print("independent replay self-test PASS")
