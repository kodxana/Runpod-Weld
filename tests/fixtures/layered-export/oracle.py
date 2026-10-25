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
import struct
import subprocess
import tarfile
import tempfile
from decimal import Decimal
from fixture_tar import FixtureInfo


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
    if "history" in config:
        assert sum(not entry.get("empty_layer", False) for entry in config["history"]) == len(manifest["layers"]), "history/diff-ID mismatch"
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

    def timestamps(member, path):
        ns = lambda value: int(Decimal(str(value)) * 1_000_000_000)
        mtime = member.pax_headers.get("mtime", member.mtime)
        # Deterministic replay convention, not an OCI requirement for atime.
        os.utime(path, ns=(ns(member.pax_headers.get("atime", mtime)), ns(mtime)), follow_symlinks=False)

    def extract(archive, member):
        # One member at a time retains tar ordering, including links to lower
        # inodes subsequently replaced by a later regular-file header.
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w", format=tarfile.PAX_FORMAT) as single:
            single.addfile(member, archive.extractfile(member) if member.isfile() else None)
        subprocess.run(["tar", "--extract", "--file=-", "--directory", str(destination),
                        "--numeric-owner", "--same-owner", "--same-permissions",
                        "--xattrs", "--xattrs-include=*"],
                       input=data.getvalue(), check=True, capture_output=True)
        timestamps(member, destination / member.name)

    for desc in manifest["layers"]:
        root_before = destination.stat()
        data = verified(layout, desc)
        if desc["mediaType"].endswith("+gzip"):
            data = gzip.decompress(data)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members = archive.getmembers()
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
            directories = {}
            explicit_root = False
            for member in members:
                if Path(member.name).name.startswith(".wh."):
                    continue
                path = destination / member.name
                explicit_root |= Path(member.name) == Path(".")
                existing_directory = path.is_dir() and not path.is_symlink()
                if member.isdir() and existing_directory:
                    # A directory header replaces metadata, not children. Missing
                    # xattrs mean deletion; do not clear attrs of untouched dirs.
                    for attr in os.listxattr(path, follow_symlinks=False):
                        os.removexattr(path, attr, follow_symlinks=False)
                elif path.exists() or path.is_symlink():
                    remove(path)
                extract(archive, member)
                if member.isdir():
                    identity = path.stat()
                    directories[path] = (member, identity.st_dev, identity.st_ino)
            # Children alter parent times. Restore only surviving directory
            # headers, never a directory removed/replaced later in the archive.
            for path, (member, dev, ino) in reversed(list(directories.items())):
                if path.is_dir() and not path.is_symlink():
                    current = path.stat()
                    if (current.st_dev, current.st_ino) == (dev, ino):
                        timestamps(member, path)
            if not explicit_root:
                os.utime(destination, ns=(root_before.st_atime_ns, root_before.st_mtime_ns))
    return manifest, config


def snapshot(root):
    """Capture pre-read metadata; link reads may advance live atime, never restored."""
    result = {}
    inodes = {}
    def walk(path):
        s = path.lstat()
        yield path, s
        if stat.S_ISDIR(s.st_mode):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME)
            try:
                with os.scandir(fd) as entries:
                    names = sorted(e.name for e in entries)
                for name in names:
                    yield from walk(path / name)
            finally:
                os.close(fd)
    # Capture ALL entries before readlink/content reads can affect inode aliases.
    paths = list(walk(root))
    for path, s in paths:
        relative = str(path.relative_to(root))
        result[relative] = {"mode": s.st_mode, "uid": s.st_uid, "gid": s.st_gid,
                "mtime_ns": s.st_mtime_ns, "atime_ns": s.st_atime_ns,
                "xattrs": {k: os.getxattr(path, k, follow_symlinks=False).hex()
                           for k in sorted(os.listxattr(path, follow_symlinks=False))}}
    for path, s in paths:
        relative = str(path.relative_to(root))
        item = result[relative]
        if stat.S_ISREG(s.st_mode):
            fd = os.open(path, os.O_RDONLY | os.O_NOATIME)
            with os.fdopen(fd, "rb") as f:
                item["sha256"] = hashlib.file_digest(f, "sha256").hexdigest()
            identity = (s.st_dev, s.st_ino)
            item["hardlink_group"] = inodes.setdefault(identity, relative)
        elif stat.S_ISLNK(s.st_mode):
            item["target"] = os.readlink(path)
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
                for name, kind, content, *extra in entries:
                    entry = FixtureInfo(name)
                    entry.uid, entry.gid, entry.mode, entry.mtime = 123, 456, 0o750, 1700000000
                    entry.uname = entry.gname = "root"  # Deliberately conflicts with numeric ownership.
                    entry.type = kind
                    entry.pax_headers = {"atime": "1700000000.125"}
                    if kind == tarfile.REGTYPE:
                        entry.size = len(content)
                        entry.pax_headers["SCHILY.xattr.user.fixture"] = "preserved"
                    elif kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                        entry.linkname = content.decode()
                        if kind == tarfile.SYMTYPE:
                            entry.mode = 0o777
                    if extra:
                        entry.pax_headers.update(extra[0])
                    archive.addfile(entry, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
            encoded = data.getvalue()
            assert b"hdrcharset=" not in encoded
            with tarfile.open(fileobj=io.BytesIO(encoded)) as check:
                assert [os.fsencode(m.name) for m in check.getmembers()] == [os.fsencode(e[0]) for e in entries]
            return blob(encoded, "application/vnd.oci.image.layer.v1.tar")
        layers = [layer([(".", tarfile.DIRTYPE, b""), ("removed", tarfile.REGTYPE, b"old"),
                         ("replace", tarfile.REGTYPE, b"old"), ("opaque", tarfile.DIRTYPE, b""),
                         ("opaque/lower", tarfile.REGTYPE, b"old"),
                         ("a", tarfile.REGTYPE, b"old"),
                         ("dir", tarfile.DIRTYPE, b"", {"SCHILY.xattr.user.old": "stale"}),
                         ("dir/child", tarfile.REGTYPE, b"preserve child"),
                         ("untouched", tarfile.DIRTYPE, b"", {"SCHILY.xattr.user.keep": "keep"})]),
                  layer([(".wh.removed", tarfile.REGTYPE, b""), (".wh.replace", tarfile.REGTYPE, b""),
                         ("replace", tarfile.DIRTYPE, b""), ("replace/file", tarfile.REGTYPE, b"new"),
                         ("replace/link", tarfile.LNKTYPE, b"replace/file"),
                         ("opaque/.wh..wh..opq", tarfile.REGTYPE, b""),
                         ("opaque/upper", tarfile.SYMTYPE, b"../replace/file"),
                         ("dir", tarfile.DIRTYPE, b""),
                         ("b", tarfile.LNKTYPE, b"a"), ("a", tarfile.REGTYPE, b"new"),
                         (os.fsdecode(b"raw-\xff"), tarfile.REGTYPE, b"raw name"),
                         ("cap", tarfile.REGTYPE, b"capability", {
                             "SCHILY.xattr.security.capability": os.fsdecode(struct.pack("<5I", 0x02000001, 1024, 0, 0, 0))})])]
        config_value = {"rootfs": {"diff_ids": [d["digest"] for d in layers]},
                        "history": [{"created_by": "lower"}, {"empty_layer": True}, {"created_by": "upper"}]}
        config = blob(json.dumps(config_value).encode(),
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
        assert tree["."]["uid"] == 123 and tree["."]["gid"] == 456
        assert tree["."]["mtime_ns"] == 1700000000000000000
        assert tree["."]["atime_ns"] == 1700000000125000000, "missing root header lost lower root metadata"
        assert tree["dir"]["xattrs"] == {}, "directory header retained deleted xattr"
        assert tree["untouched"]["xattrs"] == {"user.keep": b"keep".hex()}
        assert (root / "replay/dir/child").read_bytes() == b"preserve child"
        assert (root / "replay/a").read_bytes() == b"new"
        assert (root / "replay/b").read_bytes() == b"old", "ordered hardlink lost lower inode"
        assert tree["a"]["hardlink_group"] != tree["b"]["hardlink_group"]
        assert (os.fsdecode(b"raw-\xff")) in tree
        assert tree["cap"]["xattrs"]["security.capability"] == struct.pack("<5I", 0x02000001, 1024, 0, 0, 0).hex()
        original_index = (layout / "index.json").read_bytes()
        config_value["history"][1]["empty_layer"] = False
        bad_config = blob(json.dumps(config_value).encode(), config["mediaType"])
        bad_manifest = blob(json.dumps({"layers": layers, "config": bad_config}).encode(), manifest["mediaType"])
        (layout / "index.json").write_text(json.dumps({"manifests": [bad_manifest]}))
        try:
            load(layout)
        except AssertionError as error:
            assert "history/diff-ID" in str(error)
        else:
            raise AssertionError("inconsistent empty_layer history accepted")
        (layout / "index.json").write_bytes(original_index)
        corrupt = blobs / layers[0]["digest"].split(":")[1]
        data = bytearray(corrupt.read_bytes())
        data[0] ^= 1
        corrupt.write_bytes(data)  # Same-size digest corruption, not just truncation.
        try:
            load(layout)
        except AssertionError:
            pass
        else:
            raise AssertionError("corrupt layer accepted")


if __name__ == "__main__":
    self_test()
    print("independent replay self-test PASS")
