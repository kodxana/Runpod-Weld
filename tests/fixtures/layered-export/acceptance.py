#!/usr/bin/env python3
"""Opt-in Linux CLI acceptance. Run only after the parent supplies a frozen binary."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import subprocess
import tarfile
import time

from oracle import load, replay, snapshot, verified
from fixture_tar import FixtureInfo
from live_metadata import assert_metadata, compile_probe, docker_metadata


def delta_members(output, base_count):
    manifest, _ = load(output)
    assert len(manifest["layers"]) == base_count + 1
    desc = manifest["layers"][-1]
    data = verified(output, desc)
    if desc["mediaType"].endswith("+gzip"):
        data = gzip.decompress(data)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = archive.getmembers()
    names = [str(Path(m.name)) for m in members]
    assert len(names) == len(set(names)), "duplicate delta paths"
    return data, dict(zip(names, members))


def loaded_reference(output):
    references = []
    for line in output.decode("utf-8", "strict").splitlines():
        for prefix in ["Loaded image ID: ", "Loaded image: "]:
            if line.startswith(prefix):
                references.append(line[len(prefix):].strip())
    assert len(references) == 1 and references[0], output
    return references[0]


def rich_base(alpine, output):
    shutil.copytree(alpine, output)
    manifest, config = load(output)
    def blob(data, media):
        digest = hashlib.sha256(data).hexdigest()
        (output / "blobs/sha256" / digest).write_bytes(data)
        return {"mediaType": media, "digest": "sha256:" + digest, "size": len(data)}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, kind, payload in [
            (".", tarfile.DIRTYPE, b""), ("probe", tarfile.DIRTYPE, b""),
            ("probe/keep", tarfile.REGTYPE, b"preserved\n"),
            ("probe/alias", tarfile.LNKTYPE, b"probe/keep"),
            ("probe/deleted", tarfile.REGTYPE, b"delete\n"),
            ("probe/to-dir", tarfile.REGTYPE, b"file\n"),
            ("probe/to-file", tarfile.DIRTYPE, b""),
            ("probe/to-file/child", tarfile.REGTYPE, b"child\n"),
            ("probe/link", tarfile.SYMTYPE, b"keep"),
            ("probe/split-main", tarfile.REGTYPE, b"old inode\n"),
            ("probe/split-peer", tarfile.LNKTYPE, b"probe/split-main"),
            ("probe/xattr-dir", tarfile.DIRTYPE, b""),
            (os.fsdecode(b"probe/raw-\xff"), tarfile.REGTYPE, b"raw filename\n"),
            ("probe/cap", tarfile.REGTYPE, b"capability bytes\n"),
        ]:
            item = FixtureInfo(name)
            item.type, item.uid, item.gid, item.mode, item.mtime = kind, 123, 456, 0o751, 1700000000
            item.pax_headers = {"atime": "1700000000.125", "mtime": "1700000000.25"}
            if kind == tarfile.REGTYPE:
                item.size = len(payload)
                item.pax_headers["SCHILY.xattr.user.layered"] = "base-value"
            elif kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                item.linkname = payload.decode()
                if kind == tarfile.SYMTYPE:
                    item.mode = 0o777
            if name == "probe/xattr-dir":
                item.pax_headers["SCHILY.xattr.user.old"] = "must disappear"
            if name == "probe/cap":
                item.pax_headers["SCHILY.xattr.security.capability"] = os.fsdecode(struct.pack("<5I", 0x02000001, 1024, 0, 0, 0))
            archive.addfile(item, io.BytesIO(payload) if kind == tarfile.REGTYPE else None)
    data = buffer.getvalue()
    assert b"hdrcharset=" not in data
    with tarfile.open(fileobj=io.BytesIO(data)) as check:
        raw = next(m for m in check if os.fsencode(m.name) == b"probe/raw-\xff")
        assert check.extractfile(raw).read() == b"raw filename\n"
    layer = blob(data, "application/vnd.oci.image.layer.v1.tar")
    layer["annotations"] = {"org.example.provenance": "preserve-this-descriptor"}
    manifest["layers"].append(layer)
    config["rootfs"]["diff_ids"].append(layer["digest"])
    config.setdefault("history", []).append({"created_by": "independent fixture"})
    config["config"].update({"Env": ["BASE=value"], "WorkingDir": "/probe",
                              "Cmd": ["/bin/sh"], "Labels": {"fixture": "layered"}, "User": "0:0"})
    manifest["config"] = blob(json.dumps(config).encode(), "application/vnd.oci.image.config.v1+json")
    desc = blob(json.dumps(manifest).encode(), "application/vnd.oci.image.manifest.v1+json")
    (output / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [desc]}))
    return manifest, config


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--layout", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--docker", action="store_true", help="require local Docker load/inspect/create/export acceptance")
    a = p.parse_args()
    assert os.geteuid() == 0
    a.evidence.mkdir(parents=True, exist_ok=False)
    base = a.evidence / "base"
    base_manifest, base_config = rich_base(a.layout, base)
    context = a.evidence / "context"
    context.mkdir()
    (context / "app").write_text("application-v1\n")
    store = a.evidence / "store"
    records = []

    def build(name, mode, dockerfile, extra=(), cache=store, expect=True):
        (context / "Dockerfile").write_text(dockerfile)
        output, work = a.evidence / (name + "-image"), a.evidence / (name + "-work")
        command = [str(a.binary), "build", "--no-host-dns", "--base", "fixture=" + str(base),
                   "-t", "layered-acceptance:test", "--output", str(output), "--work-dir", str(work), *extra, str(context)]
        if mode is not None:
            command[2:2] = ["--export-mode", mode]
        tags_before = {p.name: p.read_bytes() for p in cache.glob("tag-*.json")}
        result = subprocess.run(command, env=dict(os.environ, RPWELD_HOME=str(cache)), capture_output=True, timeout=120)
        (a.evidence / (name + ".stdout")).write_bytes(result.stdout)
        (a.evidence / (name + ".stderr")).write_bytes(result.stderr)
        records.append({"case": name, "command": command, "returncode": result.returncode})
        (a.evidence / "commands.json").write_text(json.dumps(records, indent=2))
        assert (result.returncode == 0) == expect, result.stderr.decode(errors="replace")
        if expect:
            load(output)
        else:
            assert not (output / "index.json").exists(), "failed build published an image"
            assert tags_before == {p.name: p.read_bytes() for p in cache.glob("tag-*.json")}, "failed build changed tags"
        return output, result.stdout + result.stderr

    def preserved(output, parent=base):
        manifest, config = load(output)
        parent_manifest, parent_config = load(parent)
        count = len(parent_manifest["layers"])
        assert manifest["layers"][:count] == parent_manifest["layers"]
        assert config["rootfs"]["diff_ids"][:count] == parent_config["rootfs"]["diff_ids"]
        assert config["rootfs"]["type"] == "layers"
        assert config["history"][:len(parent_config["history"])] == parent_config["history"]
        assert config["os"] == parent_config["os"] == "linux"
        assert config["architecture"] == parent_config["architecture"] == "amd64"
        for desc in parent_manifest["layers"]:
            assert verified(parent, desc) == verified(output, desc)
        assert len(manifest["layers"]) <= count + 1, "must be a cumulative delta, not instruction chain"
        return manifest, config

    # Same-store whole-stage cache must not return the previous export format.
    noop = "FROM fixture\n"
    default, _ = build("default-noop", None, noop)
    flat, _ = build("flat-noop", "flattened", noop)
    layered, _ = build("layered-noop", "layered", noop)
    flat_return, _ = build("flat-after-layered", "flattened", noop)
    preserved(layered)
    assert len(load(flat)[0]["layers"]) == 1
    assert len(load(flat_return)[0]["layers"]) == 1
    assert load(flat_return) == load(flat)
    assert load(default) == load(flat), "default export differs from explicit flattened"
    original = a.evidence / "original-replay"
    replay(base, original)
    restored = a.evidence / "noop-replay"
    replay(layered, restored)
    before, after = snapshot(original), snapshot(restored)
    # Explicit root timestamp and ownership are never waived.
    assert before["."] == after["."], (before["."], after["."])
    assert {k: v for k, v in before.items() if k.startswith("probe")} == {
        k: v for k, v in after.items() if k.startswith("probe")}

    # Independently identified RUN inputs, not a budget inferred from emitted size.
    runtime_files = ["bin/busybox", "lib/ld-musl-x86_64.so.1", "etc/passwd"]
    rich_payloads = {name: (original / name).lstat().st_size for name in runtime_files}
    rich_payloads.update({"probe/alias": len(b"preserved\n"), "probe/app": len(b"application-v1\n"),
                          "probe/split-main": len(b"new inode\n"), "probe/split-peer": len(b"old inode\n"),
                          "probe/to-file": len(b"replacement")})
    rich_paths = set(rich_payloads) | {".", "bin", "etc", "lib", "var", "var/run", "probe",
        "probe/keep", "probe/.wh.deleted", "probe/to-dir", "probe/xattr-dir"} | {
        "bin/" + name for name in ["chmod", "chown", "mkdir", "rm", "rmdir", "sh", "touch"]}
    sizes = {}

    def rich_size(name, output, tree):
        data, members = delta_members(output, len(base_manifest["layers"]))
        assert set(members) <= rich_paths, (name, set(members) - rich_paths)
        for path, member in members.items():
            if member.isdir():
                assert path == "." or tree[path] != before.get(path) or any(
                    other.startswith(path + "/") for other in members), (name, "unneeded parent", path)
            if path in before and not member.isdir():
                assert tree[path] != before[path], (name, "unchanged path exported", path)
            if member.isfile() and not Path(path).name.startswith(".wh."):
                assert path in rich_payloads and member.size == rich_payloads[path], (name, path, member.size)
        for path in runtime_files:
            # RUN may access these files, but must preserve all other metadata/content.
            assert {k: v for k, v in tree[path].items() if k != "atime_ns"} == {
                k: v for k, v in before[path].items() if k != "atime_ns"}, (name, path)
            source_root = a.evidence / (name + "-work") / "rootfs-final-export"
            if not source_root.exists():
                source_root = a.evidence / (name + "-work") / "rootfs"
            assert tree[path]["atime_ns"] == (source_root / path).lstat().st_atime_ns, (name, path)
        # At most one full payload per known inode; 4KiB/entry covers headers,
        # PAX and block padding for this bounded fixture, plus a tar end record.
        limit = sum(rich_payloads.values()) + 4096 * len(rich_paths) + 10240
        sizes[name] = {"actual_bytes": len(data), "payload_bound": sum(rich_payloads.values()),
                       "overhead_bound": limit - sum(rich_payloads.values()), "limit": limit,
                       "paths": sorted(members)}
        (a.evidence / "delta-sizes.json").write_text(json.dumps(sizes, indent=2))
        assert len(data) <= limit, (name, len(data), limit)

    # A real managed COPY workload isolates payload selectivity from RUN access.
    copy_file = "FROM fixture\nCOPY app /probe/app\n"
    copy_store = a.evidence / "copy-store"
    copy_trees = {}
    for name, payload, extra in [("copy-cold", b"application-v1\n", ()),
                                  ("copy-warm", b"application-v1\n", ()),
                                  ("copy-app-edit", b"application-v2\n", ()),
                                  ("copy-no-cache", b"application-v2\n", ("--no-cache",))]:
        if name in {"copy-cold", "copy-app-edit"}:
            (context / "app").write_bytes(payload)
        output, log = build(name, "layered", copy_file, extra, copy_store)
        manifest, config = preserved(output)
        assert config["config"] == base_config["config"]
        if name == "copy-warm":
            assert b"CACHED instruction 2 COPY" in log
        if name in {"copy-cold", "copy-no-cache"}:
            assert b"CACHED" not in log
        data, members = delta_members(output, len(base_manifest["layers"]))
        assert set(members) == {".", "probe", "probe/app"}, (name, set(members))
        assert members["probe/app"].isfile() and members["probe/app"].size == len(payload)
        assert manifest["layers"][-1]["size"] < 128 * 1024, "COPY-only app edit exported the base"
        root = a.evidence / (name + "-replay")
        replay(output, root)
        tree = snapshot(root)
        assert set(tree) == set(before) | {"probe/app"}
        assert {k: v for k, v in tree.items() if k not in {"probe", "probe/app"}} == {
            k: v for k, v in before.items() if k != "probe"}
        # COPY changes the containing directory's times; explicit root metadata
        # is preserved exactly, never normalized to an extraction clock.
        assert tree["."] == before["."]
        assert {k: v for k, v in tree["probe"].items() if k not in {"atime_ns", "mtime_ns"}} == {
            k: v for k, v in before["probe"].items() if k not in {"atime_ns", "mtime_ns"}}
        assert tree["probe/app"]["sha256"] == hashlib.sha256(payload).hexdigest()
        assert (root / "probe/app").read_bytes() == payload
        assert tree["probe/app"]["mode"] == stat.S_IFREG | 0o644
        assert tree["probe/app"]["uid"] == tree["probe/app"]["gid"] == 0
        assert tree["probe/app"]["xattrs"] == {}
        # Exact COPY times come from the retained build filesystem, before
        # any oracle content read; separate builds need not share wall clocks.
        source_root = a.evidence / (name + "-work") / "rootfs-final-export"
        if not source_root.exists():
            source_root = a.evidence / (name + "-work") / "rootfs"
        for path in ["probe", "probe/app"]:
            source = (source_root / path).lstat()
            assert tree[path]["atime_ns"] == source.st_atime_ns, (name, path)
            assert tree[path]["mtime_ns"] == source.st_mtime_ns, (name, path)
        copy_trees[name] = tree
        sizes[name] = {"actual_bytes": len(data), "limit": 128 * 1024, "paths": sorted(members)}
    assert copy_trees["copy-cold"] == copy_trees["copy-warm"], "warm COPY metadata changed"
    (a.evidence / "delta-sizes.json").write_text(json.dumps(sizes, indent=2))
    # Minimal COPY versus RUN regression: actual executions, no synthetic timing.
    minimal, _ = build("copy-run-true", "layered", copy_file + "RUN true\n", ["--no-cache"], copy_store)
    preserved(minimal)
    minimal_root = a.evidence / "copy-run-true-replay"
    replay(minimal, minimal_root)
    minimal_tree = snapshot(minimal_root)
    minimal_data, minimal_members = delta_members(minimal, len(base_manifest["layers"]))
    assert set(minimal_members) == {".", "probe", "probe/app", "bin", "bin/sh", "bin/busybox", "lib", "lib/ld-musl-x86_64.so.1"}
    for path in runtime_files[:2]:
        assert minimal_tree[path]["atime_ns"] != before[path]["atime_ns"], path
        assert {k: v for k, v in minimal_tree[path].items() if k != "atime_ns"} == {
            k: v for k, v in before[path].items() if k != "atime_ns"}, path
        assert minimal_members[path].isfile() and minimal_members[path].size == rich_payloads[path]
    assert len(minimal_data) > 128 * 1024 > sizes["copy-app-edit"]["actual_bytes"]
    sizes["copy-run-true"] = {"actual_bytes": len(minimal_data), "paths": sorted(minimal_members)}
    (context / "app").write_text("application-v1\n")

    dockerfile = ("FROM fixture AS parent\nCOPY app /probe/app\n"
                  "RUN rm /probe/deleted /probe/to-dir && mkdir /probe/to-dir && "
                  "rm -rf /probe/to-file && printf replacement > /probe/to-file && "
                  "rm /probe/split-main && printf 'new inode\\n' > /probe/split-main && "
                  "rmdir /probe/xattr-dir && mkdir /probe/xattr-dir && "
                  "chmod 755 /probe/to-dir /probe/xattr-dir && chmod 644 /probe/app /probe/to-file /probe/split-main && "
                  "chmod 640 /probe/keep && chown 234:567 /probe/keep && "
                  "touch -h -t 202001010000 / /probe /probe/app /probe/keep /probe/to-dir /probe/to-file /probe/split-main /probe/xattr-dir\n"
                  "ENV CHILD=value\nCMD [\"/bin/sh\",\"-c\",\"cat /probe/app\"]\n")
    first, _ = build("first", "layered", dockerfile)
    first_manifest, _ = preserved(first)
    warm, warm_log = build("warm", "layered", dockerfile)
    assert b"CACHED" in warm_log
    preserved(warm)
    uncached_store = a.evidence / "uncached-store"
    uncached, uncached_log = build("no-cache", "layered", dockerfile, ["--no-cache"], uncached_store)
    assert b"CACHED instruction" not in uncached_log
    for namespace in ["cache-v1", "cache-v2"]:
        assert not (uncached_store / namespace).exists(), "no-cache created " + namespace
    preserved(uncached)
    expected_config = dict(base_config["config"])
    expected_config.update(Env=["BASE=value", "CHILD=value"], Cmd=["/bin/sh", "-c", "cat /probe/app"])
    # Bypass a populated cache, and prove no checkpoint content was changed.
    cached_before = {name: snapshot(store / name) for name in ["cache-v1", "cache-v2"] if (store / name).exists()}
    assert cached_before, "managed cache was never populated"
    bypassed, bypass_log = build("populated-no-cache", "layered", dockerfile, ["--no-cache"])
    assert b"CACHED" not in bypass_log, "no-cache read a populated cache"
    assert cached_before == {name: snapshot(store / name) for name in cached_before}, "no-cache mutated checkpoints"
    preserved(bypassed)
    trees = []
    for name, output in [("first", first), ("warm", warm), ("no-cache", uncached), ("populated-no-cache", bypassed)]:
        dest = a.evidence / (name + "-replay")
        _, config = replay(output, dest)
        assert config["config"] == expected_config, (config["config"], expected_config)
        assert config["config"] == load(first)[1]["config"]
        for key, expected in {"Env": ["BASE=value", "CHILD=value"], "WorkingDir": "/probe",
                              "Cmd": ["/bin/sh", "-c", "cat /probe/app"],
                              "Labels": {"fixture": "layered"}, "User": "0:0"}.items():
            assert config["config"][key] == expected, (key, config["config"].get(key))
        tree = snapshot(dest)
        rich_size(name, output, tree)
        selected = {k: v for k, v in tree.items() if k == "." or k.startswith("probe")}
        trees.append(selected)
        assert "probe/deleted" not in tree and "probe/to-file/child" not in tree
        assert (dest / "probe/to-file").read_bytes() == b"replacement"
        assert (dest / "probe/to-dir").is_dir()
        assert tree["probe/keep"]["uid"] == 234 and tree["probe/keep"]["gid"] == 567
        for path in ["probe/keep", "probe/alias"]:
            assert tree[path]["mode"] == stat.S_IFREG | 0o640, path
            assert tree[path]["uid"] == 234 and tree[path]["gid"] == 567, path
        for path in [".", "probe"]:
            assert tree[path]["mode"] == stat.S_IFDIR | 0o751, path
            assert tree[path]["uid"] == 123 and tree[path]["gid"] == 456, path
        for path in ["probe/to-dir", "probe/xattr-dir"]:
            assert tree[path]["mode"] == stat.S_IFDIR | 0o755, path
            assert tree[path]["uid"] == tree[path]["gid"] == 0, path
        for path in ["probe/app", "probe/to-file", "probe/split-main"]:
            assert tree[path]["mode"] == stat.S_IFREG | 0o644, path
            assert tree[path]["uid"] == tree[path]["gid"] == 0, path
        for path in [".", "probe", "probe/app", "probe/keep", "probe/alias", "probe/to-dir", "probe/to-file", "probe/split-main", "probe/xattr-dir"]:
            assert tree[path]["mtime_ns"] == 1577836800000000000, (path, tree[path])
            assert tree[path]["atime_ns"] == 1577836800000000000, (path, tree[path])
        assert tree["probe/app"]["sha256"] == hashlib.sha256(b"application-v1\n").hexdigest()
        assert tree["probe/keep"]["sha256"] == hashlib.sha256(b"preserved\n").hexdigest()
        assert tree["probe/xattr-dir"]["xattrs"] == {}, "directory xattr deletion lost"
        assert tree["probe/split-main"]["sha256"] == hashlib.sha256(b"new inode\n").hexdigest()
        assert tree["probe/split-peer"]["sha256"] == hashlib.sha256(b"old inode\n").hexdigest()
        assert tree["probe/split-main"]["hardlink_group"] != tree["probe/split-peer"]["hardlink_group"]
        assert tree[os.fsdecode(b"probe/raw-\xff")]["sha256"] == hashlib.sha256(b"raw filename\n").hexdigest()
        assert tree["probe/cap"]["xattrs"]["security.capability"] == struct.pack("<5I", 0x02000001, 1024, 0, 0, 0).hex()
        assert tree["probe/keep"]["hardlink_group"] == tree["probe/alias"]["hardlink_group"]
        assert tree["probe/keep"]["xattrs"]["user.layered"] == b"base-value".hex()
    assert all(tree == trees[0] for tree in trees[1:]), "cache/no-cache changed delivered metadata"
    # Corrupt every cached layer, not an arbitrary entry that may never be read.
    # Deduplicate hardlinked pool/layout copies and restore each inode exactly.
    cache_layers = {}
    for namespace in [store / "cache-v1", store / "cache-v2"]:
        if namespace.exists():
            for index in namespace.rglob("index.json"):
                layout = index.parent
                manifest, _ = load(layout)
                for desc in manifest["layers"]:
                    if desc["digest"] in {d["digest"] for d in base_manifest["layers"]}:
                        continue  # Never corrupt a shared original base inode.
                    path = layout / "blobs/sha256" / desc["digest"].split(":")[1]
                    identity = path.stat()
                    cache_layers.setdefault((identity.st_dev, identity.st_ino), (path, path.read_bytes()))
    assert cache_layers, "did not identify any cached layer to corrupt"
    try:
        for path, saved in cache_layers.values():
            damaged = bytearray(saved)
            damaged[len(damaged) // 2] ^= 1
            path.write_bytes(damaged)
        build("warm-checkpoint-corruption", "layered", dockerfile, expect=False)
        # A separate no-cache build must ignore the corrupted checkpoint namespace.
        bypass, bypass_log = build("corrupt-cache-bypass", "layered", dockerfile, ["--no-cache"])
        assert b"CACHED" not in bypass_log
    finally:
        for path, saved in cache_layers.values():
            path.write_bytes(saved)
    preserved(bypass)
    bypass_root = a.evidence / "corrupt-cache-bypass-replay"
    replay(bypass, bypass_root)
    bypass_snapshot = snapshot(bypass_root)
    rich_size("corrupt-cache-bypass", bypass, bypass_snapshot)
    assert {k: v for k, v in bypass_snapshot.items() if k == "." or k.startswith("probe")} == trees[0]
    inherited_file = dockerfile + "FROM parent\nENV INHERITED=yes\n"
    parent, _ = build("parent-target", "layered", inherited_file, ["--target", "parent"])
    child, _ = build("inherited-child", "layered", inherited_file)
    child_manifest, child_config = preserved(child, parent)
    assert "INHERITED=yes" in child_config["config"]["Env"]
    for desc in child_manifest["layers"][len(load(parent)[0]["layers"]):]:
        data = verified(child, desc)
        if desc["mediaType"].endswith("+gzip"):
            data = gzip.decompress(data)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members = archive.getmembers()
            assert all(Path(m.name) == Path(".") and m.isdir() for m in members), "metadata-only child added payload or whiteouts"
    parent_tree, child_tree = a.evidence / "parent-replay", a.evidence / "child-replay"
    replay(parent, parent_tree)
    replay(child, child_tree)
    assert snapshot(parent_tree) == snapshot(child_tree), "metadata-only inherited stage changed filesystem"
    mutating_file = dockerfile + ("FROM parent\nRUN printf child > /probe/child && "
                                 "chmod 600 /probe/child && touch -t 202001010000 / /probe /probe/child\n")
    mutating_parent, _ = build("mutating-parent-target", "layered", mutating_file, ["--target", "parent"])
    mutating_child, _ = build("mutating-child", "layered", mutating_file)
    preserved(mutating_child, mutating_parent)
    mutating_root = a.evidence / "mutating-replay"
    replay(mutating_child, mutating_root)
    mutated = snapshot(mutating_root)
    assert mutated["probe/child"]["mode"] == stat.S_IFREG | 0o600
    assert mutated["probe/child"]["sha256"] == hashlib.sha256(b"child").hexdigest()
    assert mutated["probe/child"]["uid"] == mutated["probe/child"]["gid"] == 0
    assert mutated["probe/child"]["mtime_ns"] == mutated["probe/child"]["atime_ns"] == 1577836800000000000
    (context / "app").write_text("application-v2\n")
    edited, _ = build("app-edit", "layered", dockerfile)
    edited_manifest, _ = preserved(edited)
    assert edited_manifest["layers"][-1]["digest"] != first_manifest["layers"][-1]["digest"]
    edited_root = a.evidence / "app-edit-replay"
    replay(edited, edited_root)
    edited_tree = snapshot(edited_root)
    assert edited_tree["probe/app"]["sha256"] == hashlib.sha256(b"application-v2\n").hexdigest()
    expected_edit = {path: dict(item) for path, item in trees[0].items()}
    expected_edit["probe/app"]["sha256"] = hashlib.sha256(b"application-v2\n").hexdigest()
    assert {k: v for k, v in edited_tree.items() if k == "." or k.startswith("probe")} == expected_edit
    rich_size("app-edit", edited, edited_tree)
    build("budget", "layered", dockerfile, ["--max-layer-bytes", "1024"], expect=False)
    build("metadata-budget", "layered", dockerfile, ["--metadata-budget", "128"], expect=False)
    # Corrupt a private base only; the original offline Alpine remains untouched.
    damaged = base / "blobs/sha256" / base_manifest["layers"][0]["digest"].split(":")[1]
    saved = damaged.read_bytes()
    corrupt = bytearray(saved)
    corrupt[len(corrupt) // 2] ^= 1
    damaged.write_bytes(corrupt)
    try:
        build("warm-base-corruption", "layered", noop, expect=False)
        build("corruption", "layered", noop, ["--no-cache"], a.evidence / "corrupt-store", expect=False)
    finally:
        damaged.write_bytes(saved)
    (context / "Dockerfile").write_text("FROM fixture\nRUN touch /cancel-ready; sleep 90\n")
    cancel_output, cancel_work = a.evidence / "cancel-image", a.evidence / "cancel-work"
    command = [str(a.binary), "build", "--export-mode", "layered", "--no-host-dns",
               "--base", "fixture=" + str(base), "-t", "layered-cancel:test",
               "--output", str(cancel_output), "--work-dir", str(cancel_work), str(context)]
    with (a.evidence / "cancel.log").open("wb") as log:
        child = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True,
                                 env=dict(os.environ, RPWELD_HOME=str(a.evidence / "cancel-store")))
        try:
            deadline = time.monotonic() + 30
            while not (cancel_work / "rootfs/cancel-ready").exists():
                assert child.poll() is None, "build exited before cancellation probe"
                assert time.monotonic() < deadline, "cancellation readiness timed out"
                time.sleep(0.05)
            child.send_signal(signal.SIGTERM)
            assert child.wait(timeout=15) != 0
            assert not (cancel_output / "index.json").exists()
            assert b"cancel" in (a.evidence / "cancel.log").read_bytes().lower()
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    if a.docker:
        archive = a.evidence / "docker-load.tar"
        with tarfile.open(archive, "w") as tar:
            for child in edited.iterdir():
                tar.add(child, arcname=child.name)
        loaded = subprocess.run(["docker", "load", "-i", str(archive)], capture_output=True, check=True)
        (a.evidence / "docker-load.log").write_bytes(loaded.stdout + loaded.stderr)
        reference = loaded_reference(loaded.stdout)
        inspected = json.loads(subprocess.check_output(["docker", "image", "inspect", reference]))[0]
        assert inspected["RootFS"]["Layers"] == load(edited)[1]["rootfs"]["diff_ids"]
        for key in ["Env", "Cmd", "WorkingDir", "Labels"]:
            assert inspected["Config"][key] == load(edited)[1]["config"][key]
        saved_image = a.evidence / "docker-save.tar"
        subprocess.run(["docker", "image", "save", "-o", str(saved_image), reference], check=True)
        with tarfile.open(saved_image) as saved:
            saved_manifest = json.load(saved.extractfile("manifest.json"))
            assert len(saved_manifest) == 1
            saved_config = json.load(saved.extractfile(saved_manifest[0]["Config"]))
            assert saved_config["history"] == load(edited)[1]["history"]
        expected_root = a.evidence / "edited-replay"
        replay(edited, expected_root)
        expected = snapshot(expected_root)
        intended = {"/" + k: v for k, v in expected.items() if k == "probe" or k.startswith("probe/")}
        helper = compile_probe(a.evidence / "live-metadata")
        live = docker_metadata(reference, helper, intended, a.evidence / "docker-live-metadata.jsonl")
        # Docker export truncates fractional mtime. The live filesystem is the
        # exact mtime/xattr surface; atime is recorded, not claimed as OCI fidelity.
        assert_metadata(live, intended)
        container = subprocess.check_output(["docker", "create", "--network=none", reference]).decode().strip()
        try:
            subprocess.run(["docker", "export", "-o", str(a.evidence / "docker-export.tar"), container], check=True)
            with tarfile.open(a.evidence / "docker-export.tar") as archive:
                members = {m.name.removeprefix("./").rstrip("/"): m for m in archive.getmembers()}
                assert "probe/deleted" not in members and "probe/to-file/child" not in members
                for name, item in expected.items():
                    if name != "probe" and not name.startswith("probe/"):
                        continue
                    member = members[name]
                    assert member.uid == item["uid"] and member.gid == item["gid"], name
                    assert member.mode == stat.S_IMODE(item["mode"]), name
                    if stat.S_ISREG(item["mode"]):
                        assert member.isfile() or member.islnk(), name
                        assert hashlib.sha256(archive.extractfile(member).read()).hexdigest() == item["sha256"], name
                    elif stat.S_ISLNK(item["mode"]):
                        assert member.issym() and member.linkname == item["target"], name
                    elif stat.S_ISDIR(item["mode"]):
                        assert member.isdir(), name
                aliases = [members["probe/alias"], members["probe/keep"]]
                assert any(m.islnk() and m.linkname.removeprefix("./") in {"probe/alias", "probe/keep"} for m in aliases)
            output = subprocess.check_output(["docker", "start", "-a", container])
            assert output.strip() == b"application-v2"
        finally:
            subprocess.run(["docker", "rm", "-f", container], check=True)
    print("layered acceptance PASS")


if __name__ == "__main__":
    main()
