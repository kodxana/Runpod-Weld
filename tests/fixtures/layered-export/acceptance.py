#!/usr/bin/env python3
"""Opt-in Linux CLI acceptance. Run only after the parent supplies a frozen binary."""
import argparse
from decimal import Decimal
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
    assert {k: v for k, v in bypass_snapshot.items() if k == "." or k.startswith("probe")} == trees[0]
    inherited_file = dockerfile + "FROM parent\nENV INHERITED=yes\n"
    parent, _ = build("parent-target", "layered", inherited_file, ["--target", "parent"])
    child, _ = build("inherited-child", "layered", inherited_file)
    child_manifest, child_config = preserved(child, parent)
    assert "INHERITED=yes" in child_config["config"]["Env"]
    for desc in child_manifest["layers"][len(load(parent)[0]["layers"]):]:
        import gzip
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
    assert edited_manifest["layers"][-1]["size"] < 128 * 1024, "tiny app edit exported the base"
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
        container = subprocess.check_output(["docker", "create", "--network=none", reference]).decode().strip()
        try:
            subprocess.run(["docker", "export", "-o", str(a.evidence / "docker-export.tar"), container], check=True)
            expected_root = a.evidence / "edited-replay"
            replay(edited, expected_root)
            expected = snapshot(expected_root)
            with tarfile.open(a.evidence / "docker-export.tar") as archive:
                members = {m.name.removeprefix("./").rstrip("/"): m for m in archive.getmembers()}
                assert "probe/deleted" not in members and "probe/to-file/child" not in members
                for name, item in expected.items():
                    if name != "probe" and not name.startswith("probe/"):
                        continue
                    member = members[name]
                    assert member.uid == item["uid"] and member.gid == item["gid"], name
                    assert member.mode == stat.S_IMODE(item["mode"]), name
                    assert int(Decimal(str(member.pax_headers.get("mtime", member.mtime))) * 1_000_000_000) == item["mtime_ns"], name
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
