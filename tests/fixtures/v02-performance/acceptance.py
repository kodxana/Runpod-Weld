"""Independent OCI/metadata/cache checks, always outside the measured build interval."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from fixture import ATIME, MTIME, TIMES, digest
from metrics import walk
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "layered-export"))
from oracle import replay, snapshot


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOATIME)
    with os.fdopen(fd, "rb") as stream:
        return stream.read()


def load(layout):
    def verified(descriptor):
        algorithm, checksum = descriptor["digest"].split(":", 1)
        assert algorithm == "sha256"
        path = layout / "blobs/sha256" / checksum
        assert path.stat().st_size == descriptor["size"] and digest(path) == checksum, descriptor
        return path
    index = json.loads(read(layout / "index.json"))
    assert len(index["manifests"]) == 1
    manifest = json.loads(read(verified(index["manifests"][0])))
    config = json.loads(read(verified(manifest["config"])))
    assert config["rootfs"]["type"] == "layers"
    assert len(manifest["layers"]) == len(config["rootfs"]["diff_ids"])
    assert sum(not item.get("empty_layer", False) for item in config["history"]) == len(manifest["layers"])
    for descriptor, diffid in zip(manifest["layers"], config["rootfs"]["diff_ids"]):
        path = verified(descriptor)
        fd = os.open(path, os.O_RDONLY | os.O_NOATIME)
        with os.fdopen(fd, "rb") as stream:
            if descriptor["mediaType"].endswith("+gzip"):
                with gzip.GzipFile(fileobj=stream) as expanded:
                    checksum = hashlib.file_digest(expanded, "sha256").hexdigest()
            else:
                assert descriptor["mediaType"].endswith(".tar"), descriptor
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        assert diffid == "sha256:" + checksum, (descriptor, diffid)
    return manifest, config


def cache_fingerprint(store):
    result = {}
    for namespace in (store / "cache-v1", store / "cache-v2"):
        for path, info in walk(namespace):
            if stat.S_ISREG(info.st_mode):
                result[str(path.relative_to(store))] = {
                    "identity": [info.st_dev, info.st_ino], "mode": info.st_mode,
                    "uid": info.st_uid, "gid": info.st_gid, "size": info.st_size,
                    "mtime_ns": info.st_mtime_ns, "sha256": digest(path)}
    return result


def assert_preserved(before, after, exact=False):
    assert before, "cache was not populated"
    assert all(after.get(name) == value for name, value in before.items()), "existing checkpoint changed"
    if exact:
        assert before == after, "unchanged/no-cache build added or rewrote checkpoint files"


def assert_log(case, log):
    executed = set()
    for line in log.splitlines():
        match = re.search(r"(?:^| RUN stdout\] )(V02_EXEC_\w+)$", line.strip())
        if match:
            executed.add(match.group(1))
    all_runs = {"V02_EXEC_dependencies", "V02_EXEC_config", "V02_EXEC_application"}
    if case in ("cold", "no-cache"):
        assert executed == all_runs, (case, executed)
        assert "CACHED" not in log, (case, "unexpected cache hit")
    elif case == "warm":
        assert not executed and "CACHED" in log, "warm build executed RUN or missed cache"
    elif case == "app-edit":
        assert executed == {"V02_EXEC_application"}, executed
        for ordinal, op in ((2, "COPY"), (3, "RUN"), (4, "COPY"), (5, "RUN")):
            assert f"CACHED instruction {ordinal} {op}" in log, (ordinal, op)
        assert "CACHED instruction 6 COPY" not in log and "CACHED instruction 7 RUN" not in log
    return {"executed": sorted(executed), "hits": [line for line in log.splitlines() if "CACHED" in line]}


def expected_tree(base_tree, context, version):
    expected = json.loads(json.dumps(base_tree))
    source = snapshot(context)
    for directory, destination in (("dep", "deps"), ("config", "config"), ("app", "app")):
        for path, item in source.items():
            if path == directory or path.startswith(directory + "/"):
                name = destination + path[len(directory):]
                value = dict(item)
                if "hardlink_group" in value:
                    value["hardlink_group"] = name
                expected[name] = value
    def regular(name, content, mode=0o644):
        expected[name] = {"mode": stat.S_IFREG | mode, "uid": 0, "gid": 0,
            "mtime_ns": TIMES[1], "atime_ns": TIMES[0], "xattrs": {},
            "sha256": hashlib.sha256(content).hexdigest(), "hardlink_group": name}
    regular("deps/checked", b"dependencies-ok\n")
    regular("config/generated", b"offline-setting=v1\n")
    regular("app/result", f"application-v{version}\noffline-setting=v1\n".encode(), 0o640)
    expected["app/main.txt"]["hardlink_group"] = "app/alias"
    expected["app/alias"] = dict(expected["app/main.txt"])
    expected["app/link"] = {"mode": stat.S_IFLNK | 0o777, "uid": 0, "gid": 0,
        "mtime_ns": TIMES[1], "atime_ns": TIMES[0], "xattrs": {}, "target": "main.txt"}
    return expected


def assert_tree(actual, expected):
    assert actual.keys() == expected.keys(), {"extra": sorted(actual.keys()-expected.keys()),
                                             "missing": sorted(expected.keys()-actual.keys())}
    differences = {path: {"actual": actual[path], "expected": expected[path]}
                   for path in actual if actual[path] != expected[path]}
    assert not differences, json.dumps(differences, indent=2)


def verify_output(layout, replay_root, base, expected):
    manifest, config = load(layout)
    base_manifest, base_config = load(base)
    count = len(base_manifest["layers"])
    assert manifest["layers"][:count] == base_manifest["layers"]
    assert config["rootfs"]["diff_ids"][:count] == base_config["rootfs"]["diff_ids"]
    assert config["history"][:len(base_config["history"])] == base_config["history"]
    assert config["architecture"] == "amd64" and config["os"] == "linux"
    runtime = config["config"]
    assert "V02_FIXTURE=synthetic" in runtime["Env"]
    assert runtime["Cmd"] == ["/bin/busybox", "cat", "/app/result"]
    assert runtime["Labels"]["org.rpweld.fixture"] == "v02-performance"
    replay(layout, replay_root)
    tree = snapshot(replay_root)
    assert_tree(tree, expected)
    return manifest, config, tree


def candidate_prefix(store, base):
    """Every cold instruction snapshot must extend the previous verified chain."""
    base_manifest, base_config = load(base)
    entries = []
    for index in sorted(store.glob("cache-*/entries/*/index.json")):
        manifest, config = load(index.parent)
        entries.append({"path": str(index.parent), "layers": manifest["layers"],
                        "diff_ids": config["rootfs"]["diff_ids"],
                        "final_metadata": config["config"].get("Labels", {}).get("org.rpweld.fixture") == "v02-performance"})
    # ENV/LABEL/CMD follow all six filesystem instructions in this fixture.
    # Their final stage checkpoint appends a metadata suffix, not an instruction.
    instructions = [entry for entry in entries if not entry["final_metadata"]]
    suffixes = [entry for entry in entries if entry["final_metadata"]]
    chains = {tuple(d["digest"] for d in e["layers"]): e for e in instructions}
    ordered = sorted(chains.values(), key=lambda e: len(e["layers"]))
    count = len(base_manifest["layers"])
    assert [len(e["layers"]) for e in ordered] == list(range(count+1, count+7)), "six incremental checkpoints required"
    previous, previous_diff = base_manifest["layers"], base_config["rootfs"]["diff_ids"]
    for entry in ordered:
        assert entry["layers"][:-1] == previous, "checkpoint rewrote verified descriptor prefix"
        assert entry["diff_ids"][:-1] == previous_diff, "checkpoint rewrote verified diff-ID prefix"
        previous, previous_diff = entry["layers"], entry["diff_ids"]
    assert suffixes, "trailing ENV/LABEL/CMD stage checkpoint missing"
    for entry in suffixes:
        assert entry["layers"][:-1] == previous, "metadata suffix rewrote instruction prefix"
        assert entry["diff_ids"][:-1] == previous_diff
    # For a given digest, all cache-owned appearances must share one inode.
    aliases = {}
    for path, info in walk(store / "cache-v2"):
        if stat.S_ISREG(info.st_mode) and path.parent.name == "sha256":
            aliases.setdefault(path.name, []).append((str(path), (info.st_dev, info.st_ino)))
    assert aliases
    assert all(len({identity for _, identity in group}) == 1 for group in aliases.values())
    assert any(len(group) > 2 for group in aliases.values()), "no internally shared blob aliases"
    return {"entries": entries, "unique_layer_chains": ordered, "metadata_suffix_entries": suffixes,
            "owned_blob_alias_counts": {key: len(value) for key, value in aliases.items()}}


def assert_isolation(store, outputs):
    cached = {(s.st_dev, s.st_ino) for path, s in walk(store / "cache-v2") if stat.S_ISREG(s.st_mode)}
    previous = set()
    assert cached, "no cache inodes"
    for output in outputs:
        identities = {(s.st_dev, s.st_ino) for path, s in walk(output) if stat.S_ISREG(s.st_mode)}
        assert not identities & cached, "mutable output aliases owned cache"
        assert not identities & previous, "separate mutable outputs share inodes"
        previous |= identities


def mutation_probe(store, outputs):
    """Mutate then restore an output layer, prove all caches and peers unchanged."""
    assert_isolation(store, outputs)
    before = cache_fingerprint(store)
    peer_hashes = [{str(p): digest(p) for p, s in walk(out) if stat.S_ISREG(s.st_mode)} for out in outputs[1:]]
    manifest, _ = load(outputs[0])
    path = outputs[0] / "blobs/sha256" / manifest["layers"][-1]["digest"].split(":")[1]
    info = path.stat()
    with path.open("r+b") as stream:
        original = stream.read(1)
        try:
            stream.seek(0)
            stream.write(bytes([original[0] ^ 0xff]))
            stream.flush()
            os.fsync(stream.fileno())
            assert_preserved(before, cache_fingerprint(store), exact=True)
            for peer in peer_hashes:
                assert all(digest(Path(name)) == checksum for name, checksum in peer.items())
        finally:
            stream.seek(0)
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    load(outputs[0])
