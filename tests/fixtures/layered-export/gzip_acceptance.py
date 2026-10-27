#!/usr/bin/env python3
"""Local gzip RUN/export/reimport acceptance against an offline Alpine layout."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from acceptance import rich_base
from oracle import load, replay, snapshot, verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    args.evidence.mkdir(parents=True, exist_ok=False)
    base = args.evidence / "base"
    rich_base(args.layout, base)
    context = args.evidence / "context"
    context.mkdir()
    (context / "app").write_text("gzip-runtime-payload\n")
    os.utime(context / "app", ns=(2000000001000000000, 2000000000000000000))
    records = []

    def build(name, parent, mode, compression, source):
        (context / "Dockerfile").write_text(source)
        output = args.evidence / (name + "-image")
        work = args.evidence / (name + "-work")
        command = [str(args.binary), "build", "--no-cache", "--no-host-dns",
                   "--compression", compression, "--export-mode", mode,
                   "--base", "fixture=" + str(parent), "--output", str(output),
                   "--work-dir", str(work), "-t", "gzip-runtime:test", str(context)]
        result = subprocess.run(command, env=dict(os.environ, RPWELD_HOME=str(args.evidence / "store")),
                                capture_output=True, timeout=120)
        (args.evidence / (name + ".stdout")).write_bytes(result.stdout)
        (args.evidence / (name + ".stderr")).write_bytes(result.stderr)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert b"CACHED" not in result.stderr
        manifest, config = load(output)
        assert manifest["layers"][-1]["mediaType"].endswith("+gzip") == (compression == "gzip")
        if mode == "layered":
            inherited, inherited_config = load(parent)
            count = len(inherited["layers"])
            assert manifest["layers"][:count] == inherited["layers"]
            assert config["rootfs"]["diff_ids"][:count] == inherited_config["rootfs"]["diff_ids"]
            for descriptor in inherited["layers"]:
                assert verified(parent, descriptor) == verified(output, descriptor)
        root = args.evidence / (name + "-replay")
        replay(output, root)
        tree = snapshot(root)
        records.append({"case": name, "layers": len(manifest["layers"]),
                        "stored_bytes": sum(d["size"] for d in manifest["layers"]),
                        "paths": len(tree), "command": command})
        return output, config, tree

    source = ("FROM fixture AS parent\nCOPY app /probe/app\n"
              "RUN test -s /probe/app && rm /probe/deleted /probe/to-dir && mkdir /probe/to-dir && "
              "rm -rf /probe/to-file && printf replacement > /probe/to-file && "
              "rm /probe/split-main && printf new > /probe/split-main && "
              "rmdir /probe/xattr-dir && mkdir /probe/xattr-dir && "
              "chmod 640 /probe/keep && chown 234:567 /probe/keep && "
              "touch -h -t 202001010000 / /probe /probe/app /probe/keep /probe/to-dir "
              "/probe/to-file /probe/split-main /probe/xattr-dir\n"
              "ENV GZIP_RUNTIME=ok\nLABEL purpose=gzip\nCMD [\"/bin/sh\",\"-c\",\"cat /probe/app\"]\n"
              "FROM parent\nLABEL handoff=preserved\n")
    for mode in ["layered", "flattened"]:
        output, config, expected = build(mode + "-runtime", base, mode, "gzip", source)
        assert "probe/deleted" not in expected
        assert expected["probe/keep"]["uid"] == 234
        assert expected["probe/keep"]["gid"] == 567
        assert expected["probe/keep"]["hardlink_group"] == expected["probe/alias"]["hardlink_group"]
        assert expected["probe/split-main"]["hardlink_group"] != expected["probe/split-peer"]["hardlink_group"]
        assert expected["probe/xattr-dir"]["xattrs"] == {}
        assert "security.capability" in expected["probe/cap"]["xattrs"]
        assert "GZIP_RUNTIME=ok" in config["config"]["Env"]
        assert config["config"]["Labels"]["handoff"] == "preserved"
        for compression in ["gzip", "uncompressed"]:
            _, imported_config, actual = build(mode + "-reimport-" + compression, output,
                                               mode, compression, "FROM fixture\n")
            assert imported_config["config"] == config["config"]
            assert set(actual) == set(expected)
            for path in expected:
                # Only a newly created root's timestamps may reflect extraction.
                # Explicit fixture root timestamps are fixed and checked here too.
                assert actual[path] == expected[path], (mode, compression, path, expected[path], actual[path])
    (args.evidence / "results.json").write_text(json.dumps(records, indent=2))
    print(json.dumps({"passed": len(records), "evidence": str(args.evidence)}))


if __name__ == "__main__":
    main()
