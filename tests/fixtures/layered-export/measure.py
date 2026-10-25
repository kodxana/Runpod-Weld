#!/usr/bin/env python3
"""Measure offline fixtures; evidence and all generated trees stay on native Linux."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time


def usage(path):
    logical = allocated = 0
    seen = set()
    for root, dirs, files in os.walk(path):
        for name in ["."] + files + [d for d in dirs if (Path(root) / d).is_symlink()]:
            s = (Path(root) / name).lstat()
            logical += s.st_size
            identity = (s.st_dev, s.st_ino)
            if identity not in seen:
                allocated += s.st_blocks * 512
                seen.add(identity)
    return {"logical_bytes": logical, "unique_allocated_bytes": allocated,
            "unique_inodes": len(seen)}


def image(layout):
    def blob(d):
        algorithm, digest = d["digest"].split(":")
        assert algorithm == "sha256"
        data = (layout / "blobs" / algorithm / digest).read_bytes()
        assert len(data) == d["size"] and hashlib.sha256(data).hexdigest() == digest
        return data
    manifest = json.loads(blob(json.loads((layout / "index.json").read_text())["manifests"][0]))
    config = json.loads(blob(manifest["config"]))
    for d in manifest["layers"]:
        blob(d)
    blobs = {p.name: p.stat().st_size for p in (layout / "blobs/sha256").iterdir()}
    return manifest, config, blobs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--layout", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--revision", required=True)
    p.add_argument("--mode", choices=["legacy", "flattened", "layered"], default="legacy")
    a = p.parse_args()
    assert os.geteuid() == 0
    a.evidence.mkdir(parents=True, exist_ok=False)
    results = []
    provenance = {"revision": a.revision, "binary_sha256": hashlib.sha256(a.binary.read_bytes()).hexdigest(),
                  "uname": list(os.uname()), "mode": a.mode, "base_index_sha256": hashlib.sha256((a.layout / "index.json").read_bytes()).hexdigest(),
                  "measurement": "single sample; cold means empty managed store, not dropped OS page cache; allocated uses st_blocks*512 deduplicated by device/inode, not physical reflink extents"}
    (a.evidence / "provenance.json").write_text(json.dumps(provenance, indent=2))
    for language, app, edit in [("python", "app.py", "print('application-v2')\n"),
                                ("node", "index.js", "console.log('application-v2');\n")]:
        root = a.evidence / language
        context = root / "context"
        shutil.copytree(a.source / "tests/fixtures/instruction-cache" / language, context)
        previous = {}
        for case in ["cold", "warm", "app-edit"]:
            if case == "app-edit":
                (context / app).write_text(edit)
            out, work = root / (case + "-image"), root / (case + "-work")
            command = [str(a.binary), "build", "--no-host-dns", "--base", "alpine=" + str(a.layout),
                       "-t", "layered-measure:" + language, "--output", str(out), "--work-dir", str(work)]
            if a.mode != "legacy":
                command += ["--export-mode", a.mode]
            command += [str(context)]
            start = time.monotonic_ns()
            run = subprocess.run(command, env=dict(os.environ, RPWELD_HOME=str(root / "store")),
                                 capture_output=True, timeout=120)
            elapsed = time.monotonic_ns() - start
            (root / (case + ".stdout")).write_bytes(run.stdout)
            (root / (case + ".stderr")).write_bytes(run.stderr)
            assert run.returncode == 0, run.stderr.decode(errors="replace")
            log = run.stdout + run.stderr
            if case == "warm":
                assert b"CACHED" in log and b"IC_EXEC_dependencies\n" not in log
            if case == "app-edit":
                assert b"CACHED instruction 4 RUN" in log and b"IC_EXEC_application\n" in log
            manifest, config, blobs = image(out)
            results.append({"language": language, "case": case, "wall_seconds": elapsed / 1e9,
                "command": command, "output": usage(out), "work": usage(work), "store": usage(root / "store"),
                "all_retained": usage(root), "layer_count": len(manifest["layers"]),
                "layer_bytes": sum(d["size"] for d in manifest["layers"]), "blob_count": len(blobs),
                "blob_bytes": sum(blobs.values()), "new_blob_count": len(blobs.keys() - previous.keys()),
                "new_blob_bytes": sum(v for k, v in blobs.items() if k not in previous),
                "manifest": manifest, "diff_ids": config["rootfs"]["diff_ids"]})
            previous = blobs
            (a.evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
