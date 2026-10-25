"""Offline Docker oracle; exports only to a new native Linux temporary directory."""
import json
import io
import hashlib
import os
import re
from pathlib import Path
import subprocess
import tempfile
import tarfile


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=120)


fixtures = Path(__file__).resolve().parent
root = Path(tempfile.mkdtemp(prefix="weld-heredoc-oracle-"))
print(f"Oracle artifacts: {root}", flush=True)
for args in [("docker", "version"), ("docker", "buildx", "version"),
             ("docker", "buildx", "inspect")]:
    result = run(*args)
    assert result.returncode == 0, result.stderr
    print(result.stdout, flush=True)
base = os.environ.get("HEREDOC_DOCKER_BASE", "alpine:latest")
if layout := os.environ.get("RPWELD_TEST_LAYOUT"):
    archive = root / "base.tar"
    base = "weld-heredoc-oracle:" + root.name
    index = json.loads((Path(layout) / "index.json").read_bytes())
    index["manifests"][0]["annotations"] = {
        "io.containerd.image.name": "docker.io/library/" + base,
        "org.opencontainers.image.ref.name": base,
    }
    data = json.dumps(index).encode()
    with tarfile.open(archive, "w") as tar:
        header = tarfile.TarInfo("index.json")
        header.size = len(data)
        tar.addfile(header, io.BytesIO(data))
        for name in ["oci-layout", "blobs"]:
            tar.add(Path(layout) / name, arcname=name)
    loaded = run("docker", "load", "-i", str(archive))
    assert loaded.returncode == 0, loaded.stderr
inspection = run("docker", "image", "inspect", base)
assert inspection.returncode == 0, "Set HEREDOC_DOCKER_BASE to an existing local Alpine tag"
print("Base:", inspection.stdout, flush=True)
cases = {
    "copy": (fixtures / "Dockerfile.copy").read_text(),
    "run": (fixtures / "Dockerfile.run").read_text().replace("FROM alpine\n", f"FROM {base}\n"),
    "missing": "FROM scratch\n\nCOPY <<EOF /file\nbody\n",
    "after": "FROM scratch\nCOPY <<EOF /file\nbody\nEOF\nBOGUS value\n",
    "multiple": "FROM scratch\nCOPY <<A <<B /\na\nA\nb\nB\n",
}
cases["copy-crlf"] = cases["copy"].replace("\n", "\r\n")
cases["run-crlf"] = cases["run"].replace("\n", "\r\n")
cases["header-delimiter-crlf"] = "FROM scratch\r\nCOPY <<EOF /expanded\r\nbody\nEOF\r\n"
cases["body-crlf"] = "FROM scratch\nCOPY <<EOF /expanded\nbody\r\nEOF\n"
cases["shebang"] = f"FROM {base}\nRUN <<EOF\n#!/bin/sh\nprintf 'shebang\\n' > /tmp/result\nEOF\n"
cases["command"] = f"FROM {base}\nRUN cat <<EOF > /tmp/result\ncommand\nEOF\n"
observations = {}
for name, source in cases.items():
    context = root / name
    context.mkdir()
    (context / "Dockerfile").write_bytes(source.encode())
    out = root / (name + ".tar")
    result = run("docker", "buildx", "build", "--pull=false", "--network=none",
                 "--progress=plain", "--output", f"type=tar,dest={out}", str(context))
    (root / (name + ".log")).write_text(result.stdout + result.stderr)
    print(name, "exit", result.returncode, flush=True)
    observations[name] = {"exit": result.returncode, "files": []}
    assert (result.returncode != 0) == (name in ["missing", "after", "run-crlf"]), result.stderr
    if result.returncode:
        print(result.stderr[-1500:], flush=True)
        continue
    with tarfile.open(out) as archive:
        for entry in archive:
            if entry.name in ["expanded", "literal", "mixed", "tabs", "owned", "tmp/result", "tmp/root-result", "A", "B"]:
                data = archive.extractfile(entry).read()
                observed = {"path": entry.name,
                                  "bytes": data.decode(), "hex": data.hex(),
                                  "sha256": hashlib.sha256(data).hexdigest(),
                                  "mode": oct(entry.mode), "uid": entry.uid,
                                  "gid": entry.gid, "mtime": entry.mtime}
                observations[name]["files"].append(observed)
                print(json.dumps(observed), flush=True)
(root / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")

# Docker caches COPY without -t; Weld's CLI tests explicitly enable managed cache with -t.
context = root / "copy"
(context / ".dockerignore").write_text("ignored\n")
for name, extra, change in [
    ("cache-warm", [], None),
    ("cache-ignored", [], "ignored"),
    ("cache-body", [], "body"),
    ("cache-disabled", ["--no-cache"], None),
]:
    if change == "ignored":
        (context / "ignored").write_text("unrelated bytes")
    if change == "body":
        (context / "Dockerfile").write_bytes(cases["copy"].replace("\nowned\n", "\nchanged\n").encode())
    out = root / (name + ".tar")
    result = run("docker", "buildx", "build", "--pull=false", "--network=none",
                 "--progress=plain", *extra, "--output", f"type=tar,dest={out}", str(context))
    assert result.returncode == 0, result.stderr
    (root / (name + ".log")).write_text(result.stdout + result.stderr)
    copy_steps = re.findall(r"^(#\d+) \[.*\] COPY ", result.stderr, re.MULTILINE)
    hits = sum(f"{step} CACHED" in result.stderr for step in copy_steps)
    if name in ["cache-warm", "cache-ignored"]:
        assert hits == 5, result.stderr
    if name == "cache-disabled":
        assert hits == 0, result.stderr
    with tarfile.open(out) as archive:
        expected = b"changed\n" if name in ["cache-body", "cache-disabled"] else b"owned\n"
        assert archive.extractfile("owned").read() == expected
    print(name, "COPY cache hits", hits, flush=True)
