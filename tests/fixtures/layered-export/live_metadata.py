"""Exact live metadata for trusted Linux/Docker fixtures; no content reads."""
import json
import os
from pathlib import Path
import subprocess


def compile_probe(destination):
    subprocess.run(["cc", "-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(Path(__file__).with_suffix(".c")), "-o", str(destination)], check=True)
    return destination


def decode_probe(data):
    result = {}
    for line in data.splitlines():
        item = json.loads(line)
        name = os.fsdecode(bytes.fromhex(item.pop("path_hex")))
        assert name not in result, name
        for field in ["atime", "mtime", "ctime"]:
            item[field + "_ns"] = item.pop(field + "_sec") * 1_000_000_000 + item.pop(field + "_nsec")
        item["xattrs"] = {os.fsdecode(bytes.fromhex(k)): v for k, v in item["xattrs"].items()}
        result[name] = item
    return result


def probe_input(paths):
    return b"".join(os.fsencode(path) + b"\0" for path in paths)


def assert_metadata(actual, expected):
    assert set(actual) == set(expected), (set(actual), set(expected))
    for path, item in expected.items():
        for field in ["mode", "uid", "gid", "mtime_ns", "xattrs"]:
            assert actual[path][field] == item[field], (path, field, actual[path][field], item[field])


def docker_metadata(reference, helper, paths, evidence):
    # A separate container starts only the bind-mounted static probe, before
    # export or application execution can read image files. No image shell/loader.
    container = subprocess.check_output([
        "docker", "create", "--network=none", "--user", "0:0", "--workdir", "/", "-i",
        "--mount", "type=bind,src=" + str(helper) + ",dst=/__layered_metadata,readonly",
        "--entrypoint", "/__layered_metadata", reference]).decode().strip()
    try:
        output = subprocess.check_output(["docker", "start", "-a", "-i", container], input=probe_input(paths))
        state = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]["State"]
        assert state["ExitCode"] == 0, state
        evidence.write_bytes(output)
        return decode_probe(output)
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)
