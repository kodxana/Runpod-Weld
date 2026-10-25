#!/usr/bin/env python3
"""Opt-in local Docker oracle. No pulls, credentials, packages, or global pruning."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid

FIXTURES = Path(__file__).resolve().parent


def run(args, timeout=120):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    return {"command": args, "status": process.returncode, "stdout": stdout, "stderr": stderr}


def main():
    layout, evidence = map(Path, sys.argv[1:])
    assert (layout / "index.json").is_file()
    evidence.mkdir(parents=True, exist_ok=True)
    report = {"docker": run(["docker", "version"]),
              "buildx": run(["docker", "buildx", "version"]), "cases": []}
    base = "weld-user-qa-local:" + uuid.uuid4().hex
    images = []
    try:
        imported = run(["skopeo", "copy", "oci:" + str(layout), "docker-daemon:" + base])
        report["import"] = imported
        assert imported["status"] == 0, imported
        images.append(base)
        report["base"] = run(["docker", "image", "inspect", base])
        cases = [
            ("runtime", (FIXTURES / "Dockerfile.runtime").read_text(), True),
            ("unknown-metadata", "FROM scratch\nUSER absent:missing\n", True),
            ("unknown-user-run", "FROM alpine\nUSER absent\nRUN touch /application-started\n", False),
            ("unknown-group-run", "FROM alpine\nUSER 12001:missing\nRUN touch /application-started\n", False),
            ("stage-metadata", "FROM scratch AS first\nUSER absent:missing\nFROM first\nCMD [\"/true\"]\n", True),
        ]
        with tempfile.TemporaryDirectory(prefix="weld-user-oracle-") as directory:
            context = Path(directory)
            for name in ["passwd", "group", "payload"]:
                shutil.copyfile(FIXTURES / name, context / name)
            for name, source, expected in cases:
                (context / "Dockerfile").write_text(source.replace("FROM alpine", "FROM " + base))
                iid = context / "iid"
                iid.unlink(missing_ok=True)
                result = run(["docker", "build", "--pull=false", "--network=none", "--no-cache",
                              "--progress=plain", "--iidfile", str(iid), str(context)])
                result.update(name=name, expected_success=expected)
                if iid.exists():
                    image = iid.read_text().strip()
                    images.append(image)
                    result["inspect"] = run(["docker", "image", "inspect", image])
                    actual_user = json.loads(result["inspect"]["stdout"])[0]["Config"]["User"]
                    expected_user = "alice:chosen" if name == "runtime" else "absent:missing"
                    result["user"] = actual_user
                    result["expected_user"] = expected_user
                report["cases"].append(result)
                print(name, result["status"], flush=True)
    finally:
        report["cleanup"] = [run(["docker", "image", "rm", image]) for image in reversed(images)]
        (evidence / "docker-oracle.json").write_text(json.dumps(report, indent=2) + "\n")
    assert all((case["status"] == 0) == case["expected_success"] for case in report["cases"])
    assert all(case.get("user") == case.get("expected_user") for case in report["cases"])


if __name__ == "__main__":
    main()
