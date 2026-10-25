#!/usr/bin/env python3
"""Offline cache smoke for WSL or an authorized Pod; Python standard library only.

python3 run_acceptance.py --binary /path/rpweld --layout /path/alpine-oci --evidence /tmp/cache-qa
Run the existing .research-private/pod-capability-audit/probe.py separately first.
The fixture uses Python/Node dependency ordering, not real pip/npm installation.
Evidence must be on a Unix filesystem supporting private directory permissions.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def image_config(layout):
    def blob(descriptor):
        algorithm, digest = descriptor["digest"].split(":", 1)
        assert algorithm == "sha256"
        return json.loads((layout / "blobs" / algorithm / digest).read_text())
    manifest = blob(json.loads((layout / "index.json").read_text())["manifests"][0])
    return blob(manifest["config"])["config"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "Linux root required"
    binary, layout = args.binary.resolve(strict=True), args.layout.resolve(strict=True)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    results = []
    for language, source, lock, changed_source, changed_lock in [
        ("python", "app.py", "requirements.txt", "print('application-v2')\n", "offline-example==2\n"),
        ("node", "index.js", "package-lock.json", "console.log('application-v2');\n", '{"name":"v2","lockfileVersion":3,"packages":{}}\n'),
    ]:
        root = evidence / language
        context = root / "context"
        shutil.copytree(Path(__file__).parent / language, context)
        env = dict(os.environ, RPWELD_HOME=str(root / "store"), HOME=str(root))

        def build(name, extra=()):
            work, output = root / (name + "-work"), root / (name + "-image")
            command = [str(binary), "build", "--no-host-dns", "--base", "alpine=" + str(layout),
                       "-t", "cache-acceptance:" + language, "--work-dir", str(work),
                       "--output", str(output), *extra, str(context)]
            start = time.monotonic()
            run = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
            log = run.stdout + "\n" + run.stderr
            (root / (name + ".log")).write_text(log)
            results.append({"language": language, "case": name, "returncode": run.returncode,
                            "elapsed_seconds": round(time.monotonic() - start, 3)})
            assert run.returncode == 0, log
            return work / "rootfs", output, log

        def ran(log, token):
            return "IC_EXEC_" + token in [line.strip() for line in log.splitlines()]

        cold, _, log = build("cold")
        assert ran(log, "dependencies") and ran(log, "application"), log
        warm, _, log = build("unchanged")
        assert "CACHED" in log and not ran(log, "dependencies") and not ran(log, "application"), log
        assert (cold / "app/dependency-nonce").read_bytes() == (warm / "app/dependency-nonce").read_bytes()
        assert (cold / "app/application-nonce").read_bytes() == (warm / "app/application-nonce").read_bytes()
        (context / source).write_text(changed_source)
        app, _, log = build("application-edit")
        assert "CACHED instruction 3 COPY" in log and "CACHED instruction 4 RUN" in log, log
        assert not ran(log, "dependencies") and ran(log, "application"), log
        assert (cold / "app/dependency-nonce").read_bytes() == (app / "app/dependency-nonce").read_bytes()
        assert (cold / "app/application-nonce").read_bytes() != (app / "app/application-nonce").read_bytes()
        (context / "unrelated.txt").write_text("unselected\n")
        unrelated, _, log = build("unrelated-edit")
        assert not ran(log, "dependencies") and not ran(log, "application"), log
        assert (app / "app/application-nonce").read_bytes() == (unrelated / "app/application-nonce").read_bytes()
        (context / lock).write_text(changed_lock)
        dependency, cached_image, log = build("dependency-edit")
        assert ran(log, "dependencies") and ran(log, "application"), log
        assert (app / "app/dependency-nonce").read_bytes() != (dependency / "app/dependency-nonce").read_bytes()
        uncached, plain_image, log = build("no-cache", ["--no-cache"])
        assert ran(log, "dependencies") and ran(log, "application"), log
        assert "CACHED instruction" not in log, log
        assert (dependency / "app/result").read_bytes() == (uncached / "app/result").read_bytes()
        assert image_config(cached_image) == image_config(plain_image)
        assert changed_source in (dependency / "app/result").read_text()
        assert changed_lock in (dependency / "app/result").read_text()
    (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "builds": len(results), "evidence": str(evidence)}))


if __name__ == "__main__":
    main()
