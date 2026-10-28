#!/usr/bin/env python3
"""Small Docker reference corpus; no candidate build adapter exists yet.

Run --self-test without Docker. See fixtures/README.md for the reference contract.
"""

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import uuid


FIXTURES = Path(__file__).resolve().parent / "fixtures"
UNSUPPORTED = "this reference corpus has no Weld candidate adapter; compatibility is untested"


def command_prefix(value):
    command = json.loads(value)
    if (not isinstance(command, list) or not command
            or any(not isinstance(x, str) or not x or "\0" in x for x in command)):
        raise ValueError("--docker-command must be a nonempty JSON string array")
    return command


def base_pin(value):
    name, separator, reference = value.partition("=")
    if (not separator or name not in {"alpine", "ubuntu"}
            or not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", reference)):
        raise ValueError("base must be alpine=IMAGE@sha256:DIGEST or ubuntu=IMAGE@sha256:DIGEST")
    return name, reference


def reference_version(actual, expected):
    if not expected or expected.strip().lower() in {"latest", "auto", "*"}:
        raise ValueError("an explicit reviewed Docker server version pin is required")
    observed = actual.get("Server", {}).get("Version")
    if observed != expected:
        raise ValueError(f"Docker server version mismatch: expected {expected!r}, observed {observed!r}")


def context_digest(directory):
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            # Hash the complete fixture, including ignored inputs, with unambiguous framing.
            name = path.relative_to(directory).as_posix().encode()
            data = path.read_bytes()
            digest.update(len(name).to_bytes(8, "big") + name)
            digest.update(len(data).to_bytes(8, "big") + data)
    return "sha256:" + digest.hexdigest()


def check_semantics(archive, image, expected):
    """Read Docker's flattened export without extracting untrusted paths."""
    errors = []
    files = expected.get("files", {})
    absent = set(expected.get("absent", []))
    seen = set()
    with tarfile.open(archive, mode="r|*") as stream:
        for member in stream:
            name = member.name
            while name.startswith("./"):
                name = name[2:]
            name = name.rstrip("/")
            if name.startswith("/") or ".." in name.split("/"):
                errors.append(f"unsafe archive path: {name}")
                continue
            if name in absent:
                errors.append(f"unexpected path: {name}")
            if name not in files:
                continue
            if name in seen:
                errors.append(f"duplicate expected path: {name}")
            seen.add(name)
            wanted = files[name]
            if not member.isfile():
                errors.append(f"{name}: expected regular file")
                continue
            for key in ("uid", "gid"):
                if key in wanted and getattr(member, key) != wanted[key]:
                    errors.append(f"{name}: incorrect {key}")
            if "mode" in wanted and member.mode & 0o7777 != int(wanted["mode"], 8):
                errors.append(f"{name}: incorrect mode")
            if "text" in wanted:
                content = wanted["text"].encode("utf-8")
                if member.size != len(content) or stream.extractfile(member).read(len(content) + 1) != content:
                    errors.append(f"{name}: incorrect content")
    errors.extend(f"missing file: {name}" for name in sorted(set(files) - seen))
    config = image.get("Config") or {}
    for key, value in expected.get("config", {}).items():
        if config.get(key) != value:
            errors.append(f"config {key}: expected {value!r}, got {config.get(key)!r}")
    for value in expected.get("env", []):
        if value not in (config.get("Env") or []):
            errors.append(f"missing environment: {value}")
    for key, value in expected.get("labels", {}).items():
        if (config.get("Labels") or {}).get(key) != value:
            errors.append(f"incorrect label: {key}")
    for port in expected.get("ports", []):
        if port not in (config.get("ExposedPorts") or {}):
            errors.append(f"missing exposed port: {port}")
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        errors.append("image platform is not linux/amd64")
    return errors


def run_reference(args, report):
    command = command_prefix(args.docker_command)
    pins = {}
    for value in args.base:
        name, reference = base_pin(value)
        if name in pins:
            raise ValueError(f"duplicate base pin: {name}")
        pins[name] = reference
    corpus = json.loads((FIXTURES / "expectations.json").read_text(encoding="utf-8"))
    selected = args.fixture or [name for name, spec in corpus["fixtures"].items() if not spec["network"]]
    for name in selected:
        if name not in corpus["fixtures"]:
            raise ValueError(f"unknown fixture: {name}")
        spec = corpus["fixtures"][name]
        if spec["network"] and not args.allow_network:
            raise ValueError(f"{name} requires explicit --allow-network")
        if spec["base"] not in pins:
            raise ValueError(f"missing --base pin for {spec['base']}")
    # Validate the pin before invoking any external command, even the version probe.
    reference_version({"Server": {"Version": args.reference_version}}, args.reference_version)
    env = dict(os.environ, DOCKER_BUILDKIT="1")

    def docker(*arguments, output=None):
        result = subprocess.run(command + list(arguments), env=env, check=True,
                                stdout=output if output else subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=args.timeout)
        return result.stdout.decode("utf-8") if output is None else None

    version = json.loads(docker("version", "--format", "{{json .}}"))
    report["reference"] = {"command": command, "version": version,
                           "required_server_version": args.reference_version,
                           "frontend": "Docker bundled frontend; no external syntax directive",
                           "platform": "linux/amd64"}
    reference_version(version, args.reference_version)
    report["bases"] = {}
    for base in sorted({corpus["fixtures"][name]["base"] for name in selected}):
        ref = pins[base]
        docker("pull", "--platform", "linux/amd64", ref)
        report["bases"][base] = {"requested": ref, "inspect": json.loads(docker("image", "inspect", ref))[0]}
    report["results"] = []
    for name in selected:
        spec = corpus["fixtures"][name]
        result = {"fixture": name, "status": "failed", "network": spec["network"],
                  "context_digest": context_digest(FIXTURES / name)}
        report["results"].append(result)
        tag = "rpweld-compat-" + uuid.uuid4().hex
        container = None
        cleanup_errors = []
        try:
            with tempfile.TemporaryDirectory(prefix="rpweld-compat-") as tmp:
                log = Path(tmp) / "build.log"
                try:
                    with log.open("wb") as output:
                        docker("build", "--no-cache", "--platform", "linux/amd64", "--network",
                               "default" if spec["network"] else "none", "--build-arg",
                               "BASE=" + pins[spec["base"]], "-t", tag, str(FIXTURES / name), output=output)
                finally:
                    with log.open("rb") as output:
                        output.seek(max(0, log.stat().st_size - 65536))
                        result["build_stdout_tail"] = output.read().decode("utf-8", errors="replace")
                image = json.loads(docker("image", "inspect", tag))[0]
                result["image"] = image  # Actual config ID, rootfs diff IDs and RepoDigests, if any.
                container = docker("create", "--entrypoint", "/__weld_not_executed__", tag).strip()
                archive = Path(tmp) / "rootfs.tar"
                docker("export", "--output", str(archive), container)
                result["errors"] = check_semantics(archive, image, spec)
                result["status"] = "failed" if result["errors"] else "passed"
        except (OSError, subprocess.SubprocessError, ValueError, tarfile.TarError) as error:
            result["error"] = str(error)
            if getattr(error, "stderr", None):
                result["stderr_tail"] = error.stderr[-65536:].decode("utf-8", errors="replace")
        finally:
            if container:
                try:
                    docker("rm", "-f", container)
                except (OSError, subprocess.SubprocessError) as error:
                    cleanup_errors.append(str(error))
            try:
                docker("image", "rm", tag)
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append(str(error))
            if cleanup_errors:
                result["cleanup_errors"] = cleanup_errors
                result["status"] = "failed"
    return 0 if all(item["status"] == "passed" for item in report["results"]) else 1


class DriverTests(unittest.TestCase):
    def test_compare_never_invokes_commands(self):
        output = io.StringIO()
        with mock.patch("subprocess.run") as run, contextlib.redirect_stdout(output):
            self.assertEqual(main(["--mode", "compare"]), 2)
        run.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["candidate"]["status"], "unsupported")

    def test_missing_pin_never_invokes_commands(self):
        output = io.StringIO()
        args = ["--mode", "reference", "--docker-command", '["docker"]',
                "--base", "alpine=alpine@sha256:" + "a" * 64]
        with mock.patch("subprocess.run") as run, contextlib.redirect_stdout(output):
            self.assertEqual(main(args), 1)
        run.assert_not_called()
        self.assertIn("version pin", json.loads(output.getvalue())["error"])

    def test_command_is_argv_not_shell(self):
        self.assertEqual(command_prefix('["docker", "--context", "local"]'), ["docker", "--context", "local"])
        for value in ('"docker build"', '[]', '[1]', '[""]'):
            with self.assertRaises(ValueError):
                command_prefix(value)

    def test_digest_pin(self):
        self.assertEqual(base_pin("alpine=alpine@sha256:" + "a" * 64)[0], "alpine")
        for value in ("alpine=alpine:latest", "alpine=alpine@sha256:abc", "other=x@sha256:" + "a" * 64):
            with self.assertRaises(ValueError):
                base_pin(value)

    def test_reference_pin(self):
        reference_version({"Server": {"Version": "1.2.3"}}, "1.2.3")
        for pin in (None, "", "latest", "auto", "*", "1.2.4"):
            with self.assertRaises(ValueError):
                reference_version({"Server": {"Version": "1.2.3"}}, pin)

    def test_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "rootfs.tar"
            with tarfile.open(archive, "w") as stream:
                entry = tarfile.TarInfo("./proof")
                entry.size, entry.uid, entry.gid, entry.mode = 3, 1234, 1234, 0o600
                stream.addfile(entry, io.BytesIO(b"ok\n"))
            image = {"Os": "linux", "Architecture": "amd64", "Config": {"User": "1234:1234"}}
            spec = {"files": {"proof": {"text": "ok\n", "uid": 1234, "gid": 1234, "mode": "0600"}}, "config": {"User": "1234:1234"}}
            self.assertEqual(check_semantics(archive, image, spec), [])
            spec["absent"] = ["proof"]
            spec["files"]["proof"]["uid"] = 0
            spec["files"]["proof"]["text"] = "no\n"
            errors = check_semantics(archive, image, spec)
            self.assertEqual(len(errors), 3)

    def test_corpus_and_context_hash(self):
        corpus = json.loads((FIXTURES / "expectations.json").read_text())
        self.assertEqual(corpus["schema_version"], 1)
        for name, spec in corpus["fixtures"].items():
            self.assertTrue((FIXTURES / name / "Dockerfile").is_file())
            self.assertTrue(spec["files"])
            self.assertEqual(context_digest(FIXTURES / name), context_digest(FIXTURES / name))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "input").write_bytes(b"a")
            before = context_digest(path)
            (path / "input").write_bytes(b"b")
            self.assertNotEqual(before, context_digest(path))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--mode", choices=("reference", "compare"), default="compare")
    parser.add_argument("--docker-command", help='explicit argv JSON, e.g. ["docker"]')
    parser.add_argument("--reference-version", help="required exact Docker server version")
    parser.add_argument("--base", action="append", default=[], help="alpine/ubuntu=IMAGE@sha256:DIGEST")
    parser.add_argument("--fixture", action="append")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(DriverTests)).wasSuccessful() else 1
    report = {"schema_version": 1, "mode": args.mode,
              "candidate": {"status": "unsupported", "reason": UNSUPPORTED}}
    if args.mode == "compare":
        report["status"] = "blocked"
        code = 2
    else:
        report["candidate"]["status"] = "skipped"
        try:
            if not args.docker_command or args.timeout <= 0:
                raise ValueError("reference mode requires --docker-command and a positive timeout")
            code = run_reference(args, report)
            report["status"] = "reference-passed" if code == 0 else "failed"
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            report.update(status="failed", error=str(error))
            code = 1
    output = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    print(output, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
