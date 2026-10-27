"""Small native Linux self-tests; optional immutable baseline-only acceptance smoke."""
import json
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest

from acceptance import (assert_isolation, assert_log, assert_preserved, assert_tree, cache_fingerprint,
                        expected_tree, load, mutation_probe, replay, snapshot, verify_output)
from fixture import TIMES, digest, edit_app, make_base, make_context
from metrics import build_environment, measure, usage
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("pod_session", Path(__file__).parent / "pod-session.py")
pod_session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pod_session)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "native Linux root required")
class Fixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="v02-fixture-unit-", dir="/var/tmp")
        self.root = Path(self.temp.name)
        os.umask(0o022)

    def tearDown(self):
        self.temp.cleanup()

    def test_reproducible_base_context_and_observers(self):
        busybox = Path(shutil.which("busybox"))
        for name in ("a", "b"):
            make_base(busybox, self.root / name)
            replay(self.root / name, self.root / (name + "-replay"))
            make_context(self.root / (name + "-context"), 1, 8)
        assert load(self.root / "a") == load(self.root / "b")
        assert_tree(snapshot(self.root / "a-replay"), snapshot(self.root / "b-replay"))
        context = self.root / "a-context"
        before = snapshot(context)
        assert_tree(before, snapshot(self.root / "b-context"))
        usage(context)
        for path in context.rglob("*"):
            if path.is_file():
                digest(path)
        assert_tree(before, snapshot(context))
        assert all((item["atime_ns"], item["mtime_ns"]) == TIMES for item in before.values())
        edit_app(context)
        after = snapshot(context)
        differences = [key for key in before if before[key] != after[key]]
        assert differences == ["app/main.txt"], differences

    def test_corrupt_oci_descriptor_rejected(self):
        make_base(Path(shutil.which("busybox")), self.root / "base")
        manifest, _ = load(self.root / "base")
        blob = self.root / "base/blobs/sha256" / manifest["layers"][0]["digest"].split(":")[1]
        with blob.open("r+b") as stream:
            stream.write(b"!")
        with self.assertRaises(AssertionError):
            load(self.root / "base")

    def test_hardlink_allocation_and_noatime(self):
        data = self.root / "data"
        data.write_bytes(b"x" * 8192)
        before = usage(self.root)
        os.link(data, self.root / "alias")
        after = usage(self.root)
        assert before["unique_inodes"] == after["unique_inodes"]
        assert after["allocated_bytes"] == before["allocated_bytes"]
        assert after["logical_bytes"] > before["logical_bytes"]

    def test_measure_waited_child_io_and_cpu(self):
        child = self.root / "writer.py"
        child.write_text("import os,sys\nf=open(sys.argv[1], 'wb')\nf.write(b'x'*1048576)\nf.flush()\nos.fsync(f.fileno())\nsum(i*i for i in range(500000))\n")
        parent = self.root / "parent.py"
        parent.write_text("import subprocess,sys\nsubprocess.run(sys.argv[1:], check=True)\n")
        result = measure([sys.executable, str(parent), sys.executable, str(child), str(self.root / "written")],
            dict(os.environ), [self.root], self.root / "logs", interval=0.02)
        assert result["proc_io"]["write_bytes"] >= 1048576, result
        assert result["cpu_user_seconds"] > 0
        assert result["allocated_sampled_peak_bytes"] >= result["allocated_retained"]["allocated_bytes"]

    def test_timeout_preserves_failure_evidence(self):
        with self.assertRaises(AssertionError):
            measure([sys.executable, "-c", "import time; time.sleep(2)"], dict(os.environ),
                    [self.root], self.root / "logs", timeout=0.05)
        result = json.loads((self.root / "logs/measurement.json").read_text())
        assert result["timed_out"] and result["returncode"] < 0

    def test_cache_log_requires_actual_execution_lines(self):
        assert_log("warm", "CACHED stage 0\nRUN echo V02_EXEC_application\n")
        for invalid in ("", "RUN echo V02_EXEC_dependencies\n"):
            with self.assertRaises(AssertionError):
                assert_log("cold", invalid)
        log = "\n".join(f"[stage 0 RUN stdout] V02_EXEC_{name}" for name in ("dependencies", "config", "application"))
        assert_log("cold", log)
        with self.assertRaises(AssertionError):
            assert_log("warm", log + "\nCACHED stage 0")

    def test_teardown_requires_get_and_list_absence(self):
        ok, missing = {"returncode": 0, "code": None}, {"returncode": 1, "code": "not_found"}
        calls = []
        def fake(cli, arguments):
            calls.append(arguments)
            if arguments[1] == "get":
                return missing, None
            return ok, []
        with patch.object(pod_session, "call", fake):
            pod_session.cleanup("unused", "owned123", self.root)
        assert calls == [["pod", "delete", "owned123"], ["pod", "get", "owned123"], ["pod", "list", "--all"]]
        assert json.loads((self.root / "teardown.json").read_text())["verified_absent"]
        with patch.object(pod_session, "call", return_value=({"returncode": 1, "code": "no_credentials"}, None)):
            with self.assertRaises(RuntimeError):
                pod_session.cleanup("unused", "owned123", self.root)
        assert not json.loads((self.root / "teardown.json").read_text())["verified_absent"]

    def test_cached_prefix_and_inode_sharing(self):
        from acceptance import candidate_prefix
        from fixture import blob, CONFIG, MANIFEST, LAYER, write_json
        import io
        import tarfile
        base = self.root / "base"
        make_base(Path(shutil.which("busybox")), base)
        initial, config = load(base)
        layers = list(initial["layers"])
        pool = self.root / "store/cache-v2/content/blobs/sha256"
        pool.mkdir(parents=True)
        for item in (base / "blobs/sha256").iterdir():
            shutil.copyfile(item, pool / item.name)
        for ordinal in range(7):
            entry = self.root / f"store/cache-v2/entries/{ordinal}"
            (entry / "blobs/sha256").mkdir(parents=True)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                info = tarfile.TarInfo(f"step-{ordinal}")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            layers.append(blob(entry, buffer.getvalue(), LAYER))
            config["rootfs"]["diff_ids"] = [layer["digest"] for layer in layers]
            config["history"].append({"created_by": f"step {ordinal}"})
            if ordinal == 6:
                config["config"]["Labels"] = {"org.rpweld.fixture": "v02-performance"}
            cd = blob(entry, json.dumps(config).encode(), CONFIG)
            md = blob(entry, json.dumps({"schemaVersion": 2, "config": cd, "layers": layers}).encode(), MANIFEST)
            write_json(entry / "index.json", {"manifests": [md]})
            for item in list((entry / "blobs/sha256").iterdir()):
                if not (pool / item.name).exists():
                    shutil.copyfile(item, pool / item.name)
                item.unlink()
            for descriptor in [*layers, cd, md]:
                checksum = descriptor["digest"].split(":")[1]
                os.link(pool / checksum, entry / "blobs/sha256" / checksum)
        result = candidate_prefix(self.root / "store", base)
        assert len(result["unique_layer_chains"]) == 6
        assert len(result["metadata_suffix_entries"]) == 1
        # Duplicate payload at one alias is byte-correct but must fail ownership.
        alias = self.root / "store/cache-v2/entries/0/blobs/sha256" / initial["layers"][0]["digest"].split(":")[1]
        data = alias.read_bytes()
        alias.unlink()
        alias.write_bytes(data)
        with self.assertRaises(AssertionError):
            candidate_prefix(self.root / "store", base)

    @unittest.skipUnless(os.environ.get("RPWELD_V02_BASELINE"), "optional baseline-only smoke")
    def test_immutable_baseline_managed_smoke(self):
        binary = Path(os.environ["RPWELD_V02_BASELINE"])
        expected_hash = os.environ["RPWELD_V02_BASELINE_SHA256"]
        assert digest(binary) == expected_hash
        make_base(Path(shutil.which("busybox")), self.root / "base")
        replay(self.root / "base", self.root / "base-replay")
        base_tree = snapshot(self.root / "base-replay")
        context, store = self.root / "context", self.root / "store"
        make_context(context, 1, 8)
        outputs, cold = [], None
        for case in ("cold", "warm", "app-edit", "no-cache"):
            if case == "app-edit":
                edit_app(context)
            before = cache_fingerprint(store)
            output, logs = self.root / (case + "-out"), self.root / (case + "-logs")
            command = [str(binary), "build", "--no-host-dns", "--base", "fixture=" + str(self.root / "base"),
                       "-t", "v02-fixture:smoke", "--work-dir", str(self.root / (case + "-work")), "--output", str(output)]
            if case == "no-cache":
                command.append("--no-cache")
            command.append(str(context))
            measure(command, build_environment(self.root, store), [self.root], logs, timeout=180)
            assert_log(case, (logs / "stdout.log").read_text() + "\n" + (logs / "stderr.log").read_text())
            if before:
                assert_preserved(before, cache_fingerprint(store), exact=case in ("warm", "no-cache"))
            checked = verify_output(output, self.root / (case + "-replay"), self.root / "base",
                expected_tree(base_tree, context, 2 if case in ("app-edit", "no-cache") else 1))
            if case == "cold":
                cold = checked
            if case == "warm":
                assert checked == cold
            outputs.append(output)
            assert_isolation(store, outputs)
        mutation_probe(store, outputs)


if __name__ == "__main__":
    unittest.main()
