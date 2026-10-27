#!/usr/bin/env python3
"""Same-Pod, alternating baseline/candidate managed-build performance acceptance."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import sys

from acceptance import (assert_isolation, assert_log, assert_preserved, assert_tree,
    cache_fingerprint, candidate_prefix, expected_tree, load, mutation_probe, replay, snapshot, verify_output)
from fixture import digest, edit_app, make_base, make_context, write_json
from metrics import build_environment, environment, measure, usage

BASELINE_REVISION = "63b716e1027ceba48bf9c887567419057b1bfd73"


def summary(results):
    output = {}
    for case in ("cold", "warm", "app-edit", "no-cache"):
        output[case] = {}
        for variant in ("baseline", "candidate"):
            rows = [r for r in results if r["case"] == case and r["variant"] == variant]
            output[case][variant] = {"samples": len(rows)}
            for field in ("wall_seconds", "cpu_user_seconds", "cpu_system_seconds", "allocated_sampled_peak_bytes",
                          "layer_bytes", "new_layer_bytes"):
                values = [r[field] for r in rows]
                output[case][variant][field] = {"raw": values, "median": statistics.median(values),
                    "minimum": min(values), "maximum": max(values)}
        # Paired ratios retain repetition order; no assertion that candidate wins.
        before = {r["repetition"]: r for r in results if r["case"] == case and r["variant"] == "baseline"}
        after = {r["repetition"]: r for r in results if r["case"] == case and r["variant"] == "candidate"}
        output[case]["paired_baseline_over_candidate_wall"] = [
            before[i]["wall_seconds"] / after[i]["wall_seconds"] for i in sorted(before)]
    return output


def run(args):
    assert os.geteuid() == 0, "Linux root is required for trusted RUN/metadata fixtures"
    os.umask(0o022)
    assert datetime.now(timezone.utc).timestamp() < 2000000000, "timestamp pin needs a new version after 2033"
    assert re.fullmatch(r"[0-9a-f]{40}", args.candidate_revision), "full frozen candidate commit required"
    assert args.parent_go == args.candidate_revision, "parent GO must name the frozen candidate commit"
    assert re.fullmatch(r"[0-9a-f]{64}", args.candidate_sha256)
    assert re.fullmatch(r"[0-9a-f]{64}", args.baseline_sha256)
    assert args.repetitions >= 2 and args.repetitions % 2 == 0, "use balanced AB/BA repetitions"
    assert args.dependency_mib >= 256 and args.small_files >= 2048, "performance fixture too small"
    assert not sys.flags.optimize, "assertions must be enabled"
    baseline, candidate = args.baseline.resolve(strict=True), args.candidate.resolve(strict=True)
    assert digest(baseline) == args.baseline_sha256
    assert digest(candidate) == args.candidate_sha256
    assert baseline != candidate and args.baseline_sha256 != args.candidate_sha256
    deadline = datetime.fromisoformat(args.deadline_utc.replace("Z", "+00:00"))
    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    assert 0 < remaining <= 7200, "set a future deadline no more than two hours away"
    args.evidence = args.evidence.resolve()
    args.scratch = args.scratch.resolve()
    assert args.evidence != args.scratch and args.evidence not in args.scratch.parents and args.scratch not in args.evidence.parents
    args.evidence.mkdir(parents=True, exist_ok=False)
    args.scratch.mkdir(parents=True, exist_ok=False)
    env_info = environment(args.scratch)
    write_json(args.evidence / "environment.json", env_info)
    fs = json.loads(env_info["findmnt"])["filesystems"][0]["fstype"]
    assert fs in ("ext4", "xfs", "btrfs", "overlay"), f"native local disk required, found {fs}"
    # Conservative initial guard; retained trees are removed after each verified pair.
    assert env_info["storage"]["available_bytes"] >= max(30 * 1024**3, args.dependency_mib * 1024**2 * 70)
    def expired(*_):
        raise TimeoutError("experiment deadline reached; collect evidence and delete the Pod")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(int(remaining))
    provenance = {"pod_id": args.pod_id, "deadline_utc": deadline.isoformat(),
        "baseline_revision": BASELINE_REVISION, "candidate_revision": args.candidate_revision,
        "baseline_sha256": digest(baseline), "candidate_sha256": digest(candidate),
        "repetitions": args.repetitions, "dependency_mib": args.dependency_mib, "small_files": args.small_files,
        "scripts_sha256": {p.name: digest(p) for p in Path(__file__).parent.glob("*.py")},
        "oracle_sha256": {name: digest(Path(__file__).parent.parent / "layered-export" / name)
                          for name in ("oracle.py", "fixture_tar.py")},
        "runtime_helpers_sha256": {name: {str(p.relative_to(binary.parent.parent)): digest(p)
            for p in sorted((binary.parent.parent / "lib/rpweld").rglob("*")) if p.is_file()}
            for name, binary in (("baseline", baseline), ("candidate", candidate))},
        "notes": ["cold = empty managed store; OS page cache is not dropped",
                  "ordinary default export, actual -t, no private fast flags",
                  "wall and CPU are build-only; independent validation follows each build",
                  "allocation st_blocks*512 deduplicated by device/inode; reflink extents not deduplicated",
                  "sampled allocation peaks are lower bounds; sampling overhead is recorded",
                  "proc I/O leader includes waited children; physical read_bytes can be zero from page cache",
                  "synthetic offline dependency workload, not pip/npm/Nemotron or power-loss/sandbox evidence"]}
    base = args.scratch / "base"
    provenance["busybox_sha256"] = make_base(args.busybox.resolve(strict=True), base)
    replay(base, args.scratch / "base-replay")
    base_tree = snapshot(args.scratch / "base-replay")
    write_json(args.evidence / "base-tree.json", base_tree)
    write_json(args.evidence / "base-image.json", dict(zip(("manifest", "config"), load(base))))
    write_json(args.evidence / "provenance.json", provenance)
    results = []
    reference = {}
    try:
        for repetition in range(args.repetitions):
            pair = args.scratch / f"pair-{repetition:02d}"
            pair.mkdir()
            variants = ("baseline", "candidate") if repetition % 2 == 0 else ("candidate", "baseline")
            state = {}
            for variant in variants:
                root = pair / variant
                context = root / "context"
                make_context(context, args.dependency_mib, args.small_files)
                state[variant] = {"root": root, "context": context, "store": root / "store", "outputs": [], "previous_layers": set()}
            for case in ("cold", "warm", "app-edit", "no-cache"):
                for position, variant in enumerate(variants):
                    current = state[variant]
                    root, context, store = current["root"], current["context"], current["store"]
                    version = 2 if case in ("app-edit", "no-cache") else 1
                    if case == "app-edit":
                        edit_app(context)
                    before_context = snapshot(context)
                    before_cache = cache_fingerprint(store)
                    if case == "cold":
                        assert not store.exists(), "cold store must not exist"
                    work, output = root / (case + "-work"), root / (case + "-output")
                    log_dir = args.evidence / f"r{repetition:02d}-{case}-{variant}"
                    command = [str(baseline if variant == "baseline" else candidate), "build", "--no-host-dns",
                        "--base", "fixture=" + str(base), "-t", "v02-performance:fixture",
                        "--work-dir", str(work), "--output", str(output)]
                    if case == "no-cache":
                        command.append("--no-cache")
                    command.append(str(context))
                    print(f"START repetition={repetition} case={case} variant={variant}", flush=True)
                    child_env = build_environment(root, store)
                    row = measure(command, child_env, [root], log_dir,
                                  timeout=min(args.build_timeout, max(1, (deadline-datetime.now(timezone.utc)).total_seconds())))
                    row.update({"repetition": repetition, "case": case, "variant": variant, "position": position,
                        "build_environment": child_env,
                        "allocation_scopes": {name: usage(path) for name, path in
                            (("context", context), ("store", store), ("work", work), ("output", output), ("all_retained", root))}})
                    log = (log_dir / "stdout.log").read_text() + "\n" + (log_dir / "stderr.log").read_text()
                    row["cache_log"] = assert_log(case, log)
                    assert_tree(snapshot(context), before_context)
                    after_cache = cache_fingerprint(store)
                    if case != "cold":
                        assert_preserved(before_cache, after_cache, exact=case in ("warm", "no-cache"))
                    write_json(log_dir / "cache-fingerprint.json", after_cache)
                    if case == "cold" and variant == "candidate":
                        current["prefix"] = candidate_prefix(store, base)
                        write_json(log_dir / "prefix.json", current["prefix"])
                    replay_root = root / (case + "-replay")
                    manifest, config, tree = verify_output(output, replay_root, base,
                        expected_tree(base_tree, context, version))
                    if case == "cold":
                        current["cold_manifest"], current["cold_config"], current["cold_tree"] = manifest, config, tree
                    elif case == "warm":
                        assert manifest == current["cold_manifest"] and config == current["cold_config"], "warm descriptors/config changed"
                        assert_tree(tree, current["cold_tree"])
                    if case == "app-edit" and variant == "candidate":
                        prefix = current["prefix"]["unique_layer_chains"][3]
                        assert manifest["layers"][:len(prefix["layers"])] == prefix["layers"]
                        assert config["rootfs"]["diff_ids"][:len(prefix["diff_ids"])] == prefix["diff_ids"]
                    # Check all repetitions, both binaries, and populated no-cache controls.
                    if version in reference:
                        assert_tree(tree, reference[version]["tree"])
                        assert config["config"] == reference[version]["runtime"], "runtime config differs"
                    else:
                        reference[version] = {"tree": tree, "runtime": config["config"]}
                    layers = {d["digest"]: d["size"] for d in manifest["layers"]}
                    row.update({"manifest": manifest, "config": config, "layer_bytes": sum(d["size"] for d in manifest["layers"]),
                        "new_layer_bytes": sum(size for key, size in layers.items() if key not in current["previous_layers"]),
                        "new_layer_digests": sorted(layers.keys() - current["previous_layers"]),
                        "output_blob_hashes": {p.name: digest(p) for p in sorted((output / "blobs/sha256").iterdir())}})
                    current["previous_layers"] = set(layers)
                    current["outputs"].append(output)
                    assert_isolation(store, current["outputs"])
                    write_json(log_dir / "replay-tree.json", tree)
                    write_json(log_dir / "result.json", row)
                    results.append(row)
                    write_json(args.evidence / "results.json", results)
                    # Disposable independent replay isn't part of retained builder storage.
                    shutil.rmtree(replay_root)
                    print(f"PASS repetition={repetition} case={case} variant={variant} wall={row['wall_seconds']:.3f}s", flush=True)
            for variant in variants:
                mutation_probe(state[variant]["store"], state[variant]["outputs"])
            write_json(args.evidence / f"r{repetition:02d}-completed.json", {"order": variants,
                "mutable_output_mutation_probe": "PASS", "pair_retained": usage(pair)})
            assert pair.parent == args.scratch and pair.name == f"pair-{repetition:02d}"
            shutil.rmtree(pair)
        assert digest(baseline) == args.baseline_sha256 and digest(candidate) == args.candidate_sha256
        write_json(args.evidence / "summary.json", summary(results))
        write_json(args.evidence / "status.json", {"status": "PASS", "builds": len(results)})
    except BaseException as error:
        write_json(args.evidence / "status.json", {"status": "FAIL", "completed_builds": len(results), "error": str(error)})
        raise
    finally:
        signal.alarm(0)
        write_json(args.evidence / "environment-after.json", environment(args.scratch))
    print(json.dumps({"status": "PASS", "evidence": str(args.evidence), "builds": len(results)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "candidate", "busybox", "scratch", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("baseline-sha256", "candidate-sha256", "candidate-revision", "parent-go", "pod-id", "deadline-utc"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--dependency-mib", type=int, default=256)
    parser.add_argument("--small-files", type=int, default=2048)
    parser.add_argument("--repetitions", type=int, default=4)
    parser.add_argument("--build-timeout", type=int, default=600)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
