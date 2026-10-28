# Managed COPY checkpoint comparison on a Pod

The COPY checkpoint candidate used **32.4% less cold-build time** and **8.5% less
application-edit time** in this same-Pod, balanced comparison. Both execution
orders improved. Warm and no-cache controls were essentially unchanged.
All 16 builds and both full paired acceptance checks passed.

This is a synthetic 1 GiB dependency plus 2,048 small files, not the full Nemotron
image. Two runs per arm on one host do not establish a general speed guarantee
or stable-release readiness. The [real workload timeout](real-nemotron-5860971.md)
and missing real cold/warm/edit output acceptance remain open.

## Complete measurements

Times cover the complete builder process; independent acceptance is outside
that interval. No runs were retried, removed, or corrected by subtracting stalls.
Raw measurements, output descriptors, provenance, collected-file hashes and
teardown receipts are in [copy-checkpoint-pod.json](copy-checkpoint-pod.json).

| Case | Baseline seconds: median (two runs) | Candidate seconds: median (two runs) | Median elapsed change | CPU seconds: baseline to candidate |
| --- | ---: | ---: | ---: | ---: |
| Cold | 39.408 (39.564, 39.253) | 26.621 (26.518, 26.725) | -32.4% | 39.018 to 26.225 |
| Warm | 5.464 (5.422, 5.505) | 5.474 (5.487, 5.461) | +0.2% | 5.346 to 5.364 |
| Application edit | 32.638 (32.515, 32.761) | 29.869 (29.769, 29.969) | -8.5% | 32.407 to 29.661 |
| No cache | 6.131 (6.095, 6.167) | 6.145 (6.128, 6.163) | +0.2% | 6.031 to 6.029 |

Median process `rchar` fell from 52.965 GB to 34.589 GB for cold builds, and
48.644 GB to 44.323 GB for edits (decimal GB). These count logical reads across
the process, not exclusively SHA input or physical disk traffic. Recorded
`read_bytes` was zero for every build; this was a page-cache-resident workload.
Cold means an empty Weld cache, not a flushed kernel page cache.

Retained allocation was essentially unchanged: approximately 5.41 GB per arm
after cold, 7.58 GB after warm, 10.82 GB after edit and 12.99 GB after no-cache.
These include the arm's context, store and earlier retained work/outputs, measured
outside timed execution. They are not transient disk peaks or full-image sizing
guarantees. Raw `wait4` maximum-RSS counters are retained without a memory-saving
claim; they can include fork/pre-exec state from the Python harness.

## Scope and method

Baseline `a3ce37f6a951a388a1c81d19ae93597fbd74914e` already contains managed
publication sessions. Candidate `5204299e1340a2ca8b5401ad8ec751843d96cfa4` adds
[managed COPY inventory and inherited-layer reuse](copy-checkpoint-reuse.md).
The comparison measures that combined change, not each part independently.
New physical objects and final publication retain complete verification;
arbitrary-callback public APIs remain conservative.

Both exact revisions were built as static Linux amd64 executables with Rust 1.90,
the same dependencies, build command and bundled helpers. Their hashes and
[689-test correctness run](copy-checkpoint-validation.md) are recorded separately.
This run used ordinary managed layered defaults; only the no-cache case added
`--no-cache`. Gzip correctness passed separate tests, but gzip performance was
not measured here.

A fresh Secure `cpu3g` Pod in EU-CZ-1 supplied eight assigned logical CPUs on
an AMD EPYC 9654 host, a 32,000,000,000-byte cgroup memory ceiling and 80 GB
requested ephemeral disk. Linux was `6.8.0-138-generic`. The container used
overlay storage; XFS host-bind topology, RAID members and a synced-write
accounting probe corroborated local NVMe backing. No network volume, registry
download, model download or GPU workload was involved.

The fixture has three COPY/RUN pairs. Each case ran baseline then candidate in
repetition zero, candidate then baseline in repetition one. Every output received
independent GNU-tar replay and content/ownership/mode/timestamp/xattr/link/config/
history/descriptor/diff-ID checks. Both arms retained the required checkpoints
and edit prefixes. Both pairs passed complete OCI-byte equality, source
preservation, cache preservation and public-output mutation/inode isolation.

The half-second process sampler recorded I/O and `wait4` counters. Allocation
tree walks ran only before and after each build. There was no concurrent
recursive allocation sampler or claimed disk peak. The original limits remained:
16 builds, 300 seconds per build, 30 minutes including acceptance, no retries.
The corrected readiness gate passed before any builder ran; the first Pod's
[readiness-only failure](copy-checkpoint-validation.md#first-pod-attempt-readiness-failure-zero-builds)
remains recorded separately.

## Evidence and cleanup

Collected archive SHA-256:
`06cac437ab6004a2b07c18c3f8605478fe7cc9d144cfeb9910d3caac0a9a7d0b`.
All 150 included files were hash-verified before teardown. Full logs and raw
process snapshots remain under
`.research-private/copy-checkpoint-20261028/pod-5204299-partition-v2/`.

Independent read-only review passed with no required changes. It verified all
150 collected files and 56 sealed payload entries, exact AB/BA completeness,
binary/build provenance, acceptance records and the reported calculations.
It reviewed the frozen oracle and evidence; it did not rerun builds or claim
fresh output execution. All 609 recorded process samples remain archived.

Pod `4q09qlqo1c0vh6` was terminated. Delete returned 204; fresh get returned 404;
complete inventory was empty. Absence was confirmed at 15:07:19 UTC on
2026-10-28, 27 minutes after creation and before the one-hour cap. The cleanup
reminder was removed. Estimated compute plus disk cost is about $0.149 for that
observed lifecycle, not settled billing.

The next release gate is the pinned real Nemotron cold/warm/edit run with
independent final-image acceptance and qualified final counters. This synthetic
improvement does not prove the earlier one-hour final-export timeout is fixed,
nor can it be multiplied with results from a different host or prior candidate.
