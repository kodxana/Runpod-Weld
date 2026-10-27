# v0.2 checkpoint measurements on Runpod

The frozen candidate `503b7419b8cfd6599f6c80a3825717f687d31a84` reduces
checkpoint creation time and storage compared with published v0.1.0
`63b716e1027ceba48bf9c887567419057b1bfd73`. It does not eliminate checkpoint
overhead or establish full Nemotron/Docker performance parity.

The implementation appends instruction deltas against the preceding verified
checkpoint, shares already-owned immutable prefix blobs internally, and applies
only the next delta on instruction hits. Public outputs retain independent blob
inodes. Last-consumer root handoff also works with cached parents. Optional replay
receipt exhaustion falls back to bounded verified baseline capture, preserving the
selected external image reference; corruption and cancellation remain errors.

## Environment and method

Tests ran on 2026-10-27 on one temporary Secure Runpod CPU Pod in EU-CZ-1:
`cpu3g`, eight assigned CPUs on an AMD EPYC 9654 host, 32,000,000,000-byte cgroup
memory limit, and 80 GiB observed container-disk capacity. The filesystem was
overlay, with host container-file mounts on XFS. No FUSE/network volume was used.
The recorded CPU affinity contained eight CPUs; `cpu.max` was unlimited within
that affinity. This is not a dedicated-host claim.

Both binaries were optimized static Linux amd64 release-mode builds. The candidate
used the same private Skopeo runtime bundle as v0.1.0, although these offline builds did not
use a registry. Binary SHA-256 values:

- v0.1.0: `24c09bd3b805a525d447f5c568991dc50da417fdd299445b52c981087a273686`
- Candidate: `ecda01b49ba611f8f49a7e1bcc62e1bde2ad31e9f992af0141f410c774c1470f`

The [committed fixture](../tests/fixtures/v02-performance/README.md) uses an
incompressible dependency file, 2,048 small 1 KiB files, static BusyBox, and three
COPY/RUN pairs. It exercises content, links, ownership, permissions, xattrs,
nanosecond timestamps, configuration and cache invalidation. Source timestamps
are fixed, with atime greater than mtime to avoid unrelated relatime changes.
It is single-stage: these timings do not isolate cached-parent root handoff.

Runs alternate baseline/candidate order within each case, on the same Pod, with
separate stores for each variant and repetition. The four cases are an empty
store, an unchanged rebuild, an application-only edit, and `--no-cache` against
the populated store. Builds use ordinary managed `-t` behavior and automatic
limits, default layered/raw output, explicit fresh work/output paths, and a local
base. No private optimization flags or host credentials are inherited.

Cold means an empty managed store, **not** a cold OS page cache. Fixture creation
and independent checks touch data between builds; the recorded process
`read_bytes` values show page-cache reuse. Build time includes Weld and its waited
children, excluding independent OCI replay/acceptance afterward. A concurrent
no-atime metadata sampler records allocation every 0.5 seconds. Its scan time is
retained in the data and is not subtracted from timings; observation can affect
results, especially short warm/no-cache runs.

## Measured results

Medians from four balanced pairs per case, using the 256 MiB dependency:

| Case | v0.1.0 | Candidate | Elapsed change |
| --- | ---: | ---: | ---: |
| Cold | 26.77 s | 16.69 s | -37.6% |
| Unchanged warm | 1.68 s | 1.83 s | +8.6% |
| Application edit | 17.19 s | 10.55 s | -38.6% |
| No-cache control | 2.35 s | 2.15 s | -8.3% |

Medians from two balanced pairs per case, using the 1 GiB dependency:

| Case | v0.1.0 | Candidate | Elapsed change |
| --- | ---: | ---: | ---: |
| Cold | 95.14 s | 59.55 s | -37.4% |
| Unchanged warm | 5.39 s | 5.71 s | +6.0% |
| Application edit | 59.36 s | 37.73 s | -36.4% |
| No-cache control | 6.19 s | 6.32 s | +2.1% |

All **48 builds** passed their independent acceptance checks. These sample counts
do not establish a confidence interval or a universal speedup. In particular,
the warm differences are small and include sampler overhead. Neither size shows
a warm-build speedup, and no-cache performance does not consistently improve.

The application edit changed 273,701,888 bytes of referenced layers with v0.1.0,
versus **17,408 bytes (17 KiB)** with the candidate. The exact unchanged dependency
prefix remains in the output. At 1 GiB, the corresponding comparison is
1,079,008,256 bytes versus the same 17,408 bytes. These are new descriptor bytes
relative to the preceding output, **not measured registry upload traffic**. No-cache output still
uses one cumulative delta per stage, so switching from incremental cached output
to no-cache can introduce a large new layer even when delivered files match.

For the cold 256 MiB case, median process `write_bytes` fell from 7,690,756,096 to
1,656,672,256 bytes (78.5%). Median retained store allocation fell from
1,644,679,168 to 276,205,568 bytes. At 1 GiB, cold process writes fell from
30,239,424,512 to 6,488,545,280 bytes; retained store allocation fell from
6,476,517,376 to 1,081,511,936 bytes. The process I/O counter is not a measure of
physical device writes. Allocation uses `st_blocks * 512`, deduplicated by device
and inode; it does not deduplicate physical reflink extents. Sampled peaks are
lower bounds. Warm/edit/no-cache allocation scopes also include artifacts retained
from previous cases, so their totals are not the isolated cost of that build.

Raw repeated values, I/O counters, allocation scopes, rounded phase timings,
binary/script hashes and evidence-archive hashes are in
[v02-pod-performance.json](v02-pod-performance.json).

## What still costs time

On the candidate's 256 MiB cold build, median logged totals were approximately
6.98 seconds publishing instruction cache entries, 4.84 seconds exporting
checkpoints, and 1.62 seconds verifying checkpoint deltas. Six small instructions
still incur substantial filesystem inventory and verification work even when
their new layers contain little data. The no-cache control remains much faster
because it skips instruction checkpoint publication; its RUN workload is trivial
and does not model expensive package installation or compilation.

At 1 GiB, those candidate cold totals grow to 26.94 seconds publishing instruction
cache entries, 16.61 seconds exporting checkpoints and 6.23 seconds verifying
checkpoint deltas. Reducing serialized bytes has not removed repeated reads of
the unchanged dependency.

A subsequent attempt to reuse blob verification within one locked publication
was rejected and rolled back. Inode and size checks did not detect same-size
content changes at the required boundaries: some probes accepted corruption,
and others left newly owned corrupt blobs that prevented a healthy retry.
The original verification remains, with regression tests for these cases.
Test instrumentation counts eight full payload hash reads for a newly ingested
unique layer and six for a reused layer during publication. Those are baseline
counts, not a retained reduction or a new Pod timing result. Post-ownership
corruption can still poison retries under the existing stable-store contract.

The next investigation is reducing repeated full-tree inventories where COPY
provides an exact changed-path set. Any change must preserve verification on
consumption, inode ownership, cache corruption detection, metadata and
cancellation behavior. The benchmark does not authorize bypassing those checks
or assuming arbitrary RUN commands have known writes.

One allocation-only follow-up borrows anchor paths and symlink targets in the
temporary inventory grouping map instead of cloning them. The owned inventory,
logical budget charges, filesystem reads, hashes and cancellation checks remain
unchanged. This removes temporary allocations but has no measured Pod timing
benefit yet; it is not included in the speedups reported above.

## Scope

Every completed comparison verifies descriptor hashes and diff IDs, exact
filesystem/configuration parity, timestamps without a root exception, expected
RUN execution/cache hits, incremental prefix retention, and independent public
output inodes. Deliberately mutating a public output must leave the cache and peer
outputs unchanged. Evidence archives retain the commands, measurements, manifests,
cache fingerprints, replay snapshots and logs.

This workload does not include downloads, pip/npm/apt network installs, model
loading, GPU work, a Docker timing comparison or a full cached Nemotron build.
Earlier full Nemotron results in [performance.md](performance.md) concern earlier
changes and cannot be assigned this candidate's synthetic speedup.

## Compression and RUN mounts on the same Pod

After the timed comparisons completed, the standalone compression helper ran
three iterations for each mode/input combination, followed by five real RUN-mount
build cases. They did not overlap the main benchmark.

The helper's 64 MiB text tar shrank from 67,110,400 to 500,340 bytes. Median
encode-plus-sync time was 71.20 ms raw versus 59.73 ms gzip. Incompressible input
grew to 67,166,984 bytes, and encoding took 443.36 ms versus 71.59 ms, about
**6.2 times longer**. Verification was also slower for incompressible gzip:
288.83 ms versus 94.87 ms. This measures the helper plus separate verification,
not complete production publication or a registry push. Gzip remains opt-in.
See [the encoder contract and measurements](export-compression.md).

All five mount cases passed: nonroot secret permissions/mutation and output
suppression, deliberate secret failure restoration, managed package-cache
creation, deliberate cache failure preserving previous contents/modes/owners,
and nonroot reuse with `--no-cache` preserving setgid/sticky modes. The three
successful outputs passed every-layer gzip descriptor/diff-ID and temporary-path
checks. Inspection of 496 entries and 358,664,529 bytes across work, output, store,
cache and logs found no synthetic secret bytes or source paths. These are
synthetic offline tests, not real package-download or crash-recovery evidence.
The [documented mount restrictions](run-mounts.md) still apply.

## Validation and teardown

The broader combined source snapshot at `7cd367f` passed 620 standard tests,
with 59 ignored, plus explicit mount/resource/gzip runtime suites, Linux Clippy,
formatting and documentation checks. The final candidate adds a Linux-only cfg
guard and the selected-reference fallback fix/regression; 23 instruction-cache
tests, an independent 60-case distinct-tag probe, scoped Linux Clippy, formatting
and all-target Windows cross-Clippy passed afterward. This reuses the recorded
broad-suite evidence; it does not claim a second full-suite run at `503b741` or
native Windows runtime validation.

All 335 collected benchmark/supplemental evidence files were hash-verified
locally. The temporary Pod was deleted after collection: deletion returned 204,
fresh get returned 404, and a fresh complete inventory was empty at
2026-10-27 14:00:13 UTC. No persistent volume was created. The observed lifecycle
was approximately 38 minutes 43 seconds; compute plus 80 GB disk is estimated at
about $0.21 using the returned $0.32/hour compute rate and a 730-hour monthly
storage divisor. This is an estimate, not a settled billing amount.

The code is a tested release candidate, not a published v0.2 release.
