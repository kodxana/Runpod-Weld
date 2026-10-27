# COPY xattr scratch reuse: completed Pod comparison

All four cold builds and both independent pair checks passed on one temporary
Pod. Mean elapsed time was **94.34 seconds before and 92.31 seconds after**
the buffer-reuse change: **2.15% less elapsed time in this experiment**.
Both paired comparisons favored the candidate, by 3.06% and 1.22%.
This is a small observed difference, below the proposed 5% threshold for a
meaningful win, and is not a general speed guarantee or a large-image fix.

Raw results, provenance, environment, controller evidence hashes and teardown
are retained in [v02-xattr-scratch-balanced.json](v02-xattr-scratch-balanced.json).
The [earlier incomplete trial](xattr-scratch-performance.md) remains unchanged
apart from a link to this result. Its samples are not pooled with this trial.

## Scope and method

Baseline `d6fe610d4f38522ca0192fd39b3f531650c4ecbe` and its direct child
`e41a8ea0df588fc3f2d58ccdf1e5c5509d943516` differ only in `src/context.rs`.
Both are optimized static Rust 1.90 Linux binaries. The candidate reuses
operation-owned xattr name/value scratch while retaining every filesystem
observation, callback, budget, fingerprint and verification boundary. Returned
attribute values remain independently owned. Scratch is bounded to 64 KiB for
names plus another 64 KiB when values are encountered; this is not a process
memory bound.

The Secure `cpu3g` Pod in EU-CZ-1 provided eight assigned CPUs on an AMD EPYC
9654 host, a 32,000,000,000-byte cgroup memory ceiling, and 80 GB requested
ephemeral storage (85,899,345,920 bytes observed filesystem capacity). Build
storage was overlay, with XFS host container mounts. A private write/fsync probe
confirmed local backing I/O. No network volume or GPU was involved.

The fixture contained a 1 MiB dependency payload, 100,000 small 1 KiB files and
metadata cases. Order was baseline/candidate/candidate/baseline. Each build used
a fresh managed store; the OS page cache was not flushed. The allocation-tree
sampler was disabled during timing, while leader process observations ran every
0.5 seconds. Build wall time includes subprocess startup and exit but excludes
the independent oracle, pair checks and retained-tree accounting.

The unchanged sealed payload enforced 300 seconds per build, 35 minutes for the
experiment, zero retries and a 90-second supervision lease. The new local
controller launched it once and renewed the lease independently every 20 seconds.
It recorded 89 observations, with a maximum gap of 21.15 seconds. The supervisor
completed at 18:30:59 UTC and the controller reported PASS at 18:31:02, before
their original deadlines. No assertion or timeout was waived.

## Measurements

| Order | Executable | Build seconds | User CPU seconds | System CPU seconds | Reported max RSS (KiB) |
|---|---|---:|---:|---:|---:|
| 1 | Baseline | 95.384329 | 24.435842 | 70.745060 | 411,256 |
| 2 | Candidate | 92.465277 | 23.179437 | 68.957304 | 682,760 |
| 3 | Candidate | 92.155341 | 23.525302 | 68.411557 | 770,956 |
| 4 | Baseline | 93.290644 | 24.245586 | 68.684005 | 842,892 |

Mean user CPU was 24.34 versus 23.35 seconds; mean system CPU was 69.71 versus
68.68 seconds. These two pairs do not establish statistical significance or a
portable speedup. There was no allocator-total measurement in this experiment.
The raw `wait4` maximum-RSS values rise with run order; this experiment does not
isolate their cause and establishes neither a process-memory reduction nor an
attributable regression. Raw process samples are preserved for investigation.

Independent acceptance took approximately 217-228 seconds per output; pair
checks took a further 79-82 seconds each. Those costs are outside build timing.
The acceptance workload's per-entry tar processing explains why collecting four
roughly 93-second build measurements required a much longer experiment.

Both pairs passed exact OCI-byte equality, filesystem/configuration/metadata
replay, descriptor and diff-ID checks, source immutability, and public/cache
inode isolation. Deliberately mutating public outputs preserved cache and peer
outputs. All four builders exited zero, and all descendants were reaped under
the existing harness checks.

## Interpretation and next work

Buffer reuse is a bounded allocation improvement with a modest observed elapsed
benefit here. It does not reduce syscalls or hashes. The prior independent
correctness review matched 168 xattr syscalls and 253 callbacks byte-for-byte
between revisions and passed mutation/removal, cancellation, reentrancy and
exact-limit tests; see the earlier report for the complete scoped test counts.

The [accepted large-file diagnostic](verification-cost-v02.md) identifies the
more important target: repeatedly hashing checkpoint payloads. The
[managed publication-session design](checkpoint-verification-design.md) describes
the next implementation gate. No cross-instruction verification reuse is enabled.
There is no warm/edit/no-cache timing comparison, full Nemotron build, registry
download, package install, GPU or Docker timing comparison in this experiment.
Different Pods and prior observation settings must not be compared as revisions.

## Provenance, earlier failures and cleanup

The sealed archive was unchanged:
`89e835e3c9e0ee2c3b94d1819ae394e7af5ee9e932e2f88791396f1f1f9fdf5a`.
Baseline binary SHA-256:
`67f5d1232ffa650e45aca8af25aefc8e7bc628e907b5da36eeb3f5c6e9bfa1cf`.
Candidate binary SHA-256:
`8ec37fb9b072529c99f05ab0a8096c8b98193d86227d0d36f11187831abd176f`.

The prior incomplete trial lost its agent-driven supervision lease. A separate
controller attempt then failed before launching any build because Windows
OpenSSH required the public PROGRAMDATA path in its environment. The corrected
controller passed 15 Windows tests and read-only SSH probes before this fresh
session. Neither failed session was restarted; their evidence remains retained.

All 84 collected files passed SHA-256 verification. Evidence archive SHA-256:
`cc5f7a790c2b27d792c2ac2422e32b4d959c34b51b75d81557473840c404da65`.

Pod `69ctung099r8ir` was created at 17:59:10 UTC on 2026-10-27 and verified absent
at 18:32:42 UTC. Deletion returned 204, fresh get returned 404, and a complete
fresh inventory was empty. The cleanup reminder was removed. Observed lifecycle
was 33 minutes 32 seconds, estimated at $0.185 for compute plus disk; this is not
settled billing. No persistent volume was created and no benchmark Pod remains.
