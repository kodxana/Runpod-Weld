# COPY checkpoint candidate validation

Candidate: `5204299e1340a2ca8b5401ad8ec751843d96cfa4`, 2026-10-28.
Comparison baseline: `a3ce37f6a951a388a1c81d19ae93597fbd74914e`.

The [managed COPY change](copy-checkpoint-reuse.md) passed correctness checks and
independent review. The [16-build Pod comparison](copy-checkpoint-performance.md)
also passed: cold time fell 32.4%, edit time 8.5%, with warm/no-cache controls
essentially unchanged. **Real Nemotron acceptance remains pending.**
This is candidate validation, not a stable-release or general large-image speed claim.
The [implementation gaps](implementation-gaps.md) remain the release checklist.

## Integrated correctness

Executed from a frozen Git archive under WSL Ubuntu root with Rust 1.90.0,
offline/locked dependencies, default debug settings, native `/var/tmp` source,
target and temporary storage. All 253 archived source files were unchanged after
the checks. Test counts below overlap; they must not be added as unique coverage.

| Check | Result |
| --- | --- |
| Standard `cargo test --all-targets -- --test-threads=1` | 689 passed, 0 failed, 62 ignored |
| Explicit managed-control, RUN-mount and worker suites, including ignored tests | 14 passed |
| Explicit resource-engine suite, including ignored tests | 9 passed |
| Instruction-cache CLI suite with supplied local base fixture | 17 passed |
| Raw/gzip CLI suite with supplied local base fixture | 2 passed |
| Rustfmt, all-target/all-feature Clippy with `-D warnings`, rustdoc | Passed |

Exact commands and source-hash receipt are retained in
`/var/tmp/weld-copy-final.01kROERK/`; the parent invocation is
`.research-private/copy-checkpoint-20261028/final-qa.sh`.
The ignored tests outside these explicitly enabled suites were not claimed as run.

An intermediate default-debug instruction-cache executable exceeded the existing
64 MiB builder identity cap. Commit `5204299e` shares COPY's callback dispatch
without changing callbacks, evidence eligibility, limits or assertions. The
corrected executable measured 66,137,992 bytes, below 67,108,864, and all 23 engine
tests passed before the complete integrated run above.

## Independent review

The inherited-evidence review passed on `187536f`, including all 31 unchanged
shared-cache regressions and six additional corruption/durability probes. The
COPY integration review passed with the dispatch correction in `5204299e`.
It checked raw/gzip equality and replay, replacement and inode recycling,
hardlinks/symlinks/raw names, metadata, cancellation and partial-write retry,
descriptor fallback, cache replay, RUN/WORKDIR invalidation and public callbacks.

In the review's small replacement fixture, inventory payload reads fell from
131,080 bytes to 8, and inherited-layer verification streams from two to zero.
New deltas remained verified. These are mechanism checks, not elapsed-time
benchmarks. Some review-only probes used disposable instrumentation or stripped
binaries; default-debug acceptance comes from the integrated run above.

Review evidence remains in `/var/tmp/rpweld-review-187536f-9Zdbxnqx/` and
`/var/tmp/copy-review-8b08e7d-VUJaaYtl/`.

## Frozen comparison artifacts

Both binaries were built with the same Rust 1.90 toolchain and command:

```sh
RUSTFLAGS=-Ctarget-feature=+crt-static \
  cargo build --offline --locked --release \
  --target x86_64-unknown-linux-gnu --bin rpweld
```

Each embeds its exact revision. Static ELF inspection, full source manifests,
original build receipts, all 15 bundled runtime helpers and BusyBox were verified.

| Artifact | SHA-256 |
| --- | --- |
| Baseline binary | `62387416347edb39b1adfe607be4a8efdb66c152adc7ea6be272427c69a72717` |
| Candidate binary | `9b28f802a9ab87a9f5075565f5a5bd2dc6804273457506f2b8c54bdaef73bdd6` |
| First comparison bundle | `9c60acd4028690780d072bfd97be1b95c55e2f1ab962964ed3c7a44c48a7d3ac` |
| Corrected comparison bundle | `e5559ca3a9d25ed5941f571cb36cdb912bcd9c9a6194c72504cbf35d114ffefd` |

## First Pod attempt: readiness failure, zero builds

Pod `zvqu06covfckro` was created for the isolated comparison, then deleted after
the readiness gate rejected its storage topology. The helper treated partition
`md0p1` as a whole RAID device and attempted to read a nonexistent `slaves`
directory. Collected sysfs data identifies partition 1 of `md0`, whose six members
are PCI-backed NVMe devices. That evidence explains the helper failure; it does
not waive the required storage, counter or output-acceptance checks.

No builder, controller, benchmark or image oracle ran. The original bundle and
failure evidence are retained unchanged. Delete returned 204, a fresh get returned
404, and the complete Pod inventory was empty; the cleanup reminder was removed.
Evidence: `.research-private/copy-checkpoint-20261028/pod-5204299/`.

## Corrected readiness gate

The private readiness helper now resolves a partition to its exact parent device
before checking RAID members. It checks every member, rejects mapping errors and
cycles, and bounds traversal to 16 levels and 256 visits. Other runtime gates,
binary identities, fixture/oracle assertions and benchmark deadlines are unchanged.
Independent review passed, including 53 tests on Windows (six skipped), 57 under
WSL root (two skipped), and three additional probes. All 43 original tests and
332 protected files remained intact.

The newly sealed payload uses the same frozen binaries above. On fresh Pod
`4q09qlqo1c0vh6`, actual readiness passed before any builder: live and exited-child
I/O counters, `wait4` and reaping; local backing through the XFS RAID partition
and synced-write accounting; 85,780,533,248 available bytes; and more than 100,000
free inodes. This qualifies that Pod for the comparison, not arbitrary Pod
storage or full-workload capacity.

The unchanged real Nemotron timeout and missing cold/warm/edit final-image
acceptance remain unresolved.

The corrected trial completed all 16 builds and both full paired acceptance
checks. All 150 collected evidence files were hash-verified. The Pod was deleted;
fresh get returned 404 and complete inventory was empty. Exact timings, method,
artifact hashes and cleanup are in the [comparison report](copy-checkpoint-performance.md).
