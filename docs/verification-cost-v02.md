# OCI verification costs on a Pod

The completed diagnostic attributes most cold-build time to repeated SHA-256
work. For a 1 GiB payload plus 2,048 small files, the instrumented cold build took
60.09 seconds. OCI verification consumed 47.98 seconds, including 40.01 seconds
hashing 71.36 GB of data. This is measured attribution, not a claimed speedup.

All eight builds passed independent acceptance. Production code was unchanged;
the diagnostic only added component accounting. No hash-skipping optimization
is enabled. Raw measurements, provenance and hashes are in
[v02-verification-cost.json](v02-verification-cost.json).

## Method

The release comparator was `e41a8ea`, SHA-256
`8ec37fb9b072529c99f05ab0a8096c8b98193d86227d0d36f11187831abd176f`.
The diagnostic was built from `259100f`, whose production source and dependencies
match `e41a8ea`, with a separate diagnostic patch and build ID. Its SHA-256 is
`c3c1c225b752c980ead05f312ad2b9d33f69352ccc756e5adfb92b17f47e2528`.
Both are optimized static Rust 1.90 Linux binaries.

One temporary Secure `cpu3g` Pod in EU-CZ-1 supplied eight assigned CPUs on an
AMD EPYC 9654 host, a 32,000,000,000-byte cgroup memory ceiling and 80 GB requested
ephemeral disk. Build storage was overlay with local backing I/O verified by a
private write/fsync probe. Host container mounts were XFS. No network volume,
registry downloads, models or GPU were involved.

The fixture used a deterministic incompressible 1,024 MiB dependency file,
2,048 small files and metadata cases. Each case ran release then diagnostic:
cold, warm, app-edit, and populated-store `--no-cache`. The complete run,
including generation and oracle checks, had a 12-minute limit. Each build was
limited to 240 seconds. It completed within those limits.

Build timing excludes independent acceptance. Both arms retained a five-second
allocation-tree sampler and half-second process sampler. Cold means an empty
managed cache, not a flushed OS page cache. Fixed order, one pair per case,
sampling and instrumentation prevent using these rows as a speed comparison.

## Measurements

| Case | Release build seconds | Diagnostic build seconds | OCI bytes hashed (decimal GB) | OCI stream seconds | SHA update seconds | Read seconds | Write seconds | Callback seconds |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Cold | 58.921 | 60.094 | 71.361 | 47.984 | 40.013 | 7.196 | 0.354 | 0.277 |
| Warm | 5.404 | 5.456 | 4.329 | 2.748 | 2.394 | 0.329 | 0.000 | 0.016 |
| App edit | 36.524 | 36.806 | 43.251 | 27.856 | 23.923 | 3.261 | 0.426 | 0.161 |
| No cache | 5.883 | 6.069 | 2.169 | 1.551 | 1.202 | 0.335 | 0.0003 | 0.010 |

These counters cover `oci::verify_stream`, not every hash, copy or read in the
builder. SHA finalization was below 0.2 milliseconds per case. Stream residual
includes loop/accounting work, digest formatting and comparisons. Component
elapsed times include scheduling and timer overhead; callbacks include their
synchronous nested work. Failed `write_all` byte accounting would be partial,
but every measured stream here completed successfully.

Seven alternating empty-probe calibration pairs measured 48.08–48.30 ns of
additional wall time per timed operation. That does not justify subtracting
an overhead estimate from application measurements. The unchanged release
control helps expose instrumentation effects without claiming to isolate them.

The pinned `sha2` 0.10.9 implementation already selects SHA-NI: the diagnostic
confirmed the required SHA/SSE2/SSSE3/SSE4.1 CPU predicates. Source dispatch and
release disassembly agree. This is not an instruction-sampling trace, but it
rules out the hypothesis that the ordinary release simply omitted its hardware
SHA backend on this Pod.

## Interpretation and correctness

Repeated checkpoint processing is the main target. The cold run hashes about
71 GB through this one verifier while the no-cache control hashes about 2 GB.
Making progress polling cheaper or adding compression does not address that
multiplication. The result does not establish a safe way to remove checks.

Independent replay checked filesystem contents and metadata, configuration,
descriptors/diff IDs, inherited prefixes, exact paired OCI bytes, source
immutability, and public/cache inode isolation. Deliberate public-output mutation
also passed. The diagnostic's local differential tests covered 252 combinations
of reads, callbacks, errors and output, preserving original operation order.

The [managed publication-session proposal](checkpoint-verification-design.md)
investigates reusing evidence for continuously owned payloads while still
durably committing each completed instruction. Its complete write boundary
remains an unresolved prerequisite. Existing arbitrary-callback APIs, corruption
and healthy-retry tests, ownership checks, durability and public inode isolation
remain requirements. A publication-wide inode/size memo is not an integrity
proof; the earlier failed hash-skipping implementation remains rolled back.

## Evidence and cleanup

All 93 collected files passed SHA-256 verification. Archive SHA-256:
`f1e561aaf2a1a64340910f09c6bcb011f27d611afe7d0f1200b6aa3d78e6fb53`.

Pod `s3a7vzptky8jab` was created at 17:46:39 UTC on 2026-10-27 and verified absent
at 17:58:47 UTC: deletion returned 204, get returned 404, and complete inventory
was empty. The backup cleanup reminder was removed. Estimated compute plus disk
cost was $0.067, not settled billing.

The same Pod first received a balanced-comparison preparation, but Windows SSH
failed before launching its runner. No xattr build executed there; that failure
and untouched session evidence were retained. This diagnostic ran separately
afterward. It is not a replacement for the balanced xattr comparison.
