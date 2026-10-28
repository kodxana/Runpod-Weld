# Linux candidate validation, 2026-10-28

Candidate `586097166166fb4849e3102be802d0d0cc585284` passed the Linux
release workflow and eight ordinary managed builds on a temporary Runpod Pod.
The portable archive, Debian package and corresponding sources are verified
workflow artifacts. **No new public release or version tag was published.**
The packages still identify themselves as version `0.1.0`; these artifacts must
not replace the existing release under that version.

Exact measurements, artifact hashes and validation receipts are summarized in
[stable-candidate-5860971.json](stable-candidate-5860971.json).

## GitHub release pipeline

[CI](https://github.com/kodxana/Runpod-Weld/actions/runs/40666484293) and the
[artifact-only Linux release run](https://github.com/kodxana/Runpod-Weld/actions/runs/40669087130)
both passed at the frozen commit. The release workflow completed:

- All-targets Rust tests: 671 passing target results and 62 ignored. Nested
  filtered subprocess results are excluded from this count. Selected real
  managed-worker, mount and output tests then passed all 14 cases; these overlap
  the standard suite and are not an additional distinct-test total.
- Formatting, strict all-target/all-feature Clippy and documentation checks.
- Static Linux amd64 build, portable archive and Debian packaging.
- Nine package assertion tests and ten fixture builds across the two installed
  package formats, covering gzip, managed cache, secrets and package-cache mounts.
- Offline installation with networking disabled, nonroot execution, both bundled
  registry preflight suites, and a separate authenticated TLS push/pull roundtrip.
- Exact corresponding-source collection and final checksum verification.

The downloaded Actions ZIP matched its recorded SHA-256. All four enclosed
artifact checksums were independently verified locally. `build-info.json`
identifies the exact commit, Rust 1.90, static GNU target and bundled Skopeo 1.13.3.
The `publish` job was skipped by the existing tag-push-only condition.

| Artifact | SHA-256 |
| --- | --- |
| Actions ZIP | `2ab9885079eaebaaf8400b9f0fc3e7d162a8932e7db89d0b1375c377c8f415bf` |
| Portable archive | `5e35862cc4f3ea5d7ac1556a4c331198e5f3aefdeaca89ceb8aff76ec64f8d81` |
| Debian package | `0768c315d199587245d043c97355afd826bfcee9976cd91dbe0811ea62adaf19` |
| Corresponding sources | `99cb2859eb2005841fe37de291fb0b5ce02bd074f2ffd577caf7e1e5748b8d32` |

## Pod acceptance and startup diagnostics

A fresh Secure `cpu3g` Pod supplied 8 vCPU, a 32 GB memory ceiling and 80 GB
ephemeral storage in EU-RO-1. Builds used overlay storage; XFS host-container
mounts and a synced write observed on local block devices supported the backing
check. No network volume, registry download or model download was involved.

The unchanged fixture contains a deterministic incompressible 1 GiB dependency,
2,048 small files, metadata cases and three COPY/RUN pairs. Each case ran twice,
serially, with normal managed layered defaults. Only the no-cache control added
`--no-cache`. Cold means an empty managed cache, not a flushed OS page cache.

| Case | First run (s) | Second run (s) | Median (s) |
| --- | ---: | ---: | ---: |
| Cold | 30.054 | 30.371 | 30.212 |
| Warm | 4.152 | 3.941 | 4.046 |
| Application edit | 25.235 | 25.052 | 25.144 |
| No cache | 4.019 | 3.940 | 3.979 |

Independent replay checked contents, metadata, configuration and layer identities.
Source immutability, cached-prefix preservation, independent public inodes, two
deliberate output-mutation probes and OCI byte equality across repetitions all
passed. Every build retained its final root process counters. Acceptance work is
excluded from the build times; no recursive allocation sampler ran during builds.

All 12 observer tests passed on the Pod. A separate harmless sleeping-child probe
could read the redacted wait channel (`hrtimer_nanosleep`) and syscall number.
It was not a reproduced stall. **No qualifying unchanged D-state stall was
captured in the eight builds.** The earlier 26-second startup delay remains
unexplained; these results neither establish its cause nor claim it is fixed.

The Pod binary SHA-256 was
`5bd0d35c8b5a03c4af951d258b633cc9fba58c5269ae6e121debe0d6d5e037d9`.
The CI-packaged binary was
`e095208dca1146c0d60f5f03b97e75369695601fe1373d48691077c67a0d1c8c`.
Both are static builds of the same source revision; they are separate build
artifacts, not a bit-for-bit reproducibility result.

The experiment passed in 346.129 seconds. All 115 collected evidence files
matched their manifest; archive SHA-256:
`671ea00c1967fb1bf7ce57e1668ff439587f4fc9a64972e07e6ee63cd559dc56`.
The retained local evidence is under
`.research-private/stable-20261028/pod-5860971/verified-evidence`.
Pod `g2tsqlfvc4nqvp` was deleted at approximately 10:25:26 UTC, well before its
10:56:31 deadline. Delete returned 204, fresh get returned 404, complete inventory
was empty, and the cleanup reminder was removed.

## Release decision

This clears the tested Linux packaging and Pod candidate gates. It does not
establish full Docker compatibility or performance for the original large model
image. There was no baseline arm in this run; the earlier balanced comparison
remains in [managed-session-performance.md](managed-session-performance.md).

Before a new public release, select the new version, update its release notes,
and rebuild the final tagged source through the same gates. A real large-model
build remains the important performance follow-up; the synthetic 1 GiB fixture
does not justify a 100 GB throughput claim. No additional Rust implementation
change or speedup is claimed by this validation report.
