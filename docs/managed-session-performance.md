# Managed checkpoint reuse on a Pod

The subsequent [startup diagnostic validation](stable-candidate-validation.md)
passed eight exact-candidate Pod builds. No qualifying startup stall was captured;
that single-candidate run does not replace the balanced comparison below.

Cold builds used **33.6% less elapsed time** (1.51× speed ratio) in this
balanced, same-Pod comparison. Both execution orders improved. Application-edit
wall time was mixed: one candidate run took 53 seconds, so its two-run median
was **32.0% worse**. No general application-edit speedup is claimed. Warm and
no-cache timings were close, with only two observations per arm.

All 16 builds and both complete paired acceptance checks passed. The raw build
measurements, CPU/I/O counters, provenance, validation receipt and artifact hashes
are in [v02-managed-session-pod.json](v02-managed-session-pod.json).

## Measurements

| Case | Baseline seconds: median (two runs) | Candidate seconds: median (two runs) | Median elapsed change | CPU seconds: baseline → candidate |
| --- | ---: | ---: | ---: | ---: |
| Cold | 48.854 (47.965, 49.744) | 32.430 (31.203, 33.657) | -33.6% | 46.974 → 30.526 |
| Warm | 4.637 (4.311, 4.963) | 4.814 (4.291, 5.336) | +3.8% | 3.891 → 3.857 |
| Application edit | 29.676 (28.916, 30.437) | 39.185 (25.333, 53.037) | +32.0% | 28.147 → 24.747 |
| No cache | 5.282 (5.254, 5.310) | 5.058 (4.828, 5.288) | -4.3% | 3.833 → 3.785 |

The slow edit run is retained without trimming, subtraction or retry. Its
half-second process snapshots from 0.505 through 26.228 seconds show kernel `D`
state, zero recorded CPU ticks, and unchanged read/write character counters.
The next snapshot at 26.732 seconds shows CPU progress. Its stage log reports
26.480 seconds, versus 53.037 seconds for the complete process; total CPU was
24.696 seconds. This identifies a blocked startup interval, but the recorded
data does not identify the syscall or prove whether the cause was filesystem,
host, or application behavior. No corrected-time result replaces the observation.

Application-edit CPU fell from a 28.147-second median to 24.747 seconds, while
its wall-time result remains unfavorable. The next performance investigation
should capture the blocked startup syscall/wait channel and then repeat the
real large-image workload. Cold checkpoint publication is improved; overall
large-image build speed is not fully established.


## What changed

The managed Linux CLI retains bounded verification evidence for layer payloads
through one stage. Later instruction publications reuse that evidence only for
the same continuously held source/cache objects. New physical copies retain full
first-admission verification, and final stage publication still hashes all data.
Every successful instruction remains durably cached before the next instruction.
No flag or cache-format migration is required. Layered remains the default.

This relies on the existing cooperative stable-store/trusted-RUN contract. It is
not protection against hostile asynchronous writers. Public callback-based APIs,
cache lookups, export inventories and public-output verification remain
conservative. See [the implementation contract](publication-session-implementation.md).

## Method and provenance

One temporary Secure `cpu3g` Pod in EU-RO-1 supplied eight assigned logical CPUs
on an AMD EPYC 9655P host, a 32,000,000,000-byte cgroup memory ceiling, and an
80 GB requested ephemeral disk. Build storage was overlay; a private write/fsync
probe showed backing I/O on local devices, with XFS host container mounts.
Initial available space was 85,782,847,488 bytes. There was no network volume,
registry download, model download or GPU workload.

The fixture contained a deterministic incompressible 1,024 MiB dependency,
2,048 small files and metadata cases, with three COPY/RUN pairs. Both binaries
used ordinary managed, layered builds. Only the no-cache control added
`--no-cache`. Each case ran baseline then candidate in repetition zero, and
candidate then baseline in repetition one. There were 16 builds, with no retries.
Cold means an empty managed cache, not a flushed OS page cache.

Both binaries were optimized static Linux builds made with Rust 1.90, identical
dependencies and command:

```sh
RUSTFLAGS=-Ctarget-feature=+crt-static cargo build --offline --locked --release \
  --target x86_64-unknown-linux-gnu --bin rpweld
```

| Artifact | Frozen revision | SHA-256 |
| --- | --- | --- |
| Baseline | `ca99a363940e6c137bcef4068d71a380ab54a07e` | `2cd6b2152d20d6fd36333b18b4d2e9755f617ae7c11c46330696358ded32b8c8` |
| Candidate | `b7e7126cb7208a1c5a2ece57efda85c2c3e70b0b` | `0b0a12eebaad44e8b40ca5f4558fe4e6be2b86c2a6efe72102e88cd493160d96` |

Subsequent commits `577cf24` and `30a318d` correct test fixtures only; production
source is unchanged from the measured candidate. Build receipts record all
source hashes, toolchain details and identical private helper hashes.

Build wall/CPU timings exclude the independent acceptance checks. A half-second
`/proc` sampler and `wait4` collect process metrics. Recursive allocation walks
run only before and after a build; there is no concurrent allocation-tree sampler
or sampled disk-peak claim. The whole experiment, including acceptance, has a
30-minute cutoff; individual builds have a 300-second cutoff.

## Correctness and limits

Independent GNU-tar replay checked file contents, ownership, modes, timestamps,
xattrs, hardlinks, symlinks, configuration, history, descriptors and diff IDs.
Both arms retained six incremental checkpoints and the application-edit prefix.
All four cases in each repetition produced byte-identical paired OCI layouts.
Source immutability, cache preservation, independent public inodes and deliberate
output mutation against peers and both caches passed. No assertion was relaxed.


Before this benchmark, integrated Linux validation recorded 659 standard tests
passing and 62 ignored. Selected ignored/runtime suites were then run explicitly:
seven mount tests, three worker tests, four managed-control tests, nine resource
tests and all 17 instruction-cache tests. These counts overlap the standard
suite and are not an additional distinct-test total. Formatting, strict Linux
Clippy, rustdoc, and Windows GNU compilation/Clippy passed; Windows runtime was
not tested. Independent storage/control reviews and actual cross-RUN descriptor
checks passed. Legacy callback corruption/retry assertions remain unchanged.

The initial parallel cleanup run exposed an inherited-lock fixture race. Its
existing bounded store-busy retry now also covers cancellation; three parallel
reruns and three traced paired reruns passed. Two ignored runtime fixtures were
corrected separately: the killed-builder case now lets its shortened workload
finish naturally under the existing reaping deadline, and secret rejection
assertions match the implemented target checks. All tag, cached-prefix, output,
cleanup and protected-RUN assertions remain. Exact receipts retain the initial
failures and subsequent passes.

Two samples per case on one host are descriptive evidence, not a broad hardware
or workload guarantee. This is a synthetic offline checkpoint-heavy build, not
the full Nemotron image, a network package installation, or inference. It does
not establish a linear speedup for 100 GB images. Full-tree scans, inherited-layer
verification and final verification still cost time. The remaining gap between
cached cold builds and no-cache builds identifies further checkpoint overhead.

## Evidence and cleanup

The sealed execution bundle SHA-256 was
`845bfab27efeee9c2af65101e1dc78f383ba4db1b56f835d72b4f05215a5c4c9`.
All 150 collected evidence files were verified against their SHA-256 manifest.
The 1,976,909-byte archive SHA-256 is
`58001b0ce0700d97af649884b5e64f6ebe310ce259467015d187decd3216ad77`.
The complete raw process samples remain in that retained archive; this report's
JSON includes the edit-outlier sample analysis separately.

Pod `z28vahe6l50bgb` was created on 2026-10-27 at 20:06:37 UTC and verified absent
at 20:28:20 UTC. Deletion returned 204, a fresh get returned 404, and complete
inventory was empty. The cleanup reminder was removed. Estimated compute plus
disk cost was **$0.120**, not a settled bill: $0.32/hour compute plus 80 GB at
[$0.10/GB/month](https://docs.runpod.io/pods/pricing), prorated over 720 hours.

The benchmark finished at 20:27:03 UTC, before its 20:39:39 cutoff. An independent
local controller maintained the remote 90-second liveness lease; no session
restart or retry occurred. Two separate read-only progress-log SSH requests
timed out; the benchmark controller continued successfully. Those requests did
not pulse, restart or change the workload.
