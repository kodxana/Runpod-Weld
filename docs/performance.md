# Large-image performance

Measurements below are from Linux Runpod Pods with native container storage,
optimized Weld binaries, and layered export. They are not Docker parity claims.

## Incremental instruction checkpoints (2026-10-27)

The v0.2 candidate adds incremental instruction layers and extends verified-root
handoff to cached parents. A same-Pod comparison against published v0.1.0 measures
cold, unchanged, application-edit and no-cache builds, with exact independent
filesystem/config/cache checks. See [the new measurements and remaining
bottlenecks](performance-v02.md) and [raw repeated data](v02-pod-performance.json).
The older full Nemotron timings below are historical results for earlier changes;
they are not measurements of this candidate.

## Verified-root reuse (October 2026)

Layered builds retain a verified base-replay receipt instead of replaying the base
again to capture its baseline. Fresh layered checkpoints retain their working
root, verify the emitted delta and base identities, and repair only exporter
symlink-read timestamp effects. Cache hits and flattened checkpoints still replay.

Two reversed-order rounds on an A40 Pod (7.65 observed CPU quota) used the same
1 GiB bulk file, 16,384 small files, symlinks, and four COPY instructions:

| Measurement | Before | After |
| --- | ---: | ---: |
| Cold build mean | 111.713 s | 77.862 s |
| No-cache mean | 18.305 s | 12.114 s |
| Cold sampled process writes | 29.37 GB | 11.05 GB |
| Cold retained work | 14.91 GB | 7.66 GB |

The unchanged Nemotron Dockerfile at commit
`91ee1316e21f624082c90cc07fcbbec1d9499550` also completed on an A40 Pod with
1 TB native storage: **28m50s**, using `--no-cache` and automatic resource limits.
The existing downloaded base was reused; package/model downloads were included.
Independent streaming verification checked all 48 layer digests and diff IDs,
the exact 46-layer base prefix, image configuration, and 117 pinned model files.
GPU inference was not run.

Filesystem preparation, inventories, export and verification still accounted
for 83% of elapsed time. The model-builder stage alone spent 358.920 seconds
exporting and verifying an image consumed only through `COPY --from`.
The run retained 196.65 GiB. A prior completed build retained 266.79 GiB, but
its timing was not instrumented; it is not a controlled speed comparison.

Validation: 568 normal-suite tests passed; seven additional privileged tests and
independent OCI/Docker acceptance passed. Linux and Windows cross-target linting
passed. Native Windows execution and a full cached Nemotron run were not measured.
The tested binary SHA-256 was
`6f68a5fd466d1567e80f3cc4662c21dbd1ebdc69844fa26a35525fb1c741e46a`.

## COPY-only intermediate stages

No-cache builds now retain the owned root of a stage used only by `COPY --from`,
without capturing an export baseline or publishing an unused intermediate image.
The final target and selected `FROM` dependencies still export. Cached builds
retain manifest-based dependency identities and their existing verification.

This follows the useful separation between image-stage dependencies and file-copy
dependencies in the maintained [Kaniko executor](https://github.com/osscontainertools/kaniko/blob/c6ffb6a3f8805a2579e80fa25f362e7667177b65/pkg/executor/build.go).
That project is [Apache-2.0 licensed](https://github.com/osscontainertools/kaniko/blob/c6ffb6a3f8805a2579e80fa25f362e7667177b65/LICENSE).
Weld's implementation uses its existing Rust planner, owned roots and confined
copier; no Kaniko source code or runtime dependency was incorporated.

On the same A40 Pod, four alternating-order runs (old/new/new/old) copied a
1 GiB file through a producer stage into the final image with caching disabled:

| Measurement | Before | After |
| --- | ---: | ---: |
| Elapsed mean, two samples | 16.93 s | 6.63 s |
| Retained build allocation | 4.00 GiB | 3.00 GiB |

Every output passed independent archive content, ownership, mode, xattr and exact
timestamp checks. This small workload isolates the omitted stage export; it does
not predict the speed of RUN-heavy builds or cached builds.

The unchanged Nemotron workload then completed in **20m05.4s**, compared with
**28m50.4s** for the preceding candidate on the same Pod. This is an observed
8m45s reduction, not a controlled estimate: package/model downloads and page-cache
conditions can vary. Both runs reused the downloaded base, disabled instruction
caching, and used automatic limits. The model stage fell from 760.295s to 310.972s;
its baseline capture, intermediate export and checkpoint verification were omitted.

Retained build allocation fell from **196.65 GiB to 162.23 GiB**. The final image
still has 48 layers and 36,882,096,234 referenced layer bytes. An independent
streaming verifier checked every blob/diff ID, the exact base prefix, configuration,
117 pinned model files and source files. Source and prior tags were preserved.

Validation: 571 normal tests and seven additional resource tests passed, plus
independent OCI/Docker acceptance, formatting, documentation and Linux/Windows
cross-target linting. The tested binary SHA-256 is
`17046660f362eeaf49c3f8757e1a9778d89867fc125ed3a7f552006216743468`.
Cached full-image performance and GPU inference remain untested. Repeated inherited
base preparation still took 538.494s and is the next major optimization target.

## Last-consumer inherited-root handoff

Layered `--no-cache` builds can now transfer an exclusively owned parent root to
its last selected `FROM` consumer. The transfer is a directory rename, preserving
file inodes and hardlink groups. Earlier children still replay the parent image;
any selected `COPY --from` use excludes that parent from transfer. The parent OCI
image remains independent, and fresh exported deltas are still verified.

The exported root carries a bounded, pinned receipt containing its image identity,
verified aggregate replay usage, and captured symlink targets. Cross-filesystem
or cross-bind-mount moves and insufficient receipt metadata fall back to replay.
Cancellation after transfer retains the child-owned root in the recorded work
directory. Cached builds and flattened output keep their existing paths.

Four alternating-order runs on the existing A40 workstation (old/new/new/old)
used a 512 MiB inherited runtime, 16,384 small files, a symlink, and a 256 MiB
COPY-only model stage, with fixed source timestamps:

| Measurement | Before | After |
| --- | ---: | ---: |
| Elapsed mean, two samples | 21.539 s | 18.935 s |
| Retained build allocation | 3,793,530,880 B | 3,180,449,792 B |

This is a 12.1% observed reduction for that workload and approximately 0.57 GiB
less retained allocation. Every output passed independent blob, content, config,
mode, owner, xattr, timestamp and base-prefix checks. Parent image contents stayed
unchanged. The allocation metric uses `du`/inode blocks, not physical reflink extents.

Validation: 576 normal tests and nine additional privileged/resource-runtime
tests passed (585 unique Rust passes; 41 ignored tests remain unrun). Independent
OCI/Docker acceptance, documentation, formatting, and Linux/Windows cross-target
linting passed. The final tested release SHA-256 is
`ea24c9658388c7d196a1009a46d00d898497096aad6bae9d53bdec7e5a7a8d46`.

The unchanged Nemotron Dockerfile at the same pinned commit was then built with
both releases on one temporary A40 Pod: 7.65 observed CPU quota, 50 GB memory
ceiling, and 1 TB native container storage. The pinned base was downloaded once
outside the measurements and bound as a local OCI input. Both builds used
`--no-cache`, automatic resource limits, layered default, and a 24-hour RUN timeout;
public package and model downloads were included in their timings.

| Full Nemotron measurement | Before | After |
| --- | ---: | ---: |
| Elapsed | 19m50.3s | 16m40.3s |
| Base filesystem preparation, summed | 536.043 s | 353.669 s |
| Final stage | 499.365 s | 296.384 s |
| All RUN commands, summed | 175.839 s | 178.192 s |
| Retained build allocation | 162.23 GiB | 138.84 GiB |

The observed improvement is **3m10s (16.0%)**, with **23.39 GiB** less retained
allocation. These are sequential single full builds, not controlled page-cache or
network trials. The final stage logged the ownership handoff and omitted its
47-layer replay; both earlier stages still replayed. Final export remains costly.

Independent streaming verification passed for both outputs: every blob and diff
ID, the exact base/runtime descriptor prefixes, evaluated configuration, and all
117 pinned model files (25,082,020,070 bytes). Both final images have 48 layers and
36,882,096,234 referenced layer bytes. The source checkout remained clean. A
separate real-Pod test executed a child RUN as UID/GID 65534 after the handoff.

The temporary benchmark Pod was terminated after evidence collection. The exact
release was installed on the existing workstation and passed another nonroot RUN
smoke build. Cached full-image performance, native Windows execution and GPU
inference remain untested by this change.
