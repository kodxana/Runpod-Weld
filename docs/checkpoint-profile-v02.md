# Checkpoint profiling on Runpod

The 2026-10-27 profile separates two costs: repeated verified reads dominate the
large-file fixture, while COPY preparation and filesystem inventories matter more
for the 100,000-file fixture. It is a diagnostic experiment, not a speed trial.
All production reads, hashes, callbacks and publication checks were retained.

## Method and acceptance

The optimized static diagnostic executable uses production source `eba6d17`,
with allocator counters and operation spans. Its comparison executable is the
previously accepted `503b741` release. Neither includes the later inventory-path
borrowing change or xattr scratch reuse. Exact hashes, raw values and overlapping
scope counters are in [v02-checkpoint-profile.json](v02-checkpoint-profile.json).

One Secure `cpu3g` Pod in EU-CZ-1 supplied eight assigned CPUs on an AMD EPYC 9654
host, a 32,000,000,000-byte memory limit and 80 GiB observed disk capacity.
Builds used overlay storage; host container mounts were on local XFS. A private
write/fsync probe produced block-device I/O. There was no FUSE or network volume.

Each workload attempted cold, warm, application-edit and populated no-cache
builds for both executables. Cold means an empty managed store, not a cold OS
page cache. The large fixture used a 1 GiB incompressible file and 2,048 small
files; the many-file fixture used a 1 MiB payload and 100,000 small files.

All eight large-file cases passed independent replay, metadata, configuration,
prefix, isolation and paired OCI-byte checks. Seven many-file cases passed their
individual acceptance checks. Its final reference no-cache build exited zero,
but the 40-minute profile deadline interrupted independent replay. That case is
unaccepted, final pair checks were not completed, and the many-file profile is
**incomplete**, not a pass. Its accepted cold sample remains useful for attribution.

Build time excludes subsequent acceptance. A concurrent allocation-tree sampler
ran every five seconds, with additional process observations every half second.
The many-file cold sampler consumed 30.51 seconds concurrently with the builder;
its interference is not subtracted. Fixed order and uncalibrated diagnostic
overhead prevent treating reference/diagnostic differences as speedups.

## Large-file cost

The diagnostic cold build took 60.54 seconds. OCI verification streams accounted
for 48.11 seconds and 71,361,155,400 input bytes across 485 streams. These spans
include reads, hashing and callbacks; they are not an isolated SHA instruction
benchmark. Process `read_bytes` was zero, consistent with page-cache reuse.

Inventory took 5.34 seconds, including 5.08 seconds in payload processing and
0.26 seconds in metadata work. The 414 fsync calls took 0.235 seconds; resource
rechecks took 0.117 seconds. Publication and export spans include verification,
so their times must not be added to verification as separate costs.

The application-edit diagnostic build took 37.50 seconds, with 28.37 seconds in
OCI verification. Reducing serialization has not eliminated repeated consumption
of unchanged blobs. The rejected hash-skipping optimization remains rolled back.

## Many-file cost and the next change

The accepted diagnostic cold build took 95.60 seconds: 24.46 seconds of user CPU
and 69.66 seconds of system CPU. It recorded 20,769,127 allocation requests and
55,038,395,208 requested bytes (51.26 GiB). This is cumulative allocator traffic,
not live memory, retained memory or guaranteed memory writes.

COPY preparation spans totalled 12.27 seconds and 36.79 GiB of requested
allocations. Inventory totalled 27.80 seconds, including 13.21 seconds in metadata
work. These scopes overlap other operations and must not be summed.

The COPY xattr reader allocated a 65,536-byte name buffer on every call, including
files without xattrs, and another temporary buffer for each value. The follow-up
`e41a8ea` reuses initially empty, operation-owned scratch: 64 KiB for names and
another 64 KiB only when values are encountered. Returned attributes remain owned
copies. This changes allocation behavior without caching filesystem observations.
Independent paired traces retained 168 xattr syscalls and 253 callbacks in the
same order across five mutation/cancellation/reentrancy fixtures. A subsequent
[release-only comparison](xattr-scratch-performance.md) completed one pair at
39.89 seconds before versus 40.22 seconds after, then a parent supervision error
interrupted the reversed pair. No elapsed-time improvement is established.

A COPY target list is not a complete verified mutation journal: hardlink aliases,
implicit parents, symlink resolution and metadata observations extend beyond the
nominal paths. This profile does not justify skipping inventories or checks.

## Evidence and limits

All 177 collected evidence files passed local SHA-256 verification. Archive:
`5a455d8e8476f0c2c3e0258b067cb658d2814449b404713f1c8d0103e8baa0b7`.
The Pod was deleted: 204, followed by 404 and an empty complete inventory at
17:02:20 UTC. The backup reminder was removed. Its roughly 52-minute lifecycle
cost about $0.285 by the quoted compute/storage rates; this is not settled billing.

Helper counters are not a syscall census; callback timings are sampled. Scope
times overlap. Wait4 maximum RSS can reflect the Python launcher's high-water
mark, so it is not treated as the builder's measured peak. This experiment does
not establish full Nemotron performance, Docker timing parity, registry throughput,
GPU acceleration or native Windows behavior.
