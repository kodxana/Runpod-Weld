# Large-image performance

Measurements below are from Linux Runpod Pods with native container storage,
optimized Weld binaries, and layered export. They are not Docker parity claims.

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
