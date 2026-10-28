# Real Nemotron build: cold timeout, 2026-10-28

**Candidate `5860971` did not clear the real large-image gate.** The original
Nemotron Dockerfile reached the fixed 3,600-second cold-build limit during final
image export. Weld handled cancellation and recorded the build as failed.
The final image had no `index.json`, and the record had no manifest. Warm and
application-edit builds did not start; independent full-image acceptance and
GPU inference were not run. No release tag or new public release was published.

This result supplements the successful synthetic/packaging checks in
[stable candidate validation](stable-candidate-validation.md). It does not
invalidate those checks or establish a functional regression against an older
Weld build. It does establish that the managed cold path remains too expensive
for this workload. [Machine-readable measurements](real-nemotron-5860971.json)
retain the completed-step timings, missing-metric flags and artifact identities.

## What actually ran

The source was `kodxana/nemotron-bolt-runpod` at
`91ee1316e21f624082c90cc07fcbbec1d9499550`, with its original pinned base,
package locks, three stages and both model revisions. No source instructions
were removed. The models contain 117 pinned files totaling 25,082,020,070 bytes.
The optional `HF_TOKEN` was absent; the models were public. Runtime package
installation and the source's build checks completed, followed by both model
downloads and their in-build checks. This is not independent final-image acceptance.

The executable was the actual CI portable package for
`586097166166fb4849e3102be802d0d0cc585284`, still version `0.1.0`:

| Input | SHA-256 |
| --- | --- |
| Executable | `e095208dca1146c0d60f5f03b97e75369695601fe1373d48691077c67a0d1c8c` |
| Portable archive | `5e35862cc4f3ea5d7ac1556a4c331198e5f3aefdeaca89ceb8aff76ec64f8d81` |
| Source archive | `13d7ef64e39070a3e4f64b74597a66627d2837aed0edc112b40336ffa31a81e0` |
| Sealed benchmark runner | `06109ea06db30dffee68d016cbeb4cc0e8fbfb67599e6904e4c23d65ec034230` |

Preflight verified all 38 source files and all 170 portable-package files,
including exact modes. Source timestamps were pinned to mtime 2000000000 and
atime 2000000001 to prevent relatime reads from changing cache fingerprints.
There was one attempt, an initially empty store, normal managed layered defaults,
and automatic resource limits. The only build override was
`--run-timeout-seconds 3600`; the default 300-second RUN limit was not tested.
The separate harness capped the complete cold build at 3,600 seconds.

The temporary Secure A40 Pod in EU-SE-1 had an observed CPU quota of 7.65 cores,
a 49,999,998,976-byte cgroup v1 memory limit, and 1000 requested disk units.
Initial available space was 1,073,657,020,416 bytes. Build storage was overlay;
XFS container backing and a synced write observed on local block devices
supported the local-storage check. There was no attached volume. A prior
allocation exposing FUSE network storage was rejected and deleted before any
builder ran. No GPU inference was attempted.

## Where the hour went

| Stage | Observed duration | Outcome |
| --- | ---: | --- |
| Runtime | 1,176.008 s | Completed |
| Model builder | 1,351.593 s | Completed |
| Final image | 994.307 s | Interrupted during final export |

These stage timers exclude earlier CLI/base-pull work. They are not a substitute
for a completed whole-process wall measurement. The harness recorded
`timed_out: true`, and its last live sample was at 3,599.929 seconds.

Completed subphase totals:

| Subphase | Count | Seconds |
| --- | ---: | ---: |
| Base-layer preparation | 2 | 383.668 |
| Verified baseline capture | 3 | 113.916 |
| Instruction checkpoint export | 16 | 1,342.108 |
| Checkpoint delta verification | 16 | 341.546 |
| Instruction cache publication | 16 | 612.899 |

Subphase times are contained within instruction/stage times; do not add these
tables together. Final stage-cache work and the interrupted final export are
not all represented by the completed subphase rows.

The managed-session optimization was active: repeated runtime checkpoint
publications took roughly 0.2–0.4 seconds after first admission, and the final
stage reused the owned parent root without replay. Nevertheless, small runtime
COPY steps took around 59–70 seconds each. The final tiny JSON COPY took
**191.467 seconds**: 153.937 seconds exporting, 35.376 seconds verifying, and
0.364 seconds publishing its instruction cache, plus surrounding work.
The final model COPY/checkpoint took 612.796 seconds, including 261.688 seconds
of cache publication. The last image export was cancelled after 42.406 seconds.

At the last live sample, the process counters reported 2,935,734,721,265 bytes
requested through reads (`rchar`), 965,823,193,088 storage-read bytes and
476,557,230,080 storage-write bytes. These are sampled process accounting,
not final totals or image size; `rchar` is not physical disk traffic. The
sampled parent high-water RSS was 581,204 KiB, not aggregate workload memory.
The pattern supports targeting repeated large-data processing and filesystem
scans. It does not identify one syscall as the sole cause. No qualifying
unchanged D-state stall was captured by the bounded observer.

The historical 20m05s Nemotron result used an earlier binary, `--no-cache`, and
an already downloaded base. It is not a matched baseline for this cold managed
run. No speed ratio, warm timing or edited-build timing is claimed here.

## Sampler failure and follow-up

After timeout, the sealed sampler tried to read the exited child's
`/proc/<pid>/io` before `wait4`. The Pod denied that read even though the
container UID was zero. This secondary `PermissionError` prevented the sampler
from recording final exit status, whole-process wall/CPU/RSS and I/O totals.
The original evidence remains unchanged; none of those totals were reconstructed.

A separate 0.2-second child reproduced the issue on the same stopped-workload
Pod: live counters were readable, but the zombie counter file was UID/GID 65534,
mode 0400, in a namespace mapping UID 0 to host UID 231072. `wait4` still
succeeded. The tracked sampler now records counter unavailability, always
collects the available `wait4` evidence, and preserves build failure/timeout as
the primary error. Successful benchmark acceptance still requires final I/O
counters. Missing counters are never replaced with zeroes or the last sample.

Three regression cases failed before the fix and passed afterward. All 13
observer/lifecycle test methods passed under WSL Linux, including denied-counter
success, failed exit and timeout cases. These are local harness tests, not Pod
performance measurements; the fixed sampler was not rerun on a new Pod.
The existing fixture suite also passed eight tests, with one optional test
skipped. The sampler correction is commit `d9aa87b`.
The Rust builder, verification gates and cache format are unchanged.

## Evidence, cleanup and next gate

All 21 collected evidence files passed their manifest hashes; none were omitted.
The 602,426-byte evidence archive SHA-256 is
`f7a2d8e058cdaf588c13d4ed312584dc97a0598062a38fd64ac7960e9b0b5608`.
Raw logs, 7,129 process samples, failed build record, resource observations and
the namespace probe are retained under
`.research-private/real-nemotron-20261028/verified-evidence`.

The supervisor reported zero initial leftover descendants and zero survivors.
Pod `9u3jdd603gobam` was created at 11:04:06 UTC and deleted at approximately
12:14:13 UTC, before the 13:30:45 deadline. Deletion returned 204, fresh get
returned 404, the complete inventory was empty, and the cleanup reminder was
removed. No resources from this run remain.

The real-image gate remains open. The next performance work should reduce
repeated checkpoint export/inventory processing for known small changes, and
measure final publication separately, while preserving corruption detection,
durable instruction prefixes and independent output inodes. Before another
long run, qualify final process-counter access on the actual Pod. Repeat this
real workload after the implementation change; do not replace its failed cold
result with synthetic timings or publish a large-image speed claim.
