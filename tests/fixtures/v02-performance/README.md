# v0.2 Pod performance and acceptance

For the separately sealed `d6fe610` / `e41a8ea` cold-only xattr comparison, use
the [independent local lease controller](lease-controller.md). Its fresh-session
handoff replaces manual liveness pulses without changing the sealed payload.

Prepared independently at v0.1.0 commit
`63b716e1027ceba48bf9c887567419057b1bfd73`. Only these test files are owned by
this workstream. No candidate execution or Pod creation belongs to preparation.
The parent must supply GO naming a **frozen full commit and binary SHA256**.
`run.py` requires both and records them; it does not build a dirty checkout.

## Workload and comparisons

The standard-library fixture is an offline synthetic dependency workload: a
deterministic, incompressible, non-sparse 256 MiB payload, 2,048 small 1 KiB files,
and three COPY/RUN pairs. The input image contains an existing static amd64
BusyBox, with no pull. The application produces known text, hardlinks, symlinks,
permissions and xattrs. This is not pip/npm installation, a Python/Node app,
or a full Nemotron result. A later real application/model trial needs its own
offline dependencies, measured space and explicit cost fit; this runner does not
download them. Start at 256 MiB. Use 1,024 MiB only after measured peak storage and
remaining lease permit it, with a new evidence directory.

All builds use ordinary default managed behavior and actual `-t`, without
implementation-specific fast flags. Each variant/repetition has an isolated store.
Child processes receive only PATH, LANG, isolated HOME/TMPDIR and RPWELD_HOME;
host credentials, user configuration and private tuning environment flags are not
inherited. These exact non-secret environment values are recorded.
The four cases are cold (store absent), warm unchanged, app-only edit, and
`--no-cache` against the populated store. The last control must execute every RUN
and leave existing checkpoint files exactly unchanged. Context is not rewritten
for warm/no-cache. Only app content changes for app-edit; its timestamps are
restored to the original values, testing content-based invalidation.

Run four repetitions on **one Pod**, in this exact order within each case:

- Repetitions 0 and 2: baseline, candidate.
- Repetitions 1 and 3: candidate, baseline.

Each repetition completes cold for both binaries, then warm for both, app-edit
for both, and no-cache for both. All measurements are serialized. Cold means an
empty managed store, **not** dropped host page cache. There is no universal
performance pass threshold: raw paired results and median/min/max are emitted.
An acceptance failure aborts the experiment and retains failure evidence.

## Exact acceptance

Input atime/mtime are pinned to **2000000001 / 2000000000** seconds. All fixture
directories, regular files, symlinks and the explicit image root get those times.
RUN explicitly pins every generated/touched output and its parents. atime is
greater than mtime and in the future at the October 2026 test date, preventing
relatime access from introducing unrelated deltas. No generic timestamp field is
discarded. **There is no root timestamp exemption in this fixture**: base includes
an explicit `.` header, and mutating RUN restores its exact timestamps. ctime is
not an OCI-restorable value and is not compared. Once the host clock passes the
pin, revisit this fixture before making observer-effect claims.

The existing independent `../layered-export/oracle.py` supplies GNU-tar replay and
metadata snapshots; bring that directory along with this one when uploading.
The new verifier separately checks streamed descriptor SHA256/size, uncompressed
diff IDs, history counts, base descriptor/diff-ID/history preservation, and runtime
config. Fresh replay must equal the explicit expected whole tree: content hashes,
type/mode, uid/gid, nanosecond atime/mtime, xattrs, symlink targets and hardlink
equivalence. Comparisons cover both binaries, every repetition, warm exactness,
and edited/no-cache equality. Cross-version runtime config is exact; layer/history
shape can legitimately differ because the candidate introduces incremental layers.
Within one variant, warm manifest and full config must be byte-semantically equal
to cold (the source JSON values, including descriptors/diff IDs/history).

Logs must show actual RUN stdout markers, not just printed Dockerfile commands.
Warm must hit cache and execute none. App edit must report COPY/RUN prefix hits at
instructions 2–5 and execute only the application RUN. Candidate cold must have
six distinct instruction chains, each appending exactly one layer to the previous
verified prefix, plus the final stage checkpoint's one-layer metadata suffix for
the trailing ENV/LABEL/CMD. The suffix must preserve all six instruction layers;
it is identified by this fixture's final runtime label, not counted as another
filesystem instruction. App-edit output must retain the first four dependency/config
checkpoint layers. Every occurrence of a cache-owned blob digest must share its
inode internally. Existing cache file identity, mode, uid/gid, size, mtime and
SHA256 must remain unchanged across later builds. Cache file atime is excluded
from this *store inventory* because it is lookup activity, not delivered image
metadata; no atime exemption applies to image snapshots. ctime/nlink are excluded
from store inventory because adding valid internal aliases changes them.

Every mutable output must have inodes independent of cache and every peer output.
After each repetition, a same-size output-layer byte mutation must leave all
cache fingerprints and peer output hashes unchanged; the byte and timestamps are
restored, then the output's OCI verification is rerun. This is an inode ownership
test, not a power-loss, hostile-writer, or sandbox guarantee. RUN is trusted code.

## Measurements and retained evidence

`metrics.py` records wall time, wait4 user/system CPU and RSS, `/proc/PID/io`
read/write bytes and rchar/wchar/syscall counters, `/proc/PID/stat` CPU including
waited children, and rusage block counts. The leader is inspected while zombie,
before reaping, so final counters survive short builds. This assumes the builder
waits for its children; a unit test verifies waited-child I/O accounting. No
claim is made that process I/O counters measure storage-device physical traffic.

Allocated bytes use `st_blocks * 512`, deduplicated by `(st_dev, st_ino)` across
the entire build root. Logical bytes are also recorded. A no-atime directory
walk samples every 0.5 seconds, and before/retained values are exact inventories.
Sampled peaks are **lower bounds**, not exact high-water marks; sampling overhead
and raw sample times are retained. They do not deduplicate reflink extents. Scopes
separately cover context, store, current work/output, and all retained artifacts of
that variant/repetition. Prior case outputs are deliberately included in the last
scope. Independent replay and verification run after measurement. Their disposable
trees are then removed. Complete paired build trees are removed only after a
successful repetition, keeping the 100 GB scratch plan bounded.

Evidence preserves commands, stdout/stderr, raw measurements, manifests/configs,
all output blob hashes, replay trees, checkpoint inventories, prefix checks,
binary, private runtime helper, script and oracle hashes, source revisions, BusyBox hash, CPU affinity, cpuinfo,
memory, cgroup quota/memory controller values, mount information, filesystem/free
space, and limits. `summary.json` retains raw repeated values and paired wall-time
ratios. Artifact data itself is disposable; copy the evidence to the controller
before teardown. Do not infer full Nemotron timing from these measurements.

## Startup-stall diagnostics for a new sealed run

`cold_metrics.py` makes the sampler used in the managed-session comparison
available here: allocation inventories run only before/after the timed child,
and half-second process samples, `wait4`, deadlines and group cleanup remain.
It is separate from the original allocation-sampling `metrics.measure` above.
Neither prior sealed bundles nor their measurements are modified.

For a diagnostic run, call this sampler with one fresh observer per build:

```python
from cold_metrics import measure
from proc_stall import ProcStallObserver

result = measure(command, env, roots, log_dir, timeout=300,
                 stall_observer=ProcStallObserver())
```

The observer consumes the existing `seconds`, `stat` and `io` sample. After at
least one second of consecutive D-state samples with unchanged CPU/I/O counters,
it reads only bounded `wchan`, `syscall` and identity-check `stat` files. It saves
the wait-channel symbol and syscall number/status; syscall arguments, pointers,
FD targets, payloads and stacks are not collected by this observer. Process
identity is checked before/after capture. Permission failures, malformed values
and exit races are diagnostic statuses, not build failures. Detection resets on
progress, invalid input, nonincreasing time or a sample gap over 1.5 seconds.

Captures are limited to one per second and 16 per build, held in memory until
the normal measurement write. Each includes capture duration. These observations
are neither atomic nor proof of the cause of a wait. Use the same settings for
both benchmark arms, record observer source hashes in a newly sealed bundle,
and report the extra sampling overhead. Default calls remain observer-free.
Actual Pod access to these proc files must be checked on that kernel. This
instrumentation does not resolve or remove the previously reported edit outlier.

```sh
python3 -B -m unittest -v test_proc_stall
```

## Local checks (no candidate)

Linux root, Python >= 3.11, GNU tar and an existing **static** BusyBox are needed.
The checks run on native `/var/tmp`, not the Windows/9p checkout.

```sh
cd tests/fixtures/v02-performance
python3 -B -m unittest -v test_fixture
bash baseline-smoke.sh /path/rpweld-0.1.0-linux-amd64.tar.gz
```

The second command verifies the published portable archive SHA256 and executes
only immutable v0.1.0, using a 1 MiB/eight-file smoke. It exercises all four managed
cases and OCI/metadata/isolation acceptance, without claiming performance.
The full portable directory is required: `bin/rpweld` finds its private Skopeo
loader/libraries in `lib/rpweld`. Do not copy just the executable.

Baseline archive SHA256:
`02396ce9ccd9800377fe4e0b0e49f42dd0ca221bccb6facec8ba86d390b861ee`.
Baseline executable SHA256:
`24c09bd3b805a525d447f5c568991dc50da417fdd299445b52c981087a273686`.
The inspected release `build-info.json` reports the above commit, amd64 target,
and `crt_static: true`.

## Deployment handoff (parent GO required)

Read-only Runpod MCP observations on 2026-10-27:

- `list-pods`: empty (no next page). No resource created by this fixture work.
- `list-cpu-types(include=AVAILABILITY, product=POD, vcpuCount=8)`:
  `cpu3g`, General Purpose, 4 GB/vCPU, $0.04/vCPU/hour; HIGH in `EU-CZ-1`.
  Selected shape: **8 vCPUs, 32 GB, $0.32/hour compute**.
- `get-template(runpod-ubuntu-2404)`: image `runpod/base:1.0.2-ubuntu2404`,
  CPU template, no mounts. The create request uses the observed image directly.
- `describe-tool(create-pod)`: current v2 shape is `cpu: {id, vcpuCount}`,
  `disk` in GB, `mounts: {}`. `pod-create.json` requests 100 GB ephemeral container
  disk, no network/persistent volume, SSH only, no Jupyter.
- `get-ssh-keys`: account has registered keys. The executor must verify possession
  of a corresponding local key and working transfer before proceeding with builds.
- [Runpod storage documentation](https://docs.runpod.io/pods/storage/types), read
  2026-10-27: container disk is $0.10/GB/month while running. 100 GB is $10/month
  prorated (about $0.0137/hour using a 730-hour month, not a live total-price quote).
  A 90-minute lease is $0.48 compute plus prorated disk; record actual returned
  Pod hourly price before running. No standing volume charge is requested.
- Installed WSL CLI help inspected: `runpodctl 2.9.0-c094cac`, `pod delete ID`,
  `pod get ID`, `pod list --all`. **CLI inventory currently returns
  `no_credentials`**, although MCP reads work. Thus the external automatic cleanup
  wrapper is prepared but cannot be armed with the current CLI auth. Before
  creation the parent must supply its authorized private CLI credential or own the
  bounded MCP deletion directly. Never put a key in chat or evidence.

Refresh stock and price immediately before creation. Do not allocate while waiting
for a candidate. The user already approved a temporary Pod; GO is parent coordination,
not another user permission request. There are no registry pushes, package/model
downloads, extra ports, privilege changes, or security waivers in this workflow.

1. Parent freezes release-mode candidate and supplies full commit, binary SHA256,
   and complete runtime bundle. Verify baseline/candidate bundles and offline static
   BusyBox locally. Upload fixture directories plus artifacts via ordinary SSH/scp.
   No toolchain or cargo target is needed on the Pod.
2. Prepare the external controller **before create**. `pod-session.py` can wrap an
   upload/run/collection command, then delete the exact created Pod in `finally`;
   it accepts a maximum 90-minute deadline from creation and stops the child eight
   minutes earlier to reserve time for bounded API cleanup. It does not create Pods.
   Use MCP create with `pod-create.json` only on parent GO. Read the new Pod back
   to verify CPU, price, image, disk, no mounts, SSH and state. Record its actual ID.
   Write the external receipt from that response:
   `{"source":"create-pod","created_by_this_task":true,"id":"ACTUAL_ID","created_at":"ACTUAL_UTC"}`.
3. Start the controller immediately, outside the Pod. Its child command must perform
   transfer, bounded connection readiness, experiment and evidence collection even
   on an experiment failure. Choose an experiment cutoff at 60 minutes after create,
   leaving up to 30 minutes for copying evidence and deletion. Account for image
   boot time in that lease. If controller auth is unavailable, parent owns the same
   absolute deadline through MCP; this is not an armed automatic watchdog.
4. On the Pod use `/var/tmp/v02-scratch-UNIQUE` and a separate
   `/var/tmp/v02-evidence-UNIQUE`. `findmnt` must report ext4/xfs/btrfs or local-backed
   overlay. Reject FUSE/NFS/9p, tmpfs, or `/workspace` network mounts. Inspect overlay
   backing mount information: a string `overlay` alone does not prove local storage.
   The runner records mount evidence and requires at least 30 GiB available at
   256 MiB (70 times dependency size at larger scales). Keep the initial 100 GB
   request; scale only from measured peaks and actual free space.
5. Run `pod-run.sh` with the frozen handoff. Run default trusted fixture behavior;
   if the container denies a required operation, preserve the failure and tear down,
   without broadening privileges. Example below uses placeholder paths/hashes only.
6. Copy evidence off the ephemeral disk, verify copied checksums, then delete the
   Pod on success **or failure**. Do not stop it and leave storage billing. The
   controller checks `get -> not_found` and `list --all -> absent`; parent also uses
   MCP get/list to verify absence. A successful delete return alone is insufficient.
   Preserve teardown evidence locally. Report an unverified deletion immediately.
   No volumes are created, so no volume cleanup should be needed.

```sh
# External controller; run only AFTER the authorized create and receipt exist.
python3 pod-session.py --receipt created-pod.json --deadline-utc "$TEARDOWN_UTC" \
  --evidence controller-evidence -- bash upload-run-collect.sh

# Within that command, over SSH on the one Pod:
bash tests/fixtures/v02-performance/pod-run.sh \
  --baseline /opt/v02/baseline/bin/rpweld \
  --baseline-sha256 24c09bd3b805a525d447f5c568991dc50da417fdd299445b52c981087a273686 \
  --candidate /opt/v02/candidate/bin/rpweld --candidate-sha256 "$CANDIDATE_SHA256" \
  --candidate-revision "$FROZEN_COMMIT" --parent-go "$FROZEN_COMMIT" \
  --busybox /opt/v02/inputs/busybox --pod-id "$POD_ID" \
  --deadline-utc "$EXPERIMENT_UTC" \
  --scratch /var/tmp/v02-scratch-UNIQUE --evidence /var/tmp/v02-evidence-UNIQUE
```

The shell variables are values supplied by the executor from actual reads. Parent
must not substitute an old Pod ID: the earlier `kjoh077bhxhu0g` is gone and is not
used here. No local timing is a Pod performance claim. No actual power-loss or
security-sandbox property is asserted by these fixtures.
