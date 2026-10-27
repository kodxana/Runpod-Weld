# Concrete managed control and output boundary

This implements the control/output prerequisite in
[checkpoint-verification-design.md](checkpoint-verification-design.md). This
slice does not skip hashes, create a publication session, or change cache formats.
Exporter capability and session integration are separate work.

## Closed entry and polling

`build::build_managed_recorded(source, options, lease, record, &Policy,
&AtomicBool)` is the Linux-only concrete entry, reexported from
[`managed_control.rs`](../src/managed_control.rs). Only that entry constructs a
production `ManagedControl`. `for_test` is compiled only in Linux unit tests and
uses the same actual output capture. No `BuildOptions` field grants provenance.

`cancelled()` reads only the borrowed atomic. `poll()` checks that atomic first,
then sticky resource failure, then the concrete policy, immediately on the first
poll and at most once per second afterward. `check()` reads sticky resource and
output failure only; it never observes new capacity after publication. The
managed engine attaches this context only to an operation that already failed,
preserving the original error. An already successful publication does not fail
because of a later resource observation.

[`build.rs`](../src/build.rs) passes `Option<&ManagedControl>` explicitly through
`build_inner_checked`, `build_stage`, `StageCache`, `export_stage`, `worker`, and
`worker_command`. All existing public `Fn` entries pass `None`, including
`build_recorded_with_resources`. The private managed entry erases its fixed
polling closure to the same internal `&dyn Fn()` type used by the compatibility
resource wrapper, avoiding another large engine instantiation. That erasure does
not create provenance: only the separately passed control authorizes future
session use. Internal resource/progress wrappers do not authorize reuse.

The `StageCache::publish` hook currently checks output status and then performs
the unchanged conservative publication. Parent integration must select the
managed exporter explicitly, preserve its owned capability before consuming
`Exported`, and admit physical payloads through the publication session. It must
not infer ownership or verified content from policy, a path, or the reporting
scope.

## Held output objects

[`progress.rs`](../src/progress.rs) owns `Output`, a pair of held CLOEXEC duplicates
of actual stdout/stderr and sticky per-sink refusal flags. `check_payload(&File)`
compares device/inode identities from the held files. Duplicate and open-unlinked
files are covered. An alias poisons its sink **before** returning an error;
metadata failure disables both sinks. A separately safe sink may still report an
error. `OutputWriter`, RUN forwarding, and quiet worker stdio refuse poisoned
sinks. Aliasing must be checked with RUN and forwarding writers quiescent, before
evidence admission or reuse and before interleaved diagnostic writes.

`Phase` retains the output object captured at creation for start, tick, finish,
and Drop. Other engine diagnostics use the scoped `progress::diagnostic` route,
including the secret suppression notice and the restoration-failure diagnostic
in [`MountGuard::drop`](../src/run_mounts/linux.rs). The scope in
[`main.rs`](../src/main.rs) remains alive through preparation, the engine call,
final stdout, tagging output, and failure reporting. Error string conversion
does not discard the sticky sink state.

Replacing the caller's fd 1/2 does not redirect these owned duplicates. Quiet RUN
receives duplicates of the same pinned objects in the child; the parent never
calls `dup2` on caller stdio. Forwarding preserves the existing pipe/socket/PTY
handling and caller flags, including refusing blocking PTY masters in plain
mode. No global signal behavior is changed.

This relies on the cooperative stable-store/process contract: callers must not
replace the builder's private descriptors, change shared open-file-description
flags, or concurrently write protected objects. Neither a read-only handle nor
CLOEXEC is OS immutability. External writers, writable mappings, proc-mediated
writes, bind aliases, and output consumers writing back to the store remain
outside the contract.

Protection begins at session admission. A caller can redirect pre-build stdio
to a pre-existing input and corrupt it before its first full verification. This
slice does not scan the entire store before CLI output or claim to prevent that
pre-admission corruption. Full source/cache verification remains responsible for
rejecting it without publishing an image/checkpoint. This differs from a
post-admission alias violation, which must suppress subsequent writes and abort
the session.

## Worker ordering and validation

The execution order in `build.rs` remains: wait for the lease guard to reap all
descendants, finish and join both output threads, finish RUN mount restoration,
restore DNS, then resume publication. The existing
[`lease_guard.rs`](../src/lease_guard.rs) enumeration closes descriptors >=3
except the lease, including descriptors above the current soft NOFILE limit.
The workload pre-exec closes the lease too. Session descriptors additionally
need CLOEXEC; these mechanisms are not a sandbox. The tracer intentionally
retains outer `/dev` and `/proc` directory handles.

Unit tests in `progress.rs` cover protected stdout/stderr, duplicate/unlinked
inodes, caller sink replacement, CLOEXEC, Phase lifecycle, actual mount Drop
failure, forwarding refusal, quiet-launch refusal and final/error reporting.
`managed_control.rs` tests atomic ordering, polling cadence and sticky resource
failure without new observations from `check()`. `build.rs` exercises the real
concrete entry for success, cancellation and resource failure.

[`tests/managed_control.rs`](../tests/managed_control.rs) distinguishes actual
pre-admission stdio corruption/full rejection from the unit tests' alias refusal.
It also exercises the hidden guard and the complete managed build → guard →
tracer → static application chain with an identifiable non-CLOEXEC payload at fd
1024 above a lowered soft limit. The application checks that no such payload
handle survives. This tests the worker boundary independently of the separately
implemented publication session, not an already admitted session object.

[`tests/worker_cli.rs`](../tests/worker_cli.rs) retains all existing byte, flag,
PTY, blocked-consumer, timeout, SIGINT and descendant-reaping assertions and runs
them through both legacy and concrete managed dispatch. Managed blocked-output
cases drain only the CLI preamble while the application waits at an explicit
gate, then leave its consumer open and undrained for the entire RUN output test.

## Focused validation record

Validation used WSL Ubuntu as root, Rust 1.90.0, offline locked dependencies, and
the native snapshot `/var/tmp/weld-managed-control-final.lNyemv` with its own
fresh `target` directory. Source stayed frozen during each command; corrections
were copied only between stopped runs. The final format-only module ordering
change was checked after the runtime checks. No broad suite or integrated
publication-session checks were duplicated in this slice.

| Command | Result |
| --- | --- |
| `cargo test --offline --locked --lib progress::` | 9 passed |
| `cargo test --offline --locked --lib managed_control::` | 1 passed |
| `cargo test --offline --locked --lib concrete_managed_entry` | 1 passed, cache enabled |
| `cargo test --offline --locked --lib resource_refusal_precedes_work_and_stops_cooperatively_with_its_reason` | 1 passed; legacy callback ordering/context |
| `cargo test --offline --locked --test managed_control -- --include-ignored` | 3 passed; actual worker chain included |
| `cargo test --offline --locked --test worker_cli -- --include-ignored --test-threads=1` | 3 passed; managed and legacy paths |
| `cargo test --offline --locked --test tags_progress_cli --test build_resources_cli` | 6 passed, 1 existing ignored |
| `cargo test --offline --locked --test run_mounts_cli injected_secret_user_mutation_output_suppression_and_checkpoints -- --ignored` | 1 passed |
| `cargo test --offline --locked --test run_mounts_cli failed_and_cancelled_secret_runs_restore_before_return -- --ignored` | 1 passed |
| `cargo clippy --offline --locked --all-targets --all-features -- -D warnings -A dead_code` | Passed |
| `cargo doc --offline --locked --no-deps` | Passed |
| `cargo fmt -- --check` | Passed |

The focused total is 26 passing tests and one existing ignored resource
mount-namespace test requiring CAP_SYS_ADMIN. Clippy's command-line dead-code
exception covers session-facing hooks that this isolated prerequisite does not
yet consume; no production bypass or stub was added. The erased polling closure
produces a 63,170,080-byte debug CLI in this snapshot, within the existing 64 MiB
cache identity limit. Non-Linux compilation, checks against actual admitted
session handles, and durable-prefix SIGKILL regression remain with parent
integration.
