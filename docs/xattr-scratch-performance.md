# COPY xattr scratch reuse: incomplete Pod comparison

The allocation change is integrated at `e41a8ea`, but this experiment does not
establish a speedup. Its only completed pair measured **39.89 seconds before
and 40.22 seconds after**. The reversed pair was interrupted by a parent-agent
supervision error, so the planned balanced comparison is incomplete.

## Change and correctness evidence

`src/context.rs` now reuses initially empty, operation-owned buffers for xattr
names and values. Scratch retains at most 64 KiB for names and another 64 KiB
when values are encountered. Returned attributes remain independently owned.
The code keeps filesystem observations, callback locations, logical budgets,
fingerprints and all integrity checks. It does not cache attribute results.

Independent review passed 39 context tests, 23 instruction-cache engine tests,
six ownership-boundary tests and four final-verification tests. An additional
instruction-cache integration run passed six cases, with ten ignored. Five
paired real-kernel traces matched all 168 xattr syscalls and 253 callbacks,
including their order, supplied lengths, returned bytes, summaries and errors.
Mutation, removal, cancellation, reentrancy and exact xattr limits were checked.
Formatting, strict Clippy and documentation checks passed. These are scoped
results, not another complete repository-suite run.

## Pod method and partial results

The baseline was `d6fe610`; the candidate was its direct child `e41a8ea`.
Both were optimized static Rust 1.90 release binaries. Their only source
difference was `src/context.rs`. Exact revisions, binary hashes and raw result
fields are in [v02-xattr-scratch-partial.json](v02-xattr-scratch-partial.json).

A temporary Secure `cpu3g` Pod in EU-CZ-1 provided eight assigned CPUs on an AMD
EPYC 9B45 host, a 32,000,000,000-byte memory ceiling and 80 GiB observed disk
capacity. Build storage was overlay; host container mounts were XFS. A private
write/fsync probe confirmed local backing I/O. No network volume was attached.

The fixture contained a 1 MiB payload, 100,000 small 1 KiB files and additional
metadata cases. Four cold builds were planned in baseline/candidate then
candidate/baseline order. Cold means an empty managed store, not a flushed OS
page cache. Each build had a 300-second limit; the experiment had a 35-minute
limit and a 90-second renewable parent-supervision lease. The concurrent
allocation-tree sampler was disabled; process observations ran every half
second. Build times exclude independent replay and acceptance.

| Order | Executable | Build seconds | User CPU seconds | System CPU seconds | Independent acceptance |
|---|---|---:|---:|---:|---|
| 1 | Baseline | 39.885535 | 15.471169 | 24.226796 | Passed |
| 2 | Candidate | 40.218766 | 15.133665 | 24.881004 | Passed |
| 3 | Candidate | 40.847470 | 15.138060 | 25.484361 | Interrupted; not accepted |
| 4 | Baseline | — | — | — | Not attempted |

The first pair passed independent filesystem/configuration/metadata replay,
descriptor/diff-ID checks, exact OCI-byte equality, source immutability and
output/cache isolation, including deliberate output mutation. Its candidate
elapsed time was 0.84% longer. One pair is insufficient to establish either
a performance improvement or a regression.

At 17:18:09 UTC the watchdog detected an expired liveness lease and stopped the
second pair during acceptance. The parent agent had failed to renew that lease
while preparing the report. The third builder had already exited zero; this
was a controller failure, not a demonstrated product failure. There was no
retry, assertion waiver or deadline extension. Three builds were attempted,
two were accepted, and one pair completed. The supervisor's whole-run
`accepted_builds: 0` field is retained verbatim in the JSON; individual completed
results establish the partial count of two.

Absolute times must not be compared with the earlier 95.60-second diagnostic
sample: the CPU host and observation settings changed. This trial collected no
allocator totals and makes no large-image, full Nemotron or Docker-parity claim.
The [earlier diagnostic profile](checkpoint-profile-v02.md) still identifies
repeated verified reads as the main large-file cost.

## Next bounded investigation

A read-only follow-up found another small allocation opportunity: `attr_path`
builds owned path bytes and then copies them through the generic `cs` helper.
Passing the owned `String` or `Vec<u8>` directly to `CString::new` could remove
that redundant copy while retaining path validation and every filesystem call.
This is a proposal, not an implemented or measured improvement; `CString` can
still resize the consumed allocation. It does not address repeated blob reads.

Combining adjacent mount and metadata observations is a broader contract change:
skipping the second call also removes its independent failure result. The current
review did not establish a replacement that preserves those semantics. It is not
authorized by the allocation-reuse evidence.

Before another timed comparison, supervision should be handled by a bounded,
independent controller process instead of depending on the agent's tool-call
cadence. The fixed experiment/deletion deadlines and stop-on-failure behavior
should remain. The sealed wrapper and this failed run have not been altered.

## Evidence and teardown

All 67 collected files passed SHA-256 verification. Evidence archive SHA-256:
`1f94992f91666e7d0b99ec8c3ca03358046ee390ea1252362d08e61ee169030f`.

Pod deletion returned 204, followed by 404 and a complete empty inventory at
17:22:43 UTC on 2026-10-27. The backup cleanup reminder was removed. The observed
lifecycle was 19 minutes 44 seconds, approximately $0.109 at the quoted compute
and prorated disk rates. This is an estimate, not settled billing. No benchmark
Pod remains running.
