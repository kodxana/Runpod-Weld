# Proposed managed checkpoint publication session

Status: design proposal, not implemented or enabled. The write-boundary proof
below is a prerequisite, not an established property of the current engine.

The [accepted Pod diagnostic](verification-cost-v02.md) identifies repeated
checkpoint hashing as the large-file bottleneck. Its cold 1 GiB fixture hashes
71.36 GB through OCI verification, spending 40.01 seconds in SHA updates. The
existing SHA-NI backend is active. Small allocation changes do not remove this
work.

## Preserve immediate durable checkpoints

Keep `cache-v2` and publish every successful instruction immediately. Layers
already represent deltas and share physical payload storage; a parent/delta
record schema is not necessary to address repeated verification.

Do not defer all publication until stage completion. Existing retry behavior
requires a completed RUN prefix to survive a later failed or cancelled
instruction. Error-handler flushing cannot preserve abrupt-exit behavior.

The candidate is a private, per-stage managed publication session. It could
retain first-admission verification and final stage-publication verification
while avoiding repeated processing of the same continuously owned objects in
intervening instruction commits. A source-level calculation for the fixture's
large dependency is approximately 44 publication passes today (8 initially,
then 6 at each of six later publications). Avoiding the five intermediate
instruction repetitions could remove about 30 passes, or 32 GB. This is a
design estimate, not measured savings or a speedup guarantee.

## Required proof boundary

The managed CLI needs a separate closed control path: a concrete atomic
cancellation token and concrete resource Policy, with no arbitrary caller
callbacks. Existing closure-based build, cache, image and BlobStore APIs must
retain their conservative behavior and regression tests.

Export must return an internal owned-checkpoint capability. The engine cannot
construct one merely from a path, digest name, inode or size. The session must
retain read-only handles to admitted physical payloads, with a bounded handle
and metadata budget and conservative fallback when that budget is unavailable.
Every newly introduced path must resolve to the admitted object. New or
independently copied objects still need content validation.

A retained read-only handle is **not** an immutability guarantee. Before reuse
can be implemented, audit and enforce the managed path's complete writer
boundary:

- No arbitrary callbacks or reader implementations may execute inside it.
- Progress, normal forwarding and quiet-mode inherited stdout/stderr must not
  alias a protected payload. Logging is a write, not a read-only observer.
- Workers must inherit no blob handles or mutable blob aliases. Mutable rootfs
  files and public output files must remain separate from archived payloads.
- Successful RUN completion must reap descendants, join forwarding threads and
  finish mount/DNS restoration before publication resumes.
- Every internal operation that can modify a protected object must invalidate
  its evidence. Uncertain effects require conservative verification.

The existing cooperative stable-store/trusted-workload contract still applies.
Store locks do not exclude hostile same-user writes, writable mappings or bind
aliases. Overlay is not an immutability certificate. Neither a new session type
nor a new on-disk schema can substitute for this proof.

## Commit and failure behavior

Hold the existing shared store lease across the build; acquire the publication
lock for each commit, never across RUN. Revalidate provenance, exact link
accounting, capacity and identities under the lock. Parse and hash metadata and
receipts, checking closure, descriptor order/multiplicity, configuration, limits
and pool bindings even when payload evidence can be reused.

Keep first-admission checks, including independent cache-copy validation;
anchor-before-pool durability; ownership-record-before-entry ordering; directory
syncs; no-replace entry publication; and concurrent-winner manifest/receipt
pairing. A losing build retains its own independent output.

Any error ends the session. Retry or restart receives no remembered verification
evidence. Existing winners and objects are checked again. Corrupt anchors remain
errors, unknown crash debris is not adopted, and visible commits are not rolled
back after an fsync failure. Earlier successful instruction commits remain usable.

The first implementation should leave exporter inventory, inherited export
verification, delta decoding, cache-hit validation and independent public-output
verification unchanged. There is no deferred publication queue or retention-policy
change.

## Acceptance gate

Keep all legacy callback-mutation, corruption and healthy-retry tests unchanged.
Exercise the actual new managed path, not a test-only conservative dispatch:
fresh-copy corruption, source/anchor/pool boundaries, repeated descriptors,
between-session corruption, stdio aliases, cancellation and abrupt-exit prefix
reuse, concurrent winners, durability failures, resource limits and public
inode isolation. A gap in writer confinement blocks cross-instruction reuse.

Count payload reads by digest, physical object and verification boundary. Only
after correctness review should frozen release builds run balanced Pod
cold/edit/warm/no-cache comparisons with independent acceptance. Then rehearse
the unchanged large application image. No substantial speedup or full Nemotron
improvement is established by this design document.
