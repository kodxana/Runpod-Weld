# Managed publication evidence

This implementation supplies the private publication-session slice of
[the checkpoint design](checkpoint-verification-design.md). Engine dispatch and
the complete worker/output boundary are separate prerequisites; this change
alone does not enable the CLI optimization or establish a runtime speedup.

`ManagedCache::publication_session` borrows the store lease through the cache
and borrows concrete `ManagedControl`. `publish_instruction` accepts only the
exporter's private `OwnedCheckpoint`, which attests closed writers and pins the
layout directories. It does not attest payload contents. The session validates
those directories before and after source bindings. Its only cancellation
closure performs concrete progress ticks and resource polling. Sticky control
errors retain the original stopped-operation error. A successful publication
does not run a new resource observation that could revoke success.

Each successful instruction still completes the same cache-v2 publication
transaction, fsyncs and no-replace rename. There is no deferred queue, new cache
format, runtime hash memo in public callback APIs, or persistent trust record.
The public cache, BlobStore and image loader retain their conservative behavior.
The image loader shares its metadata parser internally; it still hashes every
payload in the same order.

Only layer payloads can receive evidence. Source and independent cache copies
have distinct entries keyed by digest and physical identity and retain read-only
CLOEXEC file handles. A digest or matching inode/size never creates evidence.
Evidence is created only after a complete hash of that exact object. Every new
path is opened without following symlinks, checked against actual held output
sinks, and bound to the held regular-file identity and expected size. Detected
mtime changes invalidate the operation; mtime is an additional change detector,
not an immutability certificate. Cooperative peer hardlinks can change ctime and
link count without invalidating content evidence; existing provenance and exact
link audits still run under the publication lock.

New evidence cannot be reused within its first publication, including repeated
descriptors. This preserves source hashing, streamed ingest, fresh-copy readback
before ownership, anchor-before-pool durability, and final pending-layout/pool
hashing. Only a later instruction can reuse it. Metadata JSON, receipts,
descriptor ordering/multiplicity, size/count limits, closure, ownership and link
accounting remain fully validated on every commit. Winners clear reuse and
fully verify both the current source and winning entry. Cache lookup is unchanged.

Retention is capped by twice the configured descriptor limit, 1,024 handles,
and the metadata budget charged at 512 bytes per retained object. Each retention
and publication checks the current soft RLIMIT_NOFILE and current open descriptor
count, preserving 272 handles of worker/export/I/O headroom. Missing observations,
exhausted budgets and inability to clone an optional handle discard evidence and
select full verification. They do not themselves fail a cache publication.

Any publication error ends the session and drops evidence. Explicit invalidation
also ends it; further publications fail. Dropping the stage session releases all
handles. The engine must invalidate/drop before unknown effects, retries, stage
end and final-stage publication, then use the existing conservative final
publication API. No evidence survives a restart. These properties rely on the
documented cooperative stable-store/trusted-workload contract, not isolation
against hostile same-user writes, mappings or proc aliases.

The focused tests use the actual managed dispatcher and exporter/control test
constructors. Named fault points run only in managed payload verification and
cover before-read, after-buffer-read and after-verification mutation. They cover
new and previously pooled objects, repeated descriptors, fresh-copy healthy
retry, later-blob exclusion, retained-path and directory substitution, full final
verification, between-session corruption, winner pairing, durability, cancellation,
checked output aliases, metadata/FD fallback, pruning and public inode isolation.
The existing 31 shared-cache regression assertions are unchanged.

Measured local hash counts for a 4 KiB payload are eight for its first managed
publication, zero for a subsequent publication of the same retained source and
cache objects, and six for conservative final publication. Four repeated
descriptors produce 29, zero and 27 respectively. Per-object/boundary assertions
attribute the initial single-descriptor case to three source reads (including
streamed ingest) and five cache-copy reads. A newly copied source object with an
already retained digest is hashed independently. These are deterministic unit
read counts, not a measured end-to-end throughput improvement; broader engine,
independent review and Pod acceptance remain the parent integration gate.
