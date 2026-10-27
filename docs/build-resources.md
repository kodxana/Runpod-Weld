# Managed build resources

`rpweld build -t NAME .` checks current disk/inode availability before acquiring a Dockerfile source lease or creating build state. Dockerfile reads inside a managed store still require a lease; plan-dependent sizing and validation happen after that read and can leave the persistent `store.lock` in place on later refusal. Resource changes between observations can also cause later refusal. `--max-rootfs-bytes`, `--max-layer-bytes`, `--metadata-budget`, and `--max-entries` override their respective ceilings exactly. Smaller explicit ceilings are never enlarged. Explicit output/work builds without tags retain legacy defaults.

Disk sizing observes the actual work, output and store filesystems, including their nearest existing ancestors when paths do not yet exist. Shared-device estimates are added together. The policy rounds allowances down to powers of two based on filesystem capacity, so fluctuating free space does not change cache policy. It deducts a reserve of 5% of capacity, bounded to 256 MiB–4 GiB, and a 5% inode reserve bounded to 128–65536. Automatic bytes are capped at 1 TiB and entries at 16 million (further constrained by inode capacity and logical metadata). These are planning bounds: filesystem totals can be shared host capacity, quotas are unknown, and no space is reserved.

Stable workload sizing counts per-operation destination roles: work root plus spool (two copies), public output (one), and store payloads only when used. The store allowance is three copies when intermediate stages write root/spool/image there, two for external COPY roots, registry base storage or enabled instruction caching, and zero for bookkeeping/tag-only use. Shared-device roles are summed. A single scratch `--no-cache` build with explicit work/output elsewhere therefore is not limited by the store's payload capacity, while store bookkeeping still needs free bytes/inodes. Selected-stage and external-image counts are advisory retention information, not multipliers that assume every stage reaches the full ceiling. Retained stages and instruction checkpoints can grow beyond a single-operation allowance; this is not a peak-usage estimate or full-build fit guarantee. Measured additional writes and current resources must be checked at engine boundaries. Rechecks sum simultaneous additional allocations on the same filesystem, retain reserves, and refuse with operation, required and available quantities and the observation source. An arbitrary RUN or competing writer can still exhaust resources between observations.

Logical metadata charges count headers, paths, xattrs and bookkeeping; they are neither RSS nor disk bytes. A provisional automatic heuristic takes the observed cgroup operating ceiling, subtracts a sizing margin of max(128 MiB, 25%), divides by 16, bounds the result to 1 MiB–4 GiB and rounds down to a power of two. The divisor allows room for simultaneous inventories and allocator overhead; it is not a calibrated RSS conversion, allocatability proof or OOM guarantee. For example, a 50 GiB observed ceiling gives a 2 GiB logical allowance. Missing/ambiguous cgroups stay unknown and use a labelled finite 64 MiB logical fallback; large workloads may need an explicit metadata ceiling. Host RAM totals are never substituted. Operating memory headroom is advisory: `memory.high` is a pressure threshold, and `memory.current` can include reclaimable page cache. Saturated headroom never refuses or aborts a build, including builds with explicit tiny budgets.

Large workload metadata never enlarges untrusted image JSON bounds (16 MiB/document, 64 MiB total), evaluated-plan bounds (16 MiB), descriptor count (1024), gzip header bound (64 KiB), individual PAX/GNU extension payloads (16 MiB), or existing parser/depth limits. A smaller explicit metadata ceiling also constrains these subsystems. NOFILE is observed for diagnostics, with no global minimum: scratch builds without caching need not replay any layer. When replay occurs, the existing replay code calculates exact pinned FD demand and may raise soft NOFILE only within the existing hard limit. Diagnostics describe unknown observations, auto/explicit origins and reserves even with `--progress quiet`.

Managed engine operations recheck disk/inode reserves through the existing cancellation path at most once per second when polled. Crossing a reserve stops a RUN and its traced descendants, records failure, and reports the capacity reason. This is cooperative monitoring, not a disk quota: a fast allocation can fill a filesystem between polls. Cgroup memory pressure remains advisory and does not trigger this cancellation.

Before replay, layout copying, checkpoint publication and export, the engine checks the additional allocation estimated from verified entries or the existing export inventory. Export estimates count regular hardlink payloads once, include tar records and padding, and account for independent base-blob copies in layered output. Compressed expansion that is not yet known relies on the configured decompression limit and periodic reserve checks. Estimates and current-space checks do not reserve storage; retained partial work remains available for diagnosis and normal explicit cleanup after a failure.


RUN package caches use the same rootfs byte/entry ceilings and layer metadata
ceiling, both for the complete persisted package namespace and each RUN's
materialized cache data. Measured copy-in/out admission includes payload bytes,
per-entry filesystem allocation allowance and inode counts, and uses the actual
write destination. Mount growth is checked cooperatively once per second while
RUN executes; fast writers can exceed a ceiling between polls. Publication is
rejected if the stable post-RUN inventory exceeds it. Temporary copy-out retains
the old cache until atomic replacement, so old and new payloads coexist; measured
admission charges the full new allocation. This remains a resource policy, not a
hard disk quota. Details are in [RUN mounts](run-mounts.md).

For opt-in gzip export, the measured tar estimate is passed through the encoder's
checked stored-size bound. Layered payload admission is
`stored + max(raw, inherited copies)`, plus directory/JSON/inode allowances: the raw
verification spool is released before inherited blob copies start. Flattened export
admits the stored estimate alone at export time. Private checkpoint hardlinks do not
reserve another inherited payload; public outputs always copy into independent inodes.
The raw exporter ceiling and stored image ceiling remain independent.

Raw sizes learned during encoding or successful verification stay in a process-local
map bound to the stored digest, media type, stored size and diffID for the current
build. Later checkpoint verification, flattened restore and cross-stage replay admit
that known raw spool before creating it, even for gzip. The already-written stored
blob is reflected in current free space, so that later check adds only the raw spool.
Unknown imported/cached gzip continues using streaming limits and cooperative reserve
checks. No persistent unsigned raw-size hint is trusted, and reserves are unchanged.
