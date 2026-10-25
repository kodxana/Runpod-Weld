# Layered export acceptance

These fixtures use native Linux paths, root, Python's standard library, GNU tar,
and an existing local Alpine OCI layout. No pull or package installation occurs.
RUN is trusted test code, not a sandbox. Invoke candidate tests only after the
parent supplies a frozen binary/source handoff.

Fixture input archives use `fixture_tar.py`: raw ustar name fields preserve
`probe/raw-0xff` byte-for-byte, while local PAX records carry supported timestamps
and xattrs. Python's automatic `hdrcharset=BINARY` extension is deliberately not
emitted. Ordinary GNU headers are avoided because they introduce ctime fields.
Symlinks use Linux's actual mode `0777`. Both the old-encoding baseline rejection
and new-encoding baseline/frozen-candidate no-op setup acceptance were reproduced;
these setup checks are not a full candidate acceptance verdict.

`measure.py` reuses the existing offline Python/Node instruction-cache fixtures.
These simulate dependency ordering; they do not install pip/npm dependencies or
run the languages. Each language has its own empty managed store, then warm and
app-only-edit builds. Every build passes `-t` to actually enable managed caching.
Logs assert warm/dependency hits. Commands, manifests, binary SHA256, base-index
SHA256, revision, and raw measurements are retained in the evidence directory.

Example (new native Linux evidence directory required):

```sh
python3 tests/fixtures/layered-export/measure.py --binary /tmp/frozen/target/debug/rpweld \
  --source /tmp/frozen/source --layout /tmp/alpine --evidence /tmp/baseline-new \
  --revision FULL_COMMIT --mode legacy
python3 tests/fixtures/layered-export/oracle.py
python3 tests/fixtures/layered-export/acceptance.py --binary /tmp/frozen/target/debug/rpweld \
  --layout /tmp/alpine --evidence /tmp/layered-new --docker
```

Use `--mode flattened` / `--mode layered` for a candidate comparison. `legacy`
omits the new flag so the immutable old baseline can run. Measurements are single
samples, not speedup claims. Cold means an empty managed cache, not cold OS page
cache. Logical bytes sum lstat sizes (including directories/symlinks); allocated
bytes sum `st_blocks * 512`, once per device/inode. This does not detect shared
reflink extents. Output/work/store and all-retained scopes are separate. New blob
bytes mean digests absent from the preceding build, not a network transfer metric.

`oracle.py` verifies descriptor size/SHA256, uncompressed diff IDs and non-empty
history counts when history is present. It processes whiteouts before each layer,
then applies ordinary entries in archive order with GNU tar and `--numeric-owner`.
Each ordinary replacement happens at its own entry; a preceding hardlink retains
the old inode. Existing directory headers replace xattrs without deleting children;
untouched directories retain their xattrs. Explicit PAX atime is restored
separately because GNU tar only restores mtime. When an entry omits atime, replay
uses its archived mtime (including PAX fractions). This is a deterministic test
replay convention matching the product, not an OCI requirement to encode atime.
It prevents extraction wall-clock time from influencing independent comparisons;
explicit atime and mtime remain exact. Surviving explicit directory
timestamps are restored after children, and a missing root header preserves the
lower root timestamps. Snapshot includes content hash, mode/type, ownership, atime/mtime in ns,
xattrs, symlink target, and hardlink equivalence classes. ctime is not restorable.
Snapshot captures metadata for all entries before reading any content or link
targets, enumerating directories without following symlinks. This preserves the
pre-read metadata of inode aliases. Reading link targets can still advance live
symlink atime: snapshot never restores timestamps, which would itself change
ctime. Compare first observations of separate fresh replay trees, or reuse a
saved snapshot; a later observation describes the current, possibly changed tree.
The populated-cache comparison observes only OCI directories and regular files,
whose enumeration/content reads use O_NOATIME, rather than replayed symlinks.
Timestamp setting occurs only during disposable replay initialization, including
preserving lower root timestamps when the upper layer has no root header.
This is a trusted-fixture oracle, not an untrusted archive extraction service.

Run `python3 -B -m unittest -v test_oracle` from this directory for no-builder
timestamp regressions: identical four-entry replays, omitted and explicit
fractional times, hardlink aliases, missing-root preservation, and first/repeated
symlink observations without ctime mutation. Run `python3 -B oracle.py` for the
existing changeset/xattr/capability self-test as well.

The executed standalone self-test covers opaque whiteouts, deletion,
file-to-directory replacement, ordered lower-inode hardlinks and splitting,
symlinks, directory xattr deletion with child retention, conflicting text/numeric
owners, permissions, atime/mtime, a missing upper root header, raw byte names,
security capabilities, invalid history and same-size corrupt blobs.

Prepared CLI acceptance covers descriptor annotations, unchanged base bytes/diff
IDs and history prefix, explicit root metadata, cumulative delta size, metadata-only
and mutating inherited stages, both cache-format directions, fresh and populated
no-cache bypass, both cache namespace versions, explicit expected content/modes/
owners/timestamps/config, budgets, RUN cancellation, and same-size corruption of
accessed original-base and populated-checkpoint paths. Cache corruption targets
all cached non-base layer inodes, not an arbitrary entry; originals are restored
in `finally`. Run these candidate/Docker checks only against a frozen handoff.

The unchanged 128 KiB app-edit budget applies to a separate real managed
`FROM fixture; COPY app /probe/app` workload: cold, unchanged warm, edited app,
and no-cache. Every case verifies base descriptors/diff IDs/bytes/history and
config, exact app contents, and exactly three delta paths (`.`, `probe`,
`probe/app`). The full unchanged tree, including explicit root metadata, must
remain equal to a fresh base replay. COPY changes `probe` directory times and
sets app times; these are compared exactly with the retained build filesystem,
not normalized across independently executed builds. Cold/warm full snapshots
must match. Warm does not rewrite its input and must hit the COPY checkpoint.

The rich RUN workload retains its exact metadata/content assertions, cache and
failure coverage. It records actual delta bytes in `delta-sizes.json` and checks
a separate accounted bound: original sizes of the independently identified RUN
inputs (BusyBox, musl loader, passwd), literal fixture payload lengths once per
emitted inode, plus 4 KiB per allowed entry for tar/PAX/padding and 10 KiB for the
end record. An explicit path allowlist rejects unrelated base files; emitted
existing nondirectories must actually differ from the base snapshot and unchanged
directories must be required ancestors. RUN inputs must retain every field except
their access time. This check diagnoses atime changes; it does not exclude atime
from existing exact replay or rich fixture comparisons.

Exact atime can legitimately make RUN recopy unchanged executables and their ELF
loader. A real `COPY` versus `COPY; RUN true` acceptance control requires identical
binary contents/other metadata, changed atimes and full binary payloads only in
the RUN delta. The exported cumulative baseline is FROM, not the previous app
build. There is no generic claim that app edits followed by RUN fit under 128 KiB.
The previous rich app-edit failure (1,515,008 bytes versus 128 KiB) remains in the
preserved diagnostic evidence; this correction separates the two contracts.

CLI cancellation is synchronized to a marker inside RUN. It does **not** prove
cancellation during serialization or publication. No deterministic export-phase
CLI hook is available, so that independent CLI coverage is deferred. Production
exporter unit tests may exercise their cancellation closure separately; this
fixture does not claim to have run or verified those tests. Missing-root coverage
is currently an independent replay regression, not a candidate missing-root test.

No broad timestamp exception is allowed. The rich fixture gives the base root
explicit subsecond timestamps and requires exact no-op preservation. Mutating
builds explicitly normalize touched paths and root timestamps before comparing
cache/no-cache. Unspecified freshly created root timestamps can legitimately
differ across separate builds; a future fixture relying on them must identify
that exact origin rather than erase root timestamps from every comparison.

Docker acceptance loads the OCI archive locally, compares ordered diff IDs and
config, creates/exports a container, compares probe content/type, permissions,
ownership, mtime, symlinks, hardlinks and deletions, and executes the configured
command to verify edited app content. Export evidence is retained. Docker export alone is not used to
claim atime/xattr fidelity; those are checked by independent replay.
It uses the reference returned by `docker load`, rather than assuming a config
digest is a Docker image ID. Container execution disables networking.

Rust entry points live in `tests/layered_export_cli.rs`. Runtime cases are ignored
unless explicitly selected. Set `RPWELD_TEST_LAYOUT`, a new native path in
`RPWELD_LAYERED_EVIDENCE`, and optionally `RPWELD_LAYERED_DOCKER=1`.
