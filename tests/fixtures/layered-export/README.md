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
separately because GNU tar only restores mtime. Surviving explicit directory
timestamps are restored after children, and a missing root header preserves the
lower root timestamps. Snapshot includes content hash, mode/type, ownership, atime/mtime in ns,
xattrs, symlink target, and hardlink equivalence classes. ctime is not restorable.
This is a trusted-fixture oracle, not an untrusted archive extraction service.

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
in `finally`. These candidate/Docker checks remain unexecuted until frozen handoff.

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
