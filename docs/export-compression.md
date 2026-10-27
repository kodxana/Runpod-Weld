# Bounded new-layer gzip export

Builds accept `--compression uncompressed|gzip`. Uncompressed is the default;
layered export remains the default layout mode. Gzip encodes only newly generated
layers with level one. Inherited descriptors, media types, bytes, extensions,
annotations and diffIDs remain unchanged. The library exposes
`rpweld::export::Compression` through `BuildOptions.compression`; existing
standalone `export_layout` and `export_delta_layout` APIs still write raw tar.
Both stage and instruction cache identities include compression. Builder identity
also changes with the executable, covering encoder/backend changes.

Gzip is opt-in: the local random-data benchmark below found roughly 6.8x slower
encoding. Smaller blobs are not a build-speed guarantee; no Pod performance claim
or registry compatibility result is made here.

## Integration contract

```rust,ignore
LayerWriter::new(
    spool.as_file_mut(),
    Compression::Gzip, // default is Compression::Uncompressed
    Limits {
        max_uncompressed_bytes: raw_limit,
        max_blob_bytes: stored_limit,
    },
    cancelled,
)
// Implements Write; use as tar::Builder's sink.
let (_, encoded) = tar.into_inner()?.finish()?;
// encoded.descriptor: stored digest, stored size, correct OCI media type
// encoded.diff_id: SHA-256 of every uncompressed tar byte
// encoded.uncompressed_bytes: includes tar headers, padding, and end markers
```

The exporter substitutes the writer only for new tar/delta bytes and passes
`encoded.diff_id` into config rootfs history and next checkpoint/baseline state. Original base descriptor objects, extensions,
annotations, media types, and blob bytes bypass this helper. Public destination
blobs still need independent inodes; no hardlink to a mutable work/base store.

The build engine uses `image::Limits.max_layer_bytes` for the stored ceiling and
`export::Limits.max_layer_bytes` for the independent raw ceiling. The stored limit
applies to `publish_export` and `layer::verify.max_blob_bytes`; the raw limit applies
to `layer::verify.max_uncompressed_bytes`. Verification uses `encoded.diff_id`,
separate from the stored descriptor digest. Generated gzip headers use a ten-byte
budget. The exporter publishes the index last and drops its owned pending spool on
failure. Partial owned output directories can remain for diagnosis. The helper has
no filesystem paths or publication API.

Gzip uses pinned flate2 1.1.10 / miniz_oxide 0.9.1, level 1, mtime 0, OS 255, no
filename, comment, or extra fields. The exact header is
`1f 8b 08 00 00 00 00 00 04 ff`. Repeated bytes and different input write chunk
sizes produce identical output with this backend and profile. Any future backend,
level, or framing change must be reflected in the parent's output cache identity.

Raw input and stored output writes are capped at 64 KiB each, with cancellation
checks before and after chunks and through finalization. Encoder state is bounded
by the pinned backend; 64 KiB is a transfer bound, not a total RSS claim. Cancellation
is cooperative, not a blocking-I/O timeout. Terminal errors poison the sink so
flate2's drop-time finalization cannot continue writing after failure. Interrupted
ordinary writes can be retried; any failed flush or finish is terminal. A successful
finish flushes the destination but leaves sync, independent verification, and
publication to the caller. The uncompressed path hashes payload once.

## Checked measured space bound

`Compression::max_encoded_size(n)` returns `n` for uncompressed output. For gzip:

```text
2*n + 512*(floor(n / 31744) + 1) + 18
```

All size arithmetic is checked. Feed the measured tar estimate, including
padding/metadata allowances, rather than a configured workload ceiling. This is a
conservative bound for the pinned backend with **no intermediate sync flushes**.
The exporter uses tar writes followed by one finish; calling `LayerWriter::flush`
between writes inserts gzip sync points, so this estimate no longer applies.
The independently enforced stored ceiling still applies to every output byte,
including header/trailer and any sync points.

Source basis in the cached `miniz_oxide-0.9.1/src/deflate/` files:

- `core.rs:2133–2143`: the general path flushes when its LZ buffer is full or a
  sufficiently incompressible block exceeds 31 KiB of raw bytes.
- `core.rs:2298–2346`: the level-one fast path flushes when the LZ code buffer is
  full. `buffer.rs:10` sets that buffer to 65,536 bytes. Literal/match records and
  flag overhead cannot fill it with fewer than 31 KiB of input.
- `core.rs:1777–1876`: block construction and raw/static fallback. DEFLATE literal
  codes cost at most 15 bits per source byte; a match costs at most 48 bits for at
  least three source bytes. The dynamic header, EOB, and alignment fit within the
  512-byte allowance per block. One extra block covers finalization and 18 bytes
  cover gzip framing. This deliberately avoids assuming zlib's `compressBound`.
- `flate2-1.1.10/src/gz/write.rs:112–151,184–189`: explicit finish and automatic
  drop-time finish; the wrapper prevents further sink writes after errors.

`payload_peak(stored, raw, inherited)` computes
`stored + max(raw, inherited)` with checked addition. Verification temporarily
retains the stored new layer plus its raw spool; after dropping that spool, base
blob copies coexist with the stored new layer. The two phases do not overlap.
Count distinct inherited blobs and add directory/JSON/inode allowances separately.
For a flattened path without a verifier spool or inheritance, only the stored
estimate is needed. This helper neither measures nor reserves free disk space.

## Local benchmark evidence

Captured 2026-10-27, base commit `63b716e`, WSL Ubuntu root, Linux amd64,
kernel `6.18.33.2-microsoft-standard-WSL2`, Intel Core i7-11700K @ 3.60 GHz,
16 logical CPUs, `/var/tmp` on local ext4. Rust 1.90.0, Cargo release profile
(`lto = "thin"`, stripped), the existing locked dependencies, no added dependencies.
Other host activity was not controlled. This is not Pod or end-to-end evidence.

Exact Linux environment and invocation (run from this checkout):

```sh
export PATH=/root/.rustup/toolchains/1.90.0-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin
export CARGO_HOME=/mnt/c/Users/Madiator2011/.t3/projects/runpod-docker/.local-tools/cargo
export CARGO_TARGET_DIR=/var/tmp/weld-compression-target
cargo build --offline --release --example bench_export_compression
/usr/bin/time -v /var/tmp/weld-compression-target/release/examples/bench_export_compression 64 3 > docs/export-compression-wsl.jsonl
```

[Raw per-iteration JSON](export-compression-wsl.jsonl) retains every timing and size.
Each synthetic tar contains a 64 MiB regular file. Repeated source/package-like text
represents compressible payloads; deterministic xorshift bytes represent entropy
similar to already-compressed assets. These are bounds-oriented scenarios, not a
sample of real image layer distributions. Fixture generation is outside individual
timings. Iterations alternate mode order and use a fresh owned output directory.

Median of three iterations (milliseconds; CPU includes user and system time):

| Fixture | Mode | Stored bytes | Encode wall | Encode CPU | Verify wall | Verify CPU |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Text | Uncompressed | 67,110,400 | 109.1 | 87.3 | 134.4 | 134.3 |
| Text | Gzip level 1 | 500,340 | 67.8 | 64.7 | 98.2 | 98.0 |
| Incompressible | Uncompressed | 67,110,400 | 80.9 | 60.8 | 108.3 | 108.3 |
| Incompressible | Gzip level 1 | 67,166,984 | 548.4 | 518.4 | 289.9 | 289.8 |

Encoding timing includes reading the prepared tar, hashing, encoding, finalizing,
and syncing the stored file. Verification timing separately uses the real blob and
layer verifier, including writing the raw verification spool. **Neither is full
production publication**: production adds pre-publication verification/sync, source
inventory/tar generation, base copying, OCI JSON/index handling, and checkpoint
work. There is no network or registry transfer measurement. Smaller stored output
alone does not establish faster builds.

The incompressible gzip grew by 56,584 bytes (about 0.084%) and encoding took about
6.8 times the local uncompressed wall time. Keep gzip opt-in. Text's local speed
benefit includes avoiding large stored-file writes and is not a universal gain.

Observed coexisting allocations at the verification phase include the open stored
blob and anonymous raw spool, found through `/proc/self/fd`, deduplicated by device
and inode. Directory/JSON metadata and the prepared input fixture are excluded.
The benchmark writes these payloads monotonically, so their coexisting allocation
is the payload phase peak. Actual filesystem allocation may exceed logical sizes.

| Fixture/mode | Logical payload peak | Maximum observed allocated payload peak |
| --- | ---: | ---: |
| Text uncompressed | 134,220,800 | 134,230,016 |
| Text gzip | 67,610,740 | 67,616,768 |
| Incompressible uncompressed | 134,220,800 | 134,225,920 |
| Incompressible gzip | 134,277,384 | 134,283,264 |

The complete benchmark process used 4.67 s wall, 3.36 s user, 0.98 s system, and
2,748 KiB maximum RSS according to `/usr/bin/time -v`. That total includes fixture
generation and all iterations; RSS is an observation, not an enforced limit.

## Verification boundary

The original isolated test harness still compiles the helper source by path. Tests cover independent raw/stored bounds and exact thresholds,
checked overflow before writes, deterministic headers and repeated/chunked bytes,
partial and interrupted writes, sticky I/O errors, cancellation through footer and
finish, discarded private spools with no blob/index publication, compressed digest
and raw diff ID, corruption/CRC/truncation/suffix rejection, and actual exporter tar
replay with hardlinks, symlinks, permissions, ownership, timestamps, and xattrs.

Production regression coverage includes CLI defaults and both spellings, independent
raw/stored caps through the gzip footer, cancellation with no index publication,
stored digests versus diffIDs, both export modes, cache hits and cross-mode misses,
opaque inherited gzip descriptors and bytes, public inode isolation, cold/warm
checkpoint metadata, measured export space and post-export pre-spool admission.
The original source-path helper harness remains in place.

The engine retains raw-size measurements for one build only, keyed by stored digest,
media type, stored size and diffID. Export returns these measurements with its
manifest; successful imported/cache verification adds its measured size too. Every
later verification (including `verify_fresh_checkpoint`, flattened restore and
cross-stage replay) admits the known raw spool before writing it. All hashes,
parsers and replay budgets are still verified. No unsigned persistent size hint is
trusted. Initially unknown gzip expansion retains streaming limits and cooperative
reserve checks; observations neither reserve disk nor impose quotas.

`tests/fixtures/layered-export/gzip_acceptance.py` is an opt-in local Alpine runtime
fixture. It exercises RUN, whiteouts and replacements, hardlinks, symlinks,
ownership, permissions, xattrs/capabilities, configuration, no-cache stage handoff,
and export/reimport in both modes and both encodings. Its independent Python/GNU
tar oracle compares the complete replayed filesystem, including atime and mtime;
explicit root timestamps are also checked. Run with a fresh native evidence path:

```sh
python3 tests/fixtures/layered-export/gzip_acceptance.py \
  --binary /path/to/rpweld --layout /path/to/offline-alpine \
  --evidence /var/tmp/new-gzip-evidence
```

Integration validation (2026-10-27, WSL Ubuntu root, Rust 1.90.0): the full
`cargo test --offline` suite passed (592 tests, 51 ignored; subprocess self-runs
excluded). The subsequently added parser test and expanded gzip checkpoint-sharing
case also passed, as did all 11 source-path helper tests. `cargo fmt --check`,
`cargo clippy --offline --all-targets --all-features -- -D warnings`,
`cargo doc --offline --no-deps`, and the same strict Clippy check targeting
`x86_64-pc-windows-gnu` passed. The local Alpine fixture at
`/var/tmp/weld-build-cli.Njymxj/base` passed all six runtime/reimport cases, with
logs and results under `/var/tmp/weld-gzip-runtime-38d9-v1`. The full replay comparison
passed without timestamp exclusions, including the explicit root timestamps.
No Pod, registry, push or release checks were performed for this integration.

The following validation counts describe the original isolated helper, before
production integration:

Completed on the stated WSL toolchain: `cargo fmt --check`,
`cargo clippy --offline --all-targets --all-features -- -D warnings`,
`cargo doc --offline --no-deps`, and `cargo test --offline` (588 passed, 50 existing
ignored, zero failed). After adding two further cancellation/finalization tests,
the final focused `cargo test --offline --test export_compression` passed all 11;
Clippy and formatting were rerun clean. Ignored platform/runtime/network fixtures
were not enabled. No cloud, push, or release operation was performed.
