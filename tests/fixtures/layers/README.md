# Independent layer format fixtures

Producer: **CPython 3.12.3**, standard-library `tarfile`, under WSL.
GNU tar 1.35 was available but was not used to produce these archives.
No Rust `tar::Builder`, external downloads, or Go runtime is used.

`generate.py` uses Python's PAX/GNU writers for normal archives and Python's
USTAR header writer plus explicit byte framing/mutations for adversarial cases.
Regenerate explicitly with `python3 tests/fixtures/layers/generate.py`.
Cargo tests consume the checked-in archives; Python is not a test dependency.
`manifest.json` records exact sizes, SHA-256 digests, and expected metadata.
Each binary is capped at 32 KiB and their combined size at 128 KiB by both
the producer and integration tests. No large-file download or hash is performed.

The fixtures exercise normal PAX long paths/linkpaths, IDs above octal capacity,
negative fractional times (-1.250000001 and -0.000000001), GNU ordinary/L/K
headers, positive base-256 IDs and negative base-256 mtime, and hardlinks to
earlier, later, and lower-layer paths. Payload reads use verified spool offsets.
The PAX size override is 513 over a raw size of 1, crossing a block boundary;
the following sentinel must remain correctly aligned. Binary SCHILY xattr data
contains LF, NUL, equals, and a non-UTF-8 byte.

Reject fixtures cover malformed PAX length/delimiter records, dangling x/L/K,
semantic global PAX, PAX/GNU sparse encodings, and 12-byte base-256 size/mtime
overflow whose low eight bytes are zero. The repeated-comment metadata flood
must succeed with the normal budget and return `Limit("metadata bytes")` with
a 4096-byte budget; rejecting all extensions cannot satisfy this test.

API contract: `verify` returns seekable `VerifiedLayer` entries; `EntryKind`
includes `Hardlink`; `Timestamp { negative, seconds, fraction }` represents an
exact signed decimal magnitude with ASCII fractional digits; `xattrs` maps
byte names (without `SCHILY.xattr.`) to byte values. Hardlink targets are
preserved, not resolved during verification. All fixture success assertions
are mandatory; none are ignored or conditional on format support.

Validation command (WSL, workspace-local toolchain):

```sh
export CARGO_HOME="$PWD/.local-tools/cargo" RUSTUP_HOME="$PWD/.local-tools/rustup"
.local-tools/cargo/bin/cargo test --offline --test layer_formats
```

Validated 2026-10-24 with `rustc 1.90.0 (1159e78c4 2025-09-14)`:
**10 passed, 0 failed, 0 ignored**, including the typed timestamp and xattr
assertions. The 21 checked-in tar files total **91,136 bytes**.

Only this focused integration target is covered here. Multi-member gzip,
8-GiB payloads, extraction, and filesystem hardlink creation are not tested.
