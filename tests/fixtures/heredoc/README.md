# Independent heredoc oracle

Prepared on clean `c01e1becdb806f1ab26f9ad7a65cbe675114fdbb`.
No production modules are imported by the CLI assertions: files are read directly
from OCI layer tar records. Tests accept an absolute `RPWELD_TEST_BINARY` pointing
to the parent's current binary; absent that, Cargo's test binary is used.

## Pinned local oracle

Measured 2026-10-25 on Linux/amd64 with Docker Engine **29.7.2**
(server `6a43e3d`), BuildKit **v0.32.2**, buildx **v0.36.1**
(`1d8dde89b8aba914e05e45366770736fea1fd690`), bundled Dockerfile frontend.
There is no `# syntax=` directive and no frontend download. The existing Alpine
OCI manifest was `sha256:dc92f017beea8e7f43263073d717f7bc011228c95d5312e440deb4d035bb4eec`,
with rootfs diff ID `sha256:be64570a34e4c5e361d1f5d9cb42b851e7f9a33a61f91c335b287c1c7868f921`.
The script imports a uniquely tagged copy of the index if `RPWELD_TEST_LAYOUT`
is provided, or uses an already present `HEREDOC_DOCKER_BASE` tag. No pulls,
pushes, global prune, or credentials are involved. It retains its local tag and
native `/tmp/weld-heredoc-oracle-*` directory for inspection.

Primary sources:

- [Dockerfile heredocs](https://docs.docker.com/reference/dockerfile/#here-documents)
- [BuildKit v0.32.2 conversion source](https://github.com/moby/buildkit/blob/v0.32.2/frontend/dockerfile/dockerfile2llb/convert.go)
- [BuildKit v0.32.2 parser](https://github.com/moby/buildkit/blob/v0.32.2/frontend/dockerfile/parser/parser.go)

The version-pinned source links identify the implementation to compare; exact
expectations below come from direct local builds, not assumptions about source.
`oracle-observations.json` records tar bytes, hex, SHA256 and numeric metadata.
Tar export is necessary: Docker's local exporter remaps file ownership, and
Python `read_text()` normalizes CRLF. Neither is a valid byte/owner oracle.

## Findings and bounded contract

- Unquoted COPY expands `$VALUE` and `${VALUE}` even inside literal single-quote
  characters, preserves those quote characters, and turns `\$VALUE` into literal
  `$VALUE`. Any quoted delimiter component disables this expansion.
- `<<-` removes leading tabs from body and delimiter, preserving spaces.
- CRLF headers and closing delimiters are accepted; body CR bytes are preserved.
  LF body `body\n` has hex `626f64790a`, SHA256
  `9e2ec912af5dff2a72300863864fc4da04e81999339d9fac5c7590ba8a3f4e11`.
  CRLF body `body\r\n` has hex `626f64790d0a`, SHA256
  `0a4e52a11356529491e17d023afed1e6e6f6a544ed97ac73e1d4c5cfefa38b83`.
- Bare RUN executes its body through the current SHELL even when the delimiter is
  quoted. ARG/ENV and numeric USER remain effective. The fixture's LF output is
  `environment\n$VALUE\n1234\n2345\nstrict\nenvironment\n`. The same fixture with
  CRLF fails its `/bin/sh -eu -c` syntax; this is not a claim that every CRLF
  shell body fails.
- Default inline COPY mode/owner is 0644 and 0:0. Explicit options produce 0751
  and 1234:2345. Weld deliberately fixes generated-file mtime at zero for stable
  cache identity; Docker's observed timestamps are build-time values. Timestamp
  zero assertions are Weld's deterministic metadata contract, not Docker parity.
- Missing delimiter identifies opening line 3. An unknown instruction after a
  closed body identifies physical line 5.
- Docker accepts multiple COPY heredocs, shebang RUN and command-bearing RUN.
  Weld intentionally rejects these, fd prefixes, ADD/ONBUILD heredocs, mixed
  context/inline COPY, non-identifier delimiters and unsupported variable modifiers.
  The rejection test is separate from successful parity tests.

## Running

Run `oracle.py` under Linux with Docker available and either of the local-base
environment variables above. It prints the artifact directory and saves complete
Docker logs and tar archives there. It checks expected success/failure and runs
warm, ignored-context, changed-body and `--no-cache` Docker builds.
The completed local run at `/tmp/weld-heredoc-oracle-x5pn11b2` observed COPY
cache-hit counts 5, 5, 4 and 0 respectively; changed-body and bypass both exported
`changed\n`. The recorded byte/metadata snapshot is from the preceding identical
semantic run at `/tmp/weld-heredoc-oracle-sg96b8g_`.

Set `CARGO_HOME` and `RUSTUP_HOME` to the existing toolchain directories, then run
`sh tests/fixtures/heredoc/check.sh` for focused Linux and Windows clippy. The
Windows check excludes these Linux-only runtime tests by cfg; it is not Windows
runtime coverage. Target artifacts default to `/tmp/weld-heredoc-oracle-target`.

After parent integration, run as Linux root on native Linux storage:

```sh
export RPWELD_TEST_LAYOUT=/absolute/path/to/existing/alpine-oci
# Optional: export RPWELD_TEST_BINARY=/absolute/path/to/parent/rpweld
cargo +1.90.0 test --offline --locked --test heredoc_cli -- --include-ignored --test-threads=1
```

Every CLI build uses its own temporary managed store and explicit `-t`; repeat
tests require actual cache diagnostics, and bypass tests reject cache diagnostics.
Tighter byte-budget tests first prove a populated cache exists. Changed body,
ARG and quoting outputs are compared to fresh execution. Fixture files use LF;
CRLF and mixed-ending cases are generated explicitly by the test.
