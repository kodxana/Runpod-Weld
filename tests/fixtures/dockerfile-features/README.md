# Dockerfile feature oracle

`oracle.py` uses Python's standard library and the local Docker daemon. It creates
disposable scratch images, inspects config, and exports stopped (never started)
containers to inspect tar ownership, modes, directory types, and file contents.
Every command has a 45-second timeout. Images and containers are removed in
`finally`; the daemon's build cache is deliberately not globally pruned.
No syntax directive, base-image pull, user Docker config, registry credentials,
RUN command, or cloud resource is used. Docker config lives in a temporary directory.

Recorded engine/client: **Docker Engine Community 29.7.2**, Linux amd64,
2026-10-25. `docker-oracle.json` contains the inputs and actual expectations;
the candidate implementation is not imported or invoked by the generator.
Refresh with `python3 tests/fixtures/dockerfile-features/oracle.py` under Linux.
Review version changes and changed observations rather than automatically blessing them.

Primary references consulted on 2026-10-25:

- https://docs.docker.com/reference/dockerfile/ (ARG, COPY, SHELL, CMD, ENTRYPOINT, LABEL)
- https://github.com/moby/buildkit/blob/master/frontend/dockerfile/dockerfile_copy_test.go
- https://github.com/moby/buildkit/blob/master/frontend/dockerfile/dockerfile2llb/convert.go
- https://github.com/moby/buildkit/blob/master/solver/llbsolver/ops/user_linux.go
- https://github.com/moby/buildkit/blob/master/client/llb/fileop.go

## Version-specific behavior and intentional differences

The task explicitly selected parity with the observed Docker 29.7.2 behavior:

- Empty wildcard matches, including matches eliminated by `.dockerignore`, are
  accepted as no-ops. A literal missing path is a different operation.
- Missing passwd/group files or missing names on a materialized filesystem leave
  the corresponding IDs at their resolver defaults, instead of rejecting the build.
  An unknown name against untouched scratch fails with `invalid user index: -1`.
  This differs from
  the Dockerfile reference's stated rejection behavior. Do not silently replace
  these expectations with stricter candidate behavior.
- Multiple wildcard matches into a destination without a slash overwrite that
  file in match order (the recorded `a.txt`, `b.txt` example finishes with `B`).
- `root` is special-cased to numeric zero. The `named_image_account` fixture uses
  `nobody` with image-local UID 12345 and GID 23456, plus group `qa` with GID 34567,
  to detect accidental lookup on the host.
- Stage COPY without chown preserves the source owner; context COPY defaults
  to root. A new directory-copy destination root defaults to 0755, while its
  copied nested directory permissions are retained. Explicit chmod changes both.
- A later SHELL changes the image's Shell field but does not rewrite command
  arrays already captured by earlier shell-form CMD/ENTRYPOINT instructions.

Tests compare selected config fields (not timestamps/history/default PATH), and
accept absent/null/empty representations of empty command/map defaults. File
assertions use separately verified/replayed OCI layers, not the builder work tree.
These are deliberate normalization/coverage limits, not claims of byte-identical
Docker images. Symlink, timestamp and RUN execution coverage belongs to other
suites; this suite does not execute the fixture's intentionally nonexistent shells.

## Candidate suite

Run `cargo test --test dockerfile_features -- --test-threads=1` as Linux root,
with an isolated `CARGO_TARGET_DIR`. Each builder subprocess has a 25-second
deadline and its own output, work directory and store. The local-layout inheritance
case supplies a known config directly through the existing OCI exporter and uses
`--base local=LAYOUT`; no candidate build is used to establish its base expectations.

Two tests remove CAP_CHOWN from the child builder's effective, permitted,
inheritable and bounding sets, verify its absence, and set no-new-privileges.
One requires chmod on an owned file to succeed; the other requires arbitrary
ownership changes to fail with an explicit permission diagnostic and no output
image. Ordinary WSL root success is **not** evidence that a Runpod Pod permits
chown. These tests require CAP_SETPCAP in the runner to drop the bounding bit;
setup failure is an error, never a passing/skipped test.

Compilation was initially deferred while the shared production implementation
was being edited. See the QA handoff for the actual compilation/test result.
