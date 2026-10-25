# Independent USER QA

All accounts are synthetic. The runtime fixture is shared by the Docker oracle
and CLI test; it asserts kernel-observable identity, created-file ownership,
permission denial, groups, HOME and working-directory behavior. No implementation
resolver is imported into the expectations.

## Run

On an authorized Linux amd64 root host, using an existing local Alpine OCI image:

```sh
RPWELD_TEST_LAYOUT=/var/tmp/weld-build-cli.Njymxj/base \
  cargo test --locked --offline --test user_cli -- --include-ignored --test-threads=1
python3 tests/fixtures/user/oracle.py \
  /var/tmp/weld-build-cli.Njymxj/base .research-private/user-qa
```

The CLI tests use isolated temporary stores. Each build has a 20-second RUN
timeout and a 120-second subprocess deadline that kills its own process group.
Capability tests remove CAP_SETUID or CAP_SETGID from the child bounding set;
CAP_SETPCAP is required to perform that test. Parent credentials are untouched.
The capability case first proves the same application succeeds with capabilities.
Missing capabilities and unknown names must fail before the application starts.

Cache tests change USER, passwd UID/primary GID and supplementary group records,
then verify output identity. They do not infer cache hits from random nonces or
assume extraction preserves all pre-state identity. They test correctness when
cache is enabled, not hit-rate performance.

The Docker script requires already installed Docker and skopeo. It imports only
the supplied OCI base, builds with no network and no pulls, and removes only its
own image references. It does not prune shared caches. Full version, base image,
build diagnostics and cleanup evidence are written under the requested ignored
evidence directory. Docker reference evidence is not evidence that Weld passed.

## Oracle

Validated locally 2026-10-25 with Docker Engine 29.7.2, Buildx 0.36.1,
containerd 2.3.3 and runc 1.4.3. All five Docker cases passed: complete runtime
matrix, unknown-name metadata, unknown user at RUN, unknown group at RUN, and
stage metadata inheritance. The exact base image identity and diagnostics are in
`.research-private/user-qa/docker-oracle.json`.

Primary specification: https://docs.docker.com/reference/dockerfile/#user
(USER controls subsequent RUN identity; an explicit group excludes supplemental
memberships; absent primary group defaults to root). COPY numeric ownership has
different default-group semantics: https://docs.docker.com/reference/dockerfile/#copy---chown---chmod.
HOME and WORKDIR ownership expectations are additionally verified by the actual
Docker runtime fixture rather than assumed from the concise Dockerfile reference.

No registry push, dependency installation, Pod/cloud execution or private account
data is involved. Weld runtime certification requires the final stable production
snapshot and a successful opt-in suite; compilation alone is insufficient.

The root-directory regression additionally runs builder children under umasks
022 and 077 without changing the test runner's process-wide umask. A base without
a root tar header must start at 0755; explicit 0755/0700 root headers must survive
export and reimport. Explicit 0700 must still deny non-root execution. Private
outer work directories must remain 0700 under umask 077.

After a stable build, repeat the real runtime fixture offline on Linux-native
storage (requires root, Python 3 and timeout; no Rust toolchain needed):

```sh
sh tests/fixtures/user/run-umask-acceptance.sh \
  /absolute/rpweld /absolute/local-alpine-oci /var/tmp/new-user-umask-check
```

The script checks both umasks, repeat builds, stage inheritance, inherited OCI
base runtime, exported root tar mode and published cache-checkpoint root modes.
