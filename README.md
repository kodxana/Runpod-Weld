# Runpod Weld

`rpweld` is a standalone Rust project for building OCI/Docker images inside ordinary Runpod Pods. It has no Kaniko runtime dependency.

**Development preview:** experimental multi-stage builds from registry images, local OCI images or scratch are available on Linux amd64. Authenticated pulls/pushes use Skopeo. Named stages, COPY --from, target selection and local completed-stage caching are supported. A container run command is not implemented. Trusted workloads only; this is not a security sandbox.

## Build, tag and publish

```sh
rpweld build -t myuser/my-app:latest .
rpweld login docker.io
rpweld push myuser/my-app:latest
# Or build and publish together:
rpweld build -t ghcr.io/myuser/my-app:latest --tag=ghcr.io/myuser/my-app:v1 --push .
rpweld logout docker.io
```

Repeat `-t` / `--tag` to name the same build output (up to 64 occurrences).
`--tag=NAME` also works. Tags are normalized and validated before reading the
Dockerfile or pulling; normalized duplicates are ignored in first-seen order.
A failed build leaves old tags intact. Successful local tag writes are atomic
individually, **not** a transaction across all tags. `--push` attempts every tag
from this build's retained, verified output, reports each success/failure, and
returns failure if any push fails. Retry with `rpweld push TAG`; that command
uses the current local tag, which another build may have replaced.

`--progress=auto|plain|quiet` (or `--progress MODE`) controls engine progress.
`auto` is the default and currently equals `plain`: append-only stderr lines,
without terminal redraw. Stage numbers follow Dockerfile order; step numbers
are stage-local instruction ordinals for FROM/COPY/RUN/WORKDIR, so gaps denote
metadata instructions evaluated with the next boundary or final export.
Lines show operation names, start/completion, verified cache hits and elapsed
seconds; instruction arguments are omitted. A whole-stage hit summarizes all
instructions. `quiet` hides these engine lines only: RUN stdout/stderr stream
unchanged, and diagnostics, registry transfer output and final results remain
visible. These modes do not change cache identity. RUN can itself print secrets;
progress does not echo Dockerfile arguments or environment values.

The default Dockerfile is `CONTEXT/Dockerfile`. Short image names resolve explicitly to Docker Hub (`ubuntu:24.04` becomes `docker.io/library/ubuntu:24.04`). FROM images reuse fully verified local bases for Linux amd64 and pull on a miss; `--base NAME=LAYOUT` overrides that lookup. Equivalent references are resolved once per invocation. Tags are published only after a successful export; failed pushes retain local images and tags.

Weld creates unique build directories under `${RPWELD_HOME:-$HOME/.local/share/rpweld}`. This directory must be private (0700), owned by the current user, and outside the context. Work, output images and published base generations are retained for inspection; failed registry staging is removed. There is no automatic garbage collection yet. The managed workflow defaults to 2 GiB rootfs/layer budgets, 64 MiB metadata and temporary host DNS (`--no-host-dns` disables it). Explicit `--output` and `--work-dir` without a tag preserve the legacy limits and DNS opt-in. These limits are checked by the builder after transfer, not enforced download/disk quotas; provision sufficient storage. Registry transfers have a 15-minute timeout.

### Registry credentials

Interactive `rpweld login REGISTRY` uses a hidden password prompt. For CI, use a token over stdin:

```sh
printf '%s' "$REGISTRY_TOKEN" | rpweld login ghcr.io --username USER --password-stdin
rpweld build -t ghcr.io/USER/app:latest --push .
rpweld logout ghcr.io
```

Credentials are scoped by registry in `~/.config/rpweld/auth.json` (0600), separately from Docker/Podman credentials. `--authfile FILE` selects an explicit CI authfile for login/logout/build/push; it must be a private regular file, singly linked, owned by the invoking user. Authfiles inside build contexts are refused when registry preparation is used, including explicit --authfile builds. File updates use a lock and atomic replacement; failed logins preserve existing file credentials. No password flag is accepted, and backend errors are classified without printing raw registry responses. Weld does not fall back to Docker credentials after logout.

Authfile passwords are base64-encoded, **not encrypted**. Configure per-registry `credHelpers` in that authfile to use installed `docker-credential-*` helpers; global Docker `credsStore` is rejected rather than silently ignored. Helpers run from a fixed system PATH with an isolated HOME; helpers needing a session/keyring require that service and explicit configuration (for example `DBUS_SESSION_BUS_ADDRESS` or `GNUPGHOME`). Logout removes local credentials; it does not revoke a registry token.

HTTPS and certificate verification are mandatory, including localhost. `--cert-dir DIR` supplies a private registry's trusted CA (`ca.crt`) and optional client certificate/key to login/build/push. There is no insecure-TLS switch. Weld isolates registry search/mirror configuration and credential fallback, while preserving the system image signature policy. Do not place registry tokens in Dockerfile ARG/ENV. Credentials are not passed to RUN or included automatically in exported images, but **RUN is trusted code with host interfaces: this is not isolation from malicious builds**. Use a disposable environment and narrowly scoped tokens for builds you do not fully trust.

### Install with the registry backend

On Debian/Ubuntu amd64, build the package with Rust 1.90 and `dpkg-deb`:

```sh
bash scripts/package-deb.sh
sudo apt install ./target/packages/rpweld_0.1.0~dev_amd64.deb
```

The package declares Skopeo (>= 1.13) and CA certificates as dependencies, so installation brings the backend with it. Weld invokes `/usr/bin/skopeo` directly, never a binary from the build context's PATH. A raw `cargo build` binary needs this backend installed for registry operations; offline local-base builds still work without it.

## Build and inspect

Install Rust through rustup and a system C linker. The repository pins its Rust toolchain; dependencies are pinned in `Cargo.lock`.

```sh
cargo build --locked --release
./target/release/rpweld doctor
./target/release/rpweld doctor --json
```

Linux is the runtime target. On other platforms, `doctor` reports inspection as unsupported. It does not infer Pod allocations from host RAM or CPU counts.

Resource inspection reads cgroup v1/v2 membership, visible ancestor limits and usage, CPU quota, affinity and cpusets. Unknown restrictions remain unknown. The observations are not reserved resources or per-build enforcement, and cannot guarantee protection from OOM in a shared Pod.

`doctor` also reports this process's soft and hard open-file limits (`capabilities.nofile` in JSON), without changing them. Replay calculates the descriptors needed by each layer, including already-open descriptors and traversal headroom, and raises only the soft limit when needed and permitted. Whiteout and replay pins are budgeted as separate phases. The hard limit comes from the container runtime; it is not inferred from GPU, CPU or RAM specifications. No manual `ulimit` command is needed. If the required count exceeds the hard limit, replay refuses before mutating that layer and reports both counts. This does not make large layers work under arbitrarily low hard limits: retaining inode identity still requires pins proportional to the layer entries.

## Experimental image build

Supported instructions: FROM, RUN (shell or JSON), local/stage/image COPY (plain or JSON), ARG, ENV, USER, WORKDIR, SHELL, LABEL, shell or JSON CMD/ENTRYPOINT, EXPOSE, STOPSIGNAL and HEALTHCHECK (including NONE). Base images are pulled from registries automatically or supplied as local OCI layouts with --base; inherited User is supported, while inherited nonempty OnBuild remains unsupported. WORKDIR traversal through symlinks is currently unsupported.

USER accepts `user`, `uid`, `user:group`, `uid:gid`, `user:gid` and `uid:group`, with basic ARG/ENV expansion. Names use ASCII letters, digits, `_`, `.` and `-` (no leading `-`); decimal IDs are limited to 0..2147483647. Empty components, extra colons and whitespace are rejected. The evaluated string is preserved in exported `config.User`, including names. A final metadata-only USER need not exist in the image. Each RUN resolves its captured USER against the image's current account files, so an earlier RUN or COPY can create accounts. RUN applies actual kernel UID, GID and supplementary groups in a fresh worker; lookup or credential failures never fall back to root. Numeric UIDs use the passwd primary group when found, otherwise GID 0; an explicit group suppresses supplementary groups. Empty inherited User defaults to root. The worker preserves a nonempty explicit HOME, otherwise uses the resolved home or `/`, without adding it to image config.

Explicit WORKDIR resolves the current USER when it must create directories, and assigns that UID/GID only to newly created components. Existing directories retain ownership and permissions. The inherited initial WorkingDir is handled separately and does not trigger USER lookup. Account lookup occurs at execution time, never during whole-stage preflight; cached steps include the evaluated USER and preceding filesystem identity.

Global ARG values and `--build-arg` overrides can select FROM images before pulls and cache lookup. Redeclare a global ARG inside a stage to use it there. Expansion supports basic `$NAME` and `${NAME}` forms, not shell expressions. Dynamic COPY `--from` and dynamic forward/self stage references remain unsupported. Explicit `--base` bindings use the resolved image reference.

The automatic global args `BUILDPLATFORM`/`TARGETPLATFORM` default to `linux/amd64`,
`BUILDOS`/`TARGETOS` to `linux`, `BUILDARCH`/`TARGETARCH` to `amd64`, and
`BUILDVARIANT`/`TARGETVARIANT` to empty strings. These describe the supported Pod
worker and image, regardless of the CLI host. They are available in global ARG
defaults and FROM without declaration. Each stage must declare e.g. `ARG TARGETARCH`
before using it in instructions or RUN; child stages inherit declared args, unrelated
stages do not. ARG values are not persisted as image ENV unless explicitly assigned.
`--build-arg` overrides automatic globals even without a global declaration;
explicit ARG defaults override automatic defaults, while CLI values take precedence
over both. ENV shadows stage ARG values as usual. Overrides are strings and do not
change the execution architecture or exported image platform.

`FROM --platform=$BUILDPLATFORM image` and literal platforms are supported. Every
stage's expanded platform is validated before pulls, cache lookup or build mutation,
including unused stages and backward stage references. Only Linux amd64 is supported;
empty/unresolved values, ARM, other OSes and amd64 variants above v1 are rejected.
FROM accepts containerd spellings `linux`, `amd64`, `x86_64`, `x86-64`, case folding,
and `linux/amd64/v1` (normalized to `linux/amd64`). No emulation is performed.
The CLI retains its explicit `--platform linux/amd64` contract. The lexical scanner
validates literal FROM platforms and marks ARG-based platforms for build-time review.
Semantics follow [Docker's automatic ARG scope](https://docs.docker.com/build/building/variables/),
[BuildKit's default overrides](https://github.com/moby/buildkit/blob/master/frontend/dockerfile/dockerfile2llb/platform.go),
and [containerd normalization](https://github.com/containerd/platforms/blob/main/platforms.go).

SHELL accepts a JSON argument array and affects subsequent shell-form RUN, CMD and ENTRYPOINT. Exec-form commands remain literal argument arrays. LABEL supports variable expansion and inherited labels. RUN currently still needs `/bin/sh` in the image for Weld's dispatch wrapper, even when a custom shell is selected.

STOPSIGNAL and HEALTHCHECK only set exported image metadata; Weld does not run healthchecks, send stop signals, or provide a continuous container service. Both inherit from base images and stages and use the last declaration. STOPSIGNAL expands basic ARG/ENV variables and preserves the resulting spelling. Validation follows Moby's Linux signal parser: case-insensitive names with optional `SIG`, named realtime offsets `RTMIN+1..15` and `RTMAX-1..14`, or a nonzero signed 64-bit decimal integer. Numeric acceptance describes BuildKit metadata validation, not a guarantee that the runtime can deliver that signal.

HEALTHCHECK accepts `CMD command`, `CMD ["executable", "arg"]`, or `NONE`. Shell commands export as `["CMD-SHELL", "command"]`; JSON commands export as `["CMD", "executable", "arg"]`. Neither form expands build variables, and SHELL is not prepended to the stored healthcheck. `NONE` exports `["NONE"]`; a later CMD re-enables it. Every declaration replaces the whole healthcheck, including inherited options. Flags before CMD are `--interval=`, `--timeout=`, `--start-period=`, `--start-interval=` and `--retries=`. Durations support compound decimal `h`, `m`, `s`, `ms`, `us`/`µs`/`μs`, and `ns`, an optional leading `+`, and checked signed 64-bit nanoseconds (fractional nanoseconds truncate per component). They must evaluate to zero or at least 1ms; negative durations are unsupported. Retries are 0..2147483647. Empty/zero options remain omitted in config: runtime defaults (normally 30s interval/timeout, 0s start period, 5s start interval and 3 retries) are not materialized by the builder. Duplicate/unknown flags, missing `=`, variable expansion in flags, malformed JSON and flags on NONE fail clearly. BuildKit silently ignores flags on NONE; Weld deliberately rejects them. See the [independent Docker oracle](tests/fixtures/runtime-metadata/README.md).

```sh
# Given a local Alpine OCI layout in ./base-layout and context/Dockerfile:
# FROM alpine
# RUN printf hello > /hello
# CMD ["/bin/cat", "/hello"]
rpweld build -f context/Dockerfile --base alpine=./base-layout \
  --output ./new-image --work-dir ./new-work ./context
```

Output is an OCI layout with a flattened, uncompressed layer. Work/output paths must be new and disjoint from the context and bases. Failed builds retain partial directories; do not reuse them. Optional `--host-dns` supplies temporary resolver configuration and restores it before export. Run `rpweld build --help` for base reference selection and budget controls.

Local COPY supports directory merges, `COPY .`, WORKDIR-relative destinations, and bounded source wildcard selection (`*`, `?`, and bracket classes) with cumulative budgets. Wildcards do not provide recursive `**` traversal. Following the recorded Docker 29.7.2 behavior, unmatched or entirely ignored patterns are successful no-ops; missing or ignored literal sources still fail. Multiple matches from one wildcard overwrite a file destination in sorted match order. New selected directory destinations default to 0755; nested directories retain source modes. `--chmod` overrides these modes with octal values, including expanded ARG values; symbolic modes are unsupported. `--chown` accepts numeric IDs or names resolved from the destination image's `/etc/passwd` and `/etc/group`, never the host; `root` means zero. On a materialized filesystem, missing account files or names retain resolver defaults (unknown user: 0:0; unknown group: the user's default GID). Named lookup on untouched scratch still fails. Account lookup remains bounded and confined; malformed/nonregular databases and dangling account-file symlinks fail. Actual ownership changes require filesystem permission and fail explicitly when denied. Explicit source symlinks and source symlink traversal remain unsupported.

Ownership and mode changes use actual filesystem operations: no Pod capability is assumed, and denied changes fail rather than exporting fake ownership. Local COPY defaults to root ownership; stage COPY preserves source IDs unless overridden. Existing selected destination directories retain their metadata; new and nested copied directories receive the requested overrides. Supported timestamps and xattrs are preserved; unsupported attributes/ACLs fail preflight. Copying is nontransactional: a later filesystem failure can leave earlier instructions executed and a partial work directory.

Legacy builds with explicit output/work directories and no tag default to 256 MiB rootfs/layer sizes and 16 MiB metadata per subsystem. Managed builds default to 2 GiB rootfs/layer sizes and 64 MiB metadata. The default RUN timeout is 300 seconds. These limits do not enforce RUN memory or disk quotas. End-to-end builds have been checked in WSL and Ubuntu 24.04 builds on a Runpod CPU Pod; broader Dockerfile compatibility remains experimental.

## Dockerfile compatibility scan

```sh
rpweld scan Dockerfile
rpweld scan path/to/Dockerfile --json
```

The scanner accepts supported static `USER` syntax and reports invalid identities. USER with ARG/ENV expansion requires build-time validation; the scanner does not inspect image account files. It reports physical line numbers and detects features needing review, such as instruction flags, external frontends, remote ADD and multistage syntax. Supported single-body heredocs are consumed without interpreting their contents as Dockerfile instructions; scanning resumes at the next physical instruction. Unsupported or unterminated heredocs stop scanning and mark the remainder uninspected. It does not rewrite Dockerfiles.

Exit 0 means no known issues were found by these partial static checks. Exit 2 means errors, required review, incomplete scanning, or an input error. Neither outcome establishes build support: the builder is still under development, and base-image configuration and package-manager behavior are not inspected. Inputs must be regular UTF-8 files no larger than 1 MiB.

## Development checks

The internal `oci::BlobStore` supports verified SHA-256 blob ingestion and reads with fixed buffers, explicit size limits and cooperative cancellation. It publishes only verified content and rejects existing corrupt blobs. Store directories must be caller-owned and stable; blocking input reads need their own timeout. This is the artifact foundation; the user-facing build command is still in development.

`image::load_layout` selects an unambiguous Linux/amd64 OCI image from a local layout and verifies its manifest, config and compressed layer blobs within caller-supplied limits. It preserves inherited image configuration. Uncompressed diff IDs are declarations only until layer decompression verifies them; successful metadata loading does not establish a valid or runnable rootfs.

`layer::verify` adds bounded decompression, uncompressed diff-ID verification and a read-only seekable temporary spool with validated entry offsets. It supports USTAR/GNU headers, local PAX metadata, long names, exact fractional timestamps, binary xattrs and unresolved hardlink records. File sizes use checked `u64` bounds; configured byte budgets still apply. It accepts concatenated gzip members with shared output and aggregate header budgets, and validates every member trailer. Gzip name/comment fields remain limited to 65,535 bytes each. It rejects global PAX, sparse/special files and unsupported metadata encodings. Verification does not create links or extract a rootfs.
`rootfs::apply_layer` applies verified layers on Linux through pinned directory descriptors, with lower-layer whiteouts, streamed files and hardlink handling. The caller must supply a stable disposable tree with no concurrent writers, nested mounts or external hardlinks; discard it after any error. Linux statx mount IDs are required. Replay budgets retained descriptors before mutation and may raise the process soft `RLIMIT_NOFILE` within its existing hard limit; it never raises the hard limit. Pins still scale with layer entries, and insufficient hard limits fail early. ctime, sub-nanosecond timestamps, symlink xattrs/non-0777 modes and special hardlink targets are explicitly unsupported.

The development example `cargo run --example replay_layout -- LAYOUT REFERENCE DESTINATION SPOOL` joins layout verification and layer replay. All directories must exist; the destination must be empty and separate from the layout and spool. It rejects unsupported inherited `User`/`OnBuild` settings and never deletes user trees. Alpine 3.22.7 replay and a subsequent shell execution passed in WSL; this does not establish full Dockerfile or Runpod build compatibility.

```sh
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
python tests/compatibility.py --self-test
```

The [compatibility fixtures](tests/fixtures/README.md) define an explicit Docker reference workflow. Candidate comparisons fail as unsupported until an image-build implementation exists.

`export::export_layout` writes a flattened Linux/amd64 OCI layout containing one uncompressed full-tree layer. It preserves supported metadata and hardlinks under explicit byte/entry/metadata limits, and publishes the index last. Supply a stable, quiescent tree and a new output path; unsupported special files, nested mounts, external hardlinks and symlink/empty xattrs are rejected. Export uses temporary disk space plus the final blob (roughly twice the layer size); failed output may remain partial.

## Experimental execution probe

`examples/exec_root.rs` is an opt-in Linux chroot feasibility probe for trusted commands in a disposable test environment. It is not `docker run`, a sandbox, or a supported build backend. It requires chroot and UID/GID-changing capabilities. It does not create mounts or provide `/proc` or `/dev/pts`; packages requiring those interfaces can fail.

```sh
cargo build --locked --examples
# ROOTFS must contain a working /bin/sh; STATE_DIR must exist outside ROOTFS.
# Optional real-device preparation, only where the Pod permits mknod/device I/O:
cargo run --locked --example prepare_root -- ROOTFS
cargo run --locked --example exec_root -- ROOTFS STATE_DIR 1234 1234 30 'id'
```

Use only a disposable private rootfs. The probe clears the child environment, changes UID/GID, and attempts process-group cleanup on exit, timeout or cancellation. Escaped descendants and hostile commands are not contained. It refuses the outer root and overlapping engine state paths. No general same-Pod build compatibility is claimed.

`prepare_root` creates real `/dev/null`, `/dev/zero`, `/dev/random` and `/dev/urandom` nodes. It refuses symlinks, conflicting files, incorrectly permissioned existing devices, and the outer root. It tests device opens and reports permission or filesystem restrictions without substituting ordinary files. Rootfs paths must remain stable during preparation; failures can leave partial creations. Pod capabilities vary, so success on a CPU Pod does not establish GPU compatibility.

For an opt-in package/compiler integration test, supply a fresh disposable Ubuntu rootfs with working DNS, an existing separate state directory, and network access:

```sh
sh tests/private_root_smoke.sh target/debug/examples ROOTFS STATE_DIR
```

This installs packages into ROOTFS, builds a Python virtual environment and a C program, and checks nonroot device access. It is not part of ordinary unit tests.

`cargo run --locked --release --example seccomp_probe` is a separate Linux x86-64 root-only diagnostic for seccomp notification and real-device FD injection. It tests root execution and credential transitions, emits JSON per scenario, and exits nonzero if any scenario is unsupported. It is not wired into the executor: root-only injection success does not establish package-manager or nonroot compatibility.

The optional `--proc-mem-fscreds` argument tests pathname reads with matching filesystem credentials. Nondumpable credential transitions can still deny access. `cargo run --locked --release --example ptrace_credentials` separately tests register-only dumpability restoration with real credential changes.

## Experimental GPU private-root runner

```sh
cargo build --locked --release --example trace_root
target/release/examples/trace_root ROOTFS STATE_DIR 60 'echo hello >/dev/null'
python3 tests/traced_root_smoke.py target/release/examples/trace_root ROOTFS STATE_DIR
python3 tests/trace_cancel.py target/release/examples/trace_root ROOTFS STATE_DIR
```

This Linux x86-64 experiment requires root inside the Pod, chroot, credential-changing capabilities and permitted ptrace. It uses Rust syscall tracing to expose selected absolute device paths and `/proc` descendants inside a disposable rootfs without mounts or device creation. It restores process dumpability across credential transitions; package-manager UIDs remain real. The smoke test installs Ubuntu packages, creates a Python virtualenv, compiles C and checks UID transitions and timeout behavior. Supply a fresh Ubuntu rootfs and working DNS before running it.

The runner exposes the outer Pod's device/proc interfaces and changes process introspection permissions. It is for trusted workloads only. Thread handling tracks shared address spaces and coordinates credential changes with pathname reads. It requires permitted pidfd operations and becomes a subreaper to collect orphaned descendants. Exact `/dev` and `/proc` paths and group stops remain unsupported; relative paths retain native chroot behavior. Directory descriptors are retained across application close requests. These restrictions preclude general Docker compatibility. The integrated build uses a separate trace worker derived from this experiment.

`tests/trace_threads.py` documents an opt-in static C fixture covering concurrent I/O, fork, nonleader exec, exit-group, cancellation, dumpability changes and real UID/GID transitions. The suite passed under WSL and on a restricted Runpod A40 Pod, alongside unchanged Ubuntu apt/Python/compiler and lifecycle checks. Missing prerequisites and unsupported candidate behavior fail the suite rather than being skipped. This evidence covers the tested environment and fixtures, not all Pod policies or Docker workloads.

`tests/trace_sharing.py` adds raw shared-memory/shared-file-table clones, vfork dumpability changes, and exec/exit while sibling threads repeatedly change dumpability and access paths. Its bounded stress runs complement the lifecycle tests; they do not establish exhaustive race coverage.

For signal-return, vfork and descriptor-lifecycle regressions, compile `tests/trace_lifecycle.c` statically, place it in the disposable rootfs and execute it through `trace_root`. These integration tests are opt-in and require a Linux test environment.

Registry pulls and pushes show native layer progress bars on a terminal and plain progress lines when redirected. Progress goes to stderr; raw backend error diagnostics remain suppressed.
`rpweld build --verbose` enables low-level RUN compatibility diagnostics. Normal builds show one trusted-workload notice; RUN errors and application output remain visible.


### Multi-stage builds and local cache

```dockerfile
FROM ubuntu:24.04 AS dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y hello python3-venv
RUN python3 -m venv /opt/venv

FROM dependencies AS builder
WORKDIR /src
COPY app.py /src/app.py
RUN /opt/venv/bin/python -m py_compile /src/app.py

FROM dependencies AS runtime
WORKDIR /app
COPY --from=builder /src/app.py /app/app.py
ENV WELD_TEST=multi-stage
CMD ["/opt/venv/bin/python", "/app/app.py"]
```

Run `rpweld build -t yourname/app:latest --push .`, or select a named stage with
`--target builder`. Only dependencies of the selected target are built. Stage
names and zero-based indexes work for `COPY --from`; `FROM previous-stage`
inherits image configuration and declared ARG values. COPY also supports
`--chmod` and `--chown`. Literal external images are supported, for example
`COPY --from=nginx:alpine /etc/nginx/nginx.conf /nginx.conf`. Prior stage names
(case-insensitive) and numeric indexes take precedence; invalid numeric indexes,
self/forward references and dynamic `--from=$IMAGE` are rejected. Other literal names
resolve as images, including tag and SHA-256 digest references. Source paths
start at image `/`, independent of its WorkingDir. Source config (USER, ENV,
labels, commands, OnBuild) is never inherited or executed by COPY.

External COPY uses the same authenticated, TLS-verified persistent base cache
as FROM, including normalized digest pins, offline warm reuse and `--pull` tag
refresh. `--base IMAGE=LAYOUT` supplies an explicit local binding instead. Only
selected-target dependency images are fetched. Image layers are verified and
replayed under retained build state and existing replay/rootfs budgets; no
daemon, mount or extra privilege is introduced. Both stage and instruction cache
keys bind the selected external manifest digest; instruction keys also include
selected-source fingerprints. Stage and external-image COPY bypass context
ignore rules and preserve source ownership unless overridden with `--chown`.

These semantics follow the primary [Docker COPY reference](https://docs.docker.com/reference/dockerfile/#copy---from)
and [BuildKit reference](https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/reference.md#copy---from).
Weld retains its documented prior-stage-only and static-reference subset.
The offline Rust regressions cover explicit bindings and seeded base-cache reuse.
`python3 tests/external_copy_https.py /absolute/path/to/rpweld` additionally tests
the real Skopeo pull path against a temporary read-only loopback HTTPS fixture
(Linux root, Skopeo and OpenSSL required; no public registry or credentials).

Local COPY uses the context-root `.dockerignore`, unless a file named exactly
`<selected Dockerfile>.dockerignore` exists beside the selected Dockerfile. That
file takes precedence even when empty, including for a Dockerfile outside the
context (its parent is a trusted control-file root). Policies must be regular,
non-symlink UTF-8 files. Linux Moby rules support ordered `!` exceptions, ancestor
matches, `*`, `?`, `**`, escapes and character classes. A first-line BOM and CRLF
are accepted; column-one comments are recognized before whitespace trimming;
paths are lexically cleaned and `.` is ignored. Bare `!` is invalid. Filenames
are retained as bytes. As in Moby v0.6.0, exact/prefix/suffix matching compares
bytes, while regexp matching decodes each invalid UTF-8 byte as U+FFFD.
Unescaped `^` outside character classes asserts the start only in regexp mode;
it remains literal in exact/prefix/suffix modes. Escaped `\^` and class negation
remain supported. Regexp assertion escapes,
quoting, Unicode classes and braced hex escapes are also explicitly unsupported.
Unescaped `|`, `{` and `}` outside classes are rejected in regexp mode; their
literal exact/prefix/suffix, escaped and character-class forms are supported.

Excluded explicit COPY sources fail before cache lookup or earlier instructions.
Excluded directories are traversed conservatively when exceptions exist, and
structural parents are emitted only when an included descendant needs them.
Policies are capped at 1 MiB, 4096 rules, 4096 bytes per pattern and 65536 compiled
states. Iterative matching has a 268435456-unit work budget per traversal;
traversal is capped at 128 levels and 4096-byte paths. Visited excluded entries
count toward entry/metadata budgets. Reads, traversal and matching support
cooperative cancellation. Trees must remain stable throughout a build.

Managed builds automatically cache completed stages under
`~/.local/share/rpweld/cache-v1` (or `RPWELD_HOME/cache-v1`). Hits print `CACHED`.
The key includes the builder executable, stage definition, arguments, limits,
resolved base/dependency digests, and content/metadata of the context when that
stage uses local COPY. Context hashing shares COPY's filtered traversal and
includes the parsed policy identity and emitted content/metadata, including
atime, mtime and xattrs. It still covers included paths unused by that stage.
Ignored content changes do not invalidate the cache when emitted metadata is
unchanged. Adding/removing an ignored entry can change its copied parent
directory timestamp and validly invalidate the cache; directory timestamps are
preserved, not normalized.

When a whole stage cannot be reused, instruction checkpoints can reuse its
unchanged prefix. Put dependency files and their installation before application
COPY instructions to reuse that work after an application edit. Instruction hits
print `CACHED instruction N OP`, with FROM numbered 1. Checkpoints cover FROM,
COPY, RUN and WORKDIR; configuration instructions are evaluated normally and
included in subsequent checkpoint identities. COPY keys hash selected sources
and their preserved metadata, along with evaluated options and the preceding
filesystem/configuration state. Traversal budgets still apply on cache hits.
COPY operations requiring image symlink traversal execute without an instruction
cache lookup, then establish a verified checkpoint for subsequent instructions.
Re-executing such a COPY can change directory or symlink timestamps. Downstream
instructions reuse cache only when the resulting verified filesystem identity
matches; identical file contents alone do not guarantee a hit.

Checkpoints are flattened OCI images. Both freshly created checkpoints and hits
are replayed before subsequent execution so preserved metadata agrees. This adds
disk I/O and retained roots; it does not preserve ctime, matching the existing
export/replay limitation. Strict-atime source filesystems can cause cache misses
when reads cannot use O_NOATIME.

`--no-cache` bypasses stage and instruction cache reads and writes. Cache hits verify OCI digests and
replay layers under the requested limits before reuse. Corrupt entries fail
closed; use `--no-cache` to bypass them. Credentials are not cache inputs and
are not copied into cache entries by the registry transport.

Registry bases are cached separately under `RPWELD_HOME/base-cache-v1` (the same
default store as above). Every hit verifies the selected OCI manifest, config and
layer bytes under the current image limits, without loading credentials or starting
Skopeo. Context/credential path checks still apply. `--pull` refreshes tag references;
a failed refresh fails the build without falling back or replacing the old reference.
Immutable `@sha256:...` references reuse verified cache entries even with `--pull`.
The requested source digest is retained separately from the converted OCI manifest
digest: Skopeo fetches the exact pinned source, and Weld verifies the resulting OCI bytes.
Explicit `--base` bindings, scratch and unselected stages skip registry cache lookup.
Corrupt base records/content fail closed, including with `--pull` or `--no-cache`;
there is no automatic repair. Refreshes retain immutable generations, with verified
blobs shared through hardlinks. Credentials/certificates must live outside both cache
areas. Concurrent base fetches wait cancellably for up to 930 seconds; auth and output
tag locks still fail immediately on contention. Transfers use disposable staging;
only selected image content is published, and failed staging is removed.
Explicit output/work builds
without a tag or registry preparation retain the legacy uncached behavior.
Stage images/work directories and cache entries are retained; there is no
automatic garbage collection. Budgets apply per stage, not to total retained
storage. Keep build contexts and source images stable throughout a build.

`--platform linux/amd64` is accepted and validated. Other architectures and
multi-platform lists are rejected. This is not a BuildKit backend; remote
BuildKit caches, secret/SSH mounts and unchanged `docker buildx` commands are
not supported.

### Inspect local storage

Use `rpweld images`, `rpweld image inspect TAG`, `rpweld cache ls`,
`rpweld cache du`, `rpweld builds ls`, and `rpweld builds inspect BUILD_ID`.
Each accepts `--json`. These Linux-only commands provide bounded, read-only
observations: missing stores remain absent, and external image paths are not
traversed. `Complete` means structurally complete, not digest-verified. Reported
usage is not reclaimable space; legacy builds remain protected and ownership is
not inferred from a tag. Explicit cleanup is available on Linux.

Cleanup commands (omit `--dry-run` to apply):

```sh
rpweld cache prune --dry-run --json
rpweld builds prune --dry-run --json
rpweld builds rm BUILD_ID --dry-run --json
rpweld image rm TAG --dry-run --json
```

`--json` is optional. Without `--dry-run`, cleanup applies a newly computed plan.
`image rm` removes only the tag record; builds cleanup removes only validated
listed components, retaining the run, ownership record, stages container and unknown
siblings. Cache cleanup currently reports a protected no-op. A plan acquires
the existing exclusive store lease without waiting; a busy store selects nothing
and returns an error. There is no force option. Missing stores remain absent;
legacy stores without a lock get a protected best-effort inventory, without
creating a lock. Credentials and certificates are never modified.

Plans list candidates and protected scopes with reasons. Validated ownership
records authorize consideration of their listed components, never an entire run.
Populated owned components are candidates after a bounded descriptor-confined scan
on the store's statx mount ID; nested mounts fail closed. Symlinks count as entries,
never target trees. Run records, unlisted run children and stage-container siblings
stay protected. Canonical path and inode intersections scope valid tag and explicit
path protection to components. Unresolved references and unrelated external directory
targets remain broadly conservative: their unscanned descendants may contain aliases.
External regular files with unrelated identities need not protect every build.
Malformed or incomplete scans select nothing. Inventory skips of symlinks/special
entries inside validated components are resolved by the component scan. Explicit and external paths
are never owned. `image rm` selects only the validated tag record; its target stays
unchanged, including after a retag. Cache generations, temporary entries, and
structurally complete layouts lack ownership proof and stay protected. Thus cache
prune currently has zero eligible entries; current base references also remain
protected. Lockfiles, authentication files, certificates, and unknown entries are
always protected.

Inventory logical bytes include repeated hardlinks; unique logical and allocated
bytes deduplicate inodes. They are observations, not reclamation estimates. The
separate estimate covers selected items only, with a zero lower bound (open files
and reflinks may retain storage). A tag record's allocation is an upper bound;
component directory metadata has an unknown upper bound. No cache/build totals are
summed into reclaimable space. `shared_inode_count` counts selected regular-file
inodes with more than one hardlink, once each.

A dry run is a point-in-time report, not authorization for deletion. Saved JSON
cannot be applied. Apply takes a typed selection, acquires the existing exclusive
lease nonblocking, and keeps that same lease through recovery, fresh full scans,
reference/identity checks, mutation and directory sync. Missing leases, malformed
metadata and incomplete scans fail closed; there is no force override.

Each selected component or tag record moves with `renameat2(RENAME_NOREPLACE)`
into a private same-filesystem `.cleanup-txn-*` directory under the pinned root.
A durable typed journal records the original relative components and store, run,
parent, transaction and object identities. Descriptor-confined unlink checks
statx mount IDs and never follows symlinks or chmods/truncates shared files.
A nested `store.lock` is a protected store boundary and blocks component cleanup.
Hardlinked external file contents and permissions remain unchanged (unlink changes
link counts and ctime). The root and persistent `store.lock` are never moved or removed.

Only explicit cleanup recovers transactions. All recognized journals must validate
before recovery changes anything. Remaining payloads are restored without replacement
and freshly scanned; a partially unlinked payload may have lost descendants. A fully
unlinked component gets its durable version-2 removal tombstone. Unknown trash and
unknown transaction children remain protected; malformed journals block cleanup.
An interrupted journal publication may leave unknown trash requiring manual review.
Dry runs never recover or mutate. Recovery may finish an earlier explicit selection
before applying the current selection. Errors/cancellation report failure and completed
removals, retaining recoverable trash; no freed-byte guarantee is made. Successful
cleanup retains identity evidence for remaining components and rejects build-record
updates that would resume a cleaned run.

JSON schema v1 preserves UTF-8 paths as strings. Non-UTF-8 Unix paths use
`{"unix_bytes":[...]}`; Windows equivalents use `{"windows_wide":[...]}`.
These arrays preserve exact native path units without replacement-character
collisions. Human-readable output escapes control characters.

Managed builds and pushes hold a shared store lease. Dedicated supervisors keep
that lease while RUN or transfer descendants survive the CLI. Cancellation waits
for safe teardown before restoring DNS or removing temporary transfer files;
uninterruptible descendants can delay shutdown indefinitely. Do not kill the
supervisors or replace `store.lock`. This is a cooperative local-store protocol,
not isolation from hostile processes. Older binaries do not participate, so all
old workers and transfers must exit before cleanup is used. This quiescence is a
trusted operator contract; the lease cannot detect older nonparticipating binaries.

### Build ownership records

New program-allocated `build-*` runs contain a private, bounded
`build-record.json` (version 1, upgraded to version 2 on component removal), published before base pulls. Updates sync the
file and containing directory before returning and hold the shared store lease.
Allocation interrupted before publication leaves an unknown, protected run.

`rpweld builds inspect BUILD_ID --json` includes `build_record` only after schema,
store/run identity, every live owned-directory identity, and removal tombstones validate. Human
output shows the same fields. The record reports `phase` (`preparing`, `building`,
`image_ready`, `complete`, or `failed`), a manifest descriptor when available,
requested output `references`, and separate `push` status. Requested references
are not proof of a saved tag; the inventory's tag records show observed bindings.
A failed push retains `image_ready` and its manifest. Interrupted operations may
retain their last durable phase; no PID or phase proves inactivity.

`owned` lists explicit relative component arrays and device/inode identities for
created work/image/stage directories. It does not adopt arbitrary children merely
because a run is private. Explicit `--work-dir` and `--output` paths are always
informational `external` entries, even inside the store; `unix_bytes` preserves
non-UTF-8 native paths losslessly. These paths are never followed to establish
ownership. Managed multi-stage intermediates live in the allocated run's `stages`
directory, independent of explicit work/output locations.

Inventory alone grants no deletion authority. Legacy runs, invalid records and
`store.lock` remain protected. Explicit cleanup considers only freshly validated
components under its exclusive lease. Version-2 `removed` component arrays retain
the original ownership identities as tombstones; replacements at removed paths
are unknown and block cleanup. Record publication failures fail closed and may
leave unrecorded retained data.
Inventory is a bounded best-effort observation, not a snapshot or proof that an
image is valid. Same-user code that replaces store paths violates the cooperative
lease protocol; identities are checked again when inventory reads the record.

Cleanup planning performs reads only, but directory enumeration and metadata-record
reads can update access times. It does not restore atime (that would itself mutate
metadata). Selected regular-file logical bytes count each inode once; selected entry
counts include component roots and symlinks. `reclaimable_file_allocated_bytes` counts
file blocks once only when every observed link is selected. Unselected links contribute
zero and receive a protected-sharing reason. This is not guaranteed physical reclaim:
reflinks, open descriptors and directory blocks remain unknown, the total upper bound
is unknown for component plans, and the lower bound stays zero. Entry/depth limits bound
the additional component pass separately from inventory; record/metadata byte limits
apply to inventory reads. Partial scans and cancellation clear every selection.

### Bounded heredocs

Weld supports one bare `RUN <<EOF` and one inline source in
`COPY [--chmod=0755] [--chown=user:group] <<EOF destination`. Delimiters are
ASCII identifiers, optionally single-, double-, partially quoted or backslash
escaped. `<<-EOF` removes leading tabs (not spaces) from body and delimiter
lines. Bodies preserve blank lines, comments, backslashes and LF/CRLF bytes;
CRLF headers and delimiters are accepted independently of body line endings.
A closing delimiter must occupy its entire line, apart from `<<-` tabs.
Diagnostics use physical Dockerfile line numbers, including body lines.

Bare RUN executes the body directly through the current image/SHELL shell,
with current USER, WORKDIR, ARG and ENV. Quoting its delimiter does **not**
disable the shell's expansion of the script. COPY expands `$NAME` and `${NAME}`
using in-scope ARG/ENV (ENV wins), preserves quote characters, expands variables
even inside single quotes, and removes backslash escapes. Any delimiter quoting
or escaping disables COPY body expansion. Unsupported dollar forms, including
parameter modifiers and command substitution, fail closed in expanding COPY
bodies; quoted COPY bodies retain them literally. No COPY body is sent to a shell.

Inline COPY defaults to mode 0644 and uid/gid 0:0 regardless of USER; existing
COPY chmod/chown rules and confined destination traversal apply. Generated
source files live only in the owned build work directory, outside the image,
with fixed Unix-epoch access/modification timestamps. This deterministic timestamp
profile avoids host clock/temp-path dependence; it does not promise BuildKit
creation-time timestamp parity. The existing 1 MiB source, 64 KiB physical-line and evaluated-plan budgets bound
bodies; the quoted RUN command must also fit 64 KiB. Byte/entry/metadata budgets, cancellation,
leases and COPY cache receipts apply on cache hits and misses. Source body,
evaluated contents, permissions and source order participate in cache identity.
Local `.dockerignore` rules do not filter inline contents.

Multiple heredocs, mixed inline/local COPY sources, COPY --from with inline
contents, command-bearing RUN (`RUN cat <<EOF` or `RUN <<EOF bash`), fd-prefixed
heredocs, bare RUN shebangs, ADD/ONBUILD heredocs and non-identifier delimiters
are explicitly unsupported. Other `<<` occurrences retain the existing
fail-closed restriction, including quoted literals. Parser directives remain
outside the parser's supported profile. RUN CRLF scripts may fail in their
selected shell just as they do in Docker; Weld does not normalize them.

Semantics were checked against the [Dockerfile reference](https://docs.docker.com/reference/dockerfile/#here-documents),
[BuildKit's RUN and raw-expansion dispatch](https://github.com/moby/buildkit/blob/master/frontend/dockerfile/dockerfile2llb/convert.go),
and Docker 29.7.2 / BuildKit 0.32.2 byte-preserving oracle results. Focused engine
tests are in `tests/heredoc_engine.rs`; broader oracle fixtures are maintained
separately.
