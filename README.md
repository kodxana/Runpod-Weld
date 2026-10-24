# Runpod Weld

`rpweld` is a standalone Rust project for building OCI/Docker images inside ordinary Runpod Pods. It has no Kaniko runtime dependency.

**Development preview:** experimental single-stage builds from local OCI images or scratch are available on Linux amd64. Registry pull/push, multistage builds and a container run command are not implemented. Trusted workloads only; this is not a security sandbox.

## Build and inspect

Install Rust through rustup and a system C linker. The repository pins its Rust toolchain; dependencies are pinned in `Cargo.lock`.

```sh
cargo build --locked --release
./target/release/rpweld doctor
./target/release/rpweld doctor --json
```

Linux is the runtime target. On other platforms, `doctor` reports inspection as unsupported. It does not infer Pod allocations from host RAM or CPU counts.

Resource inspection reads cgroup v1/v2 membership, visible ancestor limits and usage, CPU quota, affinity and cpusets. Unknown restrictions remain unknown. The observations are not reserved resources or per-build enforcement, and cannot guarantee protection from OOM in a shared Pod.

## Experimental image build

Supported instructions: FROM, RUN (shell or JSON), local COPY (plain or JSON), ARG, ENV, WORKDIR, JSON CMD/ENTRYPOINT and EXPOSE. Unsupported features fail before execution. Base images must be supplied as local OCI layouts; explicit USER and inherited nonempty User/OnBuild are rejected. WORKDIR traversal through symlinks is currently unsupported.

```sh
# Given a local Alpine OCI layout in ./base-layout and context/Dockerfile:
# FROM alpine
# RUN printf hello > /hello
# CMD ["/bin/cat", "/hello"]
rpweld build -f context/Dockerfile --base alpine=./base-layout \
  --output ./new-image --work-dir ./new-work ./context
```

Output is an OCI layout with a flattened, uncompressed layer. Work/output paths must be new and disjoint from the context and bases. Failed builds retain partial directories; do not reuse them. Optional `--host-dns` supplies temporary resolver configuration and restores it before export. Run `rpweld build --help` for base reference selection and budget controls.

Local COPY supports directory merges and WORKDIR-relative destinations with cumulative budgets. Stage copies, flags, glob patterns, source symlink traversal and nonempty/nonregular `.dockerignore` files are rejected. Supported timestamps and xattrs are preserved; unsupported attributes/ACLs fail preflight. Copying is nontransactional: a later filesystem failure can leave earlier instructions executed and a partial work directory.

Defaults allow 256 MiB rootfs/layer sizes, 16 MiB metadata per subsystem and a 300-second RUN timeout. These are development limits, not suitable defaults for ComfyUI. They do not enforce RUN memory or disk quotas. End-to-end Alpine builds have been checked in WSL; this integrated build path still needs ordinary Runpod validation.

## Dockerfile compatibility scan

```sh
rpweld scan Dockerfile
rpweld scan path/to/Dockerfile --json
```

The initial planned profile excludes explicit `USER` instructions, including `USER root`. The scanner reports physical line numbers and detects features needing review, such as instruction flags, external frontends, remote ADD and multistage syntax. Possible heredocs stop scanning and mark the remainder uninspected. It does not rewrite Dockerfiles.

Exit 0 means no known issues were found by these partial static checks. Exit 2 means errors, required review, incomplete scanning, or an input error. Neither outcome establishes build support: the builder is still under development, and base-image configuration and package-manager behavior are not inspected. Inputs must be regular UTF-8 files no larger than 1 MiB.

## Development checks

The internal `oci::BlobStore` supports verified SHA-256 blob ingestion and reads with fixed buffers, explicit size limits and cooperative cancellation. It publishes only verified content and rejects existing corrupt blobs. Store directories must be caller-owned and stable; blocking input reads need their own timeout. This is the artifact foundation; the user-facing build command is still in development.

`image::load_layout` selects an unambiguous Linux/amd64 OCI image from a local layout and verifies its manifest, config and compressed layer blobs within caller-supplied limits. It preserves inherited image configuration. Uncompressed diff IDs are declarations only until layer decompression verifies them; successful metadata loading does not establish a valid or runnable rootfs.

`layer::verify` adds bounded decompression, uncompressed diff-ID verification and a read-only seekable temporary spool with validated entry offsets. It supports USTAR/GNU headers, local PAX metadata, long names, exact fractional timestamps, binary xattrs and unresolved hardlink records. File sizes use checked `u64` bounds; configured byte budgets still apply. It accepts concatenated gzip members with shared output and aggregate header budgets, and validates every member trailer. Gzip name/comment fields remain limited to 65,535 bytes each. It rejects global PAX, sparse/special files and unsupported metadata encodings. Verification does not create links or extract a rootfs.
`rootfs::apply_layer` applies verified layers on Linux through pinned directory descriptors, with lower-layer whiteouts, streamed files and hardlink handling. The caller must supply a stable disposable tree with no concurrent writers, nested mounts or external hardlinks; discard it after any error. Linux statx mount IDs are required. ctime, sub-nanosecond timestamps, symlink xattrs/non-0777 modes and special hardlink targets are explicitly unsupported.

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

The runner exposes the outer Pod's device/proc interfaces and changes process introspection permissions. It is for trusted workloads only. Thread handling tracks shared address spaces and coordinates credential changes with pathname reads. It requires permitted pidfd operations and becomes a subreaper to collect orphaned descendants. Exact `/dev` and `/proc` paths and group stops remain unsupported; relative paths retain native chroot behavior. Directory descriptors are retained across application close requests. These restrictions preclude general Docker compatibility. No image build/export command uses this experiment yet.

`tests/trace_threads.py` documents an opt-in static C fixture covering concurrent I/O, fork, nonleader exec, exit-group, cancellation, dumpability changes and real UID/GID transitions. The suite passed under WSL and on a restricted Runpod A40 Pod, alongside unchanged Ubuntu apt/Python/compiler and lifecycle checks. Missing prerequisites and unsupported candidate behavior fail the suite rather than being skipped. This evidence covers the tested environment and fixtures, not all Pod policies or Docker workloads.

`tests/trace_sharing.py` adds raw shared-memory/shared-file-table clones, vfork dumpability changes, and exec/exit while sibling threads repeatedly change dumpability and access paths. Its bounded stress runs complement the lifecycle tests; they do not establish exhaustive race coverage.

For signal-return, vfork and descriptor-lifecycle regressions, compile `tests/trace_lifecycle.c` statically, place it in the disposable rootfs and execute it through `trace_root`. These integration tests are opt-in and require a Linux test environment.
