# Runpod Weld

`rpweld` is a standalone Rust project for building OCI/Docker images inside ordinary Runpod Pods. It has no Kaniko runtime dependency.

**Development preview:** image building, registry push and container execution are not implemented yet. The current CLI inspects the environment and reports cgroup-aware CPU and memory observations.

## Build and inspect

Install Rust through rustup and a system C linker. The repository pins its Rust toolchain; dependencies are pinned in `Cargo.lock`.

```sh
cargo build --locked --release
./target/release/rpweld doctor
./target/release/rpweld doctor --json
```

Linux is the runtime target. On other platforms, `doctor` reports inspection as unsupported. It does not infer Pod allocations from host RAM or CPU counts.

Resource inspection reads cgroup v1/v2 membership, visible ancestor limits and usage, CPU quota, affinity and cpusets. Unknown restrictions remain unknown. The observations are not reserved resources or per-build enforcement, and cannot guarantee protection from OOM in a shared Pod.

## Development checks

```sh
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
python tests/compatibility.py --self-test
```

The [compatibility fixtures](tests/fixtures/README.md) define an explicit Docker reference workflow. Candidate comparisons fail as unsupported until an image-build implementation exists.

## Experimental execution probe

`examples/exec_root.rs` is an opt-in Linux chroot feasibility probe for trusted commands in a disposable test environment. It is not `docker run`, a sandbox, or a supported build backend. It requires chroot and UID/GID-changing capabilities. It does not create mounts or provide `/proc` and `/dev` inside the rootfs; ordinary package installation can fail because of those missing interfaces.

```sh
cargo build --locked --example exec_root
# ROOTFS must contain a working /bin/sh; STATE_DIR must exist outside ROOTFS.
cargo run --locked --example exec_root -- ROOTFS STATE_DIR 1234 1234 30 'id'
```

Use only a disposable private rootfs. The probe clears the child environment, changes UID/GID, and attempts process-group cleanup on exit, timeout or cancellation. Escaped descendants and hostile commands are not contained. It refuses the outer root and overlapping engine state paths. No general same-Pod build compatibility is claimed.
