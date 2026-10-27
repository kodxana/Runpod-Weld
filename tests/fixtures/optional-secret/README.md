# Optional-secret absence regression

`Dockerfile.nemotron` is unchanged from
https://github.com/kodxana/nemotron-bolt-runpod/blob/91ee1316e21f624082c90cc07fcbbec1d9499550/Dockerfile
(Git blob `f53524cc395720c421bd0f81bf9a1fa3217b9987`). It is a parse/scanner fixture,
not an assertion that the GPU image builds or runs. The entire Dockerfile must
parse even when selecting `runtime-base`. Large-image budgets and GPU application
installation remain separate work.

`tests/optional_secret.rs` checks the pinned source, scanner `CMD []`, directive
rejection, strict mount flags and shell/exec/heredoc payloads. Scanner checks
retire stale stage/COPY warnings only after full subset parsing
proves static stages and backward stage copies; dynamic, forward, self, external
and unsupported-flag cases retain diagnostics. The Linux unit
guard test verifies existing files and symlinks, including a host canary, remain
unchanged. `tests/instruction_cache.rs` has two offline Alpine acceptance tests:

```
RPWELD_TEST_LAYOUT=/path/to/local/alpine-oci cargo test --test instruction_cache optional_secret -- --ignored --test-threads=1
```

They cover cold/no-cache execution, guarded instruction hits, ID invalidation,
and rejection of inherited files, dangling symlinks and non-directory parents
with cold and cached predecessor stages. No network or actual token is used.
The absent-source case still intentionally rejects inherited paths; it does not claim equivalence
to Docker's behavior when an optional secret was not provided. No Docker oracle
or GPU build is required for these limited-profile tests.

Real injection and bounded package cache lifecycle are covered by `tests/run_mounts.rs`
and the ignored offline BusyBox/chroot tests in `tests/run_mounts_cli.rs`. See
[RUN mount profile](../../../docs/run-mounts.md).
