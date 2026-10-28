# Offline Linux package checks

The packaging gate checks both the portable archive and Debian installation in
fresh `python:3.12-bookworm` containers, with networking disabled and no system
Skopeo. The image must already be present: the gate uses `--pull never` and does
not install build dependencies. Debian installation/removal happens only inside
the disposable container. The standalone binary and private Skopeo loader/library
layout are unchanged.

## Repeatable checks

Use Linux amd64, Python 3.11+, Docker with the cached image, and static
`/usr/bin/busybox`. Runtime tests need root/chroot/ptrace; the HTTPS policy and
capacity fixtures also need mount namespaces, granted by the runner. Use native
Linux storage for the checkout, artifacts and `TMPDIR`.

```sh
python3 -B -m unittest discover -s tests -p test_release_package.py -v
bash -n scripts/test-release-linux.sh
sudo bash scripts/test-release-linux.sh /absolute/path/to/artifacts
```

The runner verifies `SHA256SUMS` before extraction and runs the regression tests.
Each installed file is checked against the external artifact's `build-info.json`,
including its hash and permissions. Installed metadata must equal that external
metadata. The full `rpweld VERSION (build COMMIT)` output must match, including
when executed as uid/gid 65534. Private loader resolution and Skopeo version are
checked before the actual registry fixtures.

Each package runs five builds: raw cold/warm, gzip cold/warm, and gzip no-cache.
They check layered output, descriptor sizes/digests, **uncompressed** diff IDs,
history, nonroot file ownership, secret-output suppression and exclusion,
package-cache persistence and exclusion, and managed instruction checkpoints.
Warm/no-cache builds preserve existing checkpoint hashes; the first gzip build
adds its own entries because compression participates in cache identity.
The existing authenticated loopback HTTPS preflight suite runs for each package.
Debian removal must preserve a user-data canary.

When packaging an already tested static binary, also exercise a restrictive umask:

```sh
(umask 077; python3 scripts/package-linux.py \
  --binary /absolute/path/to/rpweld --output /absolute/path/to/new-artifacts)
```

The binary must identify the packaging checkout's exact HEAD and Cargo version;
the packager retains that strict check. Its build host also needs the cached Rust
dependencies/toolchain, distribution Skopeo closure, development libraries and
license files. Package permissions are explicitly independent of the caller's
umask. Corresponding-source collection remains in `scripts/release-sources.py`;
license notices and source package/version metadata remain part of the release.
The install smoke does not replace the corresponding-source distribution gate.

## Candidate validation, 2026-10-28

The focused checks passed in WSL Ubuntu 24.04, using cached Rust 1.90.0 and Python
image `sha256:5560e9ab8709f459489e5b8aa696eda8a07ef821e14bb122be62d91234bfa98b`.
There were nine passing regression tests, ten passing fixture builds across two
package formats, two `REGISTRY_PREFLIGHT_HTTPS_PASS` results, successful Debian
verification/removal, and a passing shell syntax check.

The reused static candidate was commit
`b7e7126cb7208a1c5a2ece57efda85c2c3e70b0b`, SHA-256
`0b0a12eebaad44e8b40ca5f4558fe4e6be2b86c2a6efe72102e88cd493160d96`.
All archived source hashes matched its build receipt; `src`, `Cargo.toml` and
`Cargo.lock` were unchanged through integration base `f0fb367`. Packaging used a
native checkout of that candidate with the updated packaging/check scripts;
the candidate identity was not rewritten to the newer checkout's commit.

All 15 helper files matched the sealed candidate manifest. Two installed WSL
libraries were older than the frozen helpers: libdevmapper `3ubuntu3.1` versus
`3ubuntu3.2`, and libgpg-error `3build2` versus `3build2.1`. The retained release
archive supplied the exact files, matching copyright notices and package/source
versions inside a **private mount namespace**. Host library bytes and package
versions were verified unchanged afterward. No system installation or network
download was used.

All crate and distribution component records matched the retained release
metadata. Its checksum-verified corresponding-source archive contained the exact
13 distribution source/version pairs. The source archive SHA-256 was
`96edca659d841e127a28b21fed4f1cb38102db93ceb2e460272e7d327feced75`.
The existing notices were retained; no dependency/source distribution step was
removed or bypassed for a published release.

The original packager failed under umask 077 with `control directory has bad
permissions 700`, and its portable prefix/metadata were 0700/0600. With the fix,
packaging and both install smokes passed under the same packaging umask.

Artifacts and native logs were retained at
`/var/tmp/weld-package-b7e7126-483691bc-ukfh7odl`. The implementation worktree's
`.research-private/packaging/` contains copied provenance, script hashes, logs
and `PACKAGE-SHA256SUMS`. The generated portable/deb SHA-256 values are:

```text
c10f6299b13daf4c1e3e156a78c970aae3781c8dd61c10f38c3e0b10dd2bfc78  rpweld-0.1.0-linux-amd64.tar.gz
d5a28a0783c87ba4893f6399fefa244d676dc839fa73c0d47cc1f9261af9db4a  rpweld_0.1.0_amd64.deb
```

These are local candidate checks, not a published v0.2 release. Cargo still
reports 0.1.0. A new release source archive, final release commit/version build,
other architectures, and the separate full HTTPS push roundtrip were not run
here. Repository-wide Rust QA was left to the parent integration task.
