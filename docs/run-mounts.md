# RUN file secrets and package caches

Weld materializes ordinary files/directories inside its disposable chroot. It
does not require `CAP_SYS_ADMIN`, `unshare`, bind mounts or tmpfs. Real USER
credentials and the existing trace-worker/lease-guard cancellation protocol still
apply. This is a bounded compatibility profile for trusted Dockerfiles.

## Syntax

Repeat `--secret id=NAME,src=/private/file` on `rpweld build` (the `--secret=...`
spelling works too). IDs are 1–128 ASCII letters/digits, dots, underscores or
hyphens. Sources must be private (no group/other permissions), owned by the
invoking user, single-link regular files of at most 64 KiB. The source itself
cannot be a symlink. Sources must be outside the context even if dockerignored,
selected Dockerfile, work/output directories, base images and package cache.
There is no environment source, ARG fallback, automatic environment detection or
secret value in command-line arguments. Commas in source paths are unsupported.

```dockerfile
RUN --mount=type=secret,id=token,required=true command
USER 1234:2345
RUN --mount=type=secret,id=token,target=/run/credential,uid=1234,gid=2345,mode=0400 command
```

Secret defaults: `target=/run/secrets/<id>`, `required=false`, `mode=0400`,
`uid=0`, `gid=0`. Booleans are `true`/`false`, mode is octal 0000–0777, and
numeric ownership is 0–2147483647. The target must be absent even when the source
is missing. An inherited file, directory or symlink is refused, never read or
removed. Normal shell, JSON exec and supported heredoc RUN forms are preserved.

```dockerfile
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt
RUN --mount=type=cache,id=npm,target=/root/.npm npm ci
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y git
```

Some distro images configure apt to delete downloaded packages; remove that
image-specific configuration before relying on an archive cache. This feature
does not change apt's sandbox or package-manager settings.

Cache requires `target`; `id` defaults to the target spelling. Explicit IDs use
the simple identifier grammar above. `mode=0755,uid=0,gid=0` initialize only new
caches. Existing data retains its ownership and mode. An inherited target must
be a real directory; its complete tree is temporarily renamed into private
worker state and restored with the same inode and metadata. Inherited contents
are not used to seed a new cache. Files, ownership and permission bits are
copied between package storage and the working target; cache xattrs and original
timestamps are not part of this compatibility profile.

Omitted `sharing`, `sharing=shared`, and `sharing=locked` all serialize through
one exclusive flock per package-cache root, including copy-in, RUN and copy-out.
This is stronger serialization than Docker's shared mode. Waits observe
cancellation and have a 24-hour upper bound. Repeated cache IDs in the same RUN,
`sharing=private`, readonly caches, `from`/`source`, secret environment mounts,
SSH/bind/tmpfs mounts and unknown options are refused.

There are at most eight mounts per RUN and eight supplied secret sources. A RUN
cannot combine secret and cache mounts. Targets must be normalized absolute
paths, at most 1024 bytes and 32 components; individual components are at most
255 bytes. Root, overlapping targets, `.`/`..`, repeated separators, symlink
ancestors/targets, mount crossings, and `/proc`, `/dev` or `/sys descendants are
refused. Mount targets do not expand ARG or ENV. Root replacement, renaming mount
ancestors, and native mount behavior are unsupported.

## Storage, limits and publication

Managed builds default to `${RPWELD_HOME}/run-cache-v1` (normally beneath
`~/.local/share/rpweld`), independently of instruction caching. `--no-cache`
disables instruction/stage cache reuse but retains package cache reuse.
`--cache-mount-dir DIR` selects a separate private root and is required for
unmanaged explicit work/output builds. Its parent must exist. Use a new path;
Weld never adopts an existing unmarked directory. Cache roots must be disjoint
from context/work/output/base inputs, secrets and registry credentials/certs.

The root ownership/version record binds its device/inode and persistent lock
identity. Each digest-named entry has its own record binding namespace, entry,
payload identities and ID hash. Names alone never establish ownership. An
unmarked/replaced entry or unknown interrupted staging directory fails closed
and is retained for inspection. Managed usage retains the store lease throughout;
inventory recognizes the namespace and cleanup always protects it. There is no
automatic package-cache eviction or retirement command in this version.

The existing `--max-rootfs-bytes`, `--max-entries` and `--metadata-budget` govern
the aggregate persisted cache and each RUN's materialized cache data. Managed
builds use their resolved automatic ceilings. Standalone `MountGuard` defaults
are 16 GiB, 262144 entries and 64 MiB metadata. Cache trees allow only real
directories and single-link regular files, to depth 32; symlinks, hardlinks,
devices, FIFOs and sockets are refused. Traversal, records and path metadata are
bounded without collecting whole trees in memory. Ownership records are capped
at 4096 bytes; conservative path/record bookkeeping counts against metadata.

Known-size copy-in/out performs measured disk/inode admission before allocation.
RUN growth checks happen cooperatively once per second; they are not quotas.
A fast process can exceed a ceiling between polls. Stable post-RUN validation
must pass before publication. Copy-out stages a complete tree, then uses atomic
`renameat2` replacement; filesystems lacking the required operations fail. Old
cache data survives failures/cancellation before publication. Different IDs in a
multi-cache RUN publish individually, not as one transaction. Disk use temporarily
includes old cache, materialized data and the new staged copy.

## Secrets, checkpoints and interruption

Secret bytes and source paths are never part of the Dockerfile AST, instruction
fingerprints or receipts. Package contents are not fingerprinted either. Mount
declarations participate in instruction identity. Changing a supplied secret or
package cache does not invalidate a successful instruction cache hit; use
`--no-cache` or another explicit build input when re-execution is needed.
Required-source and target safety checks still run before instruction reuse;
whole-stage shortcuts are disabled for stages containing mounts.

For a RUN with any supplied secret, Weld announces once that stdout/stderr is
suppressed, then discards both streams, including `--progress=quiet`. This also
hides worker diagnostics from that RUN; failure status remains visible. Engine
messages do not include secret source paths or bytes. No secret is sent through
worker argv/environment. Unix mode bits are applied, but UID 0 can still modify
the temporary file. Modified files are removed as well as read-only files.

After normal exit, handled failure or cancellation, the builder waits for the
lease supervisor to reap every descendant. It then detaches temporary targets,
restores inherited paths and their metadata, and only afterward publishes
package caches or returns to the checkpoint loop. Cleanup ignores the cancelled
flag and is bounded separately. Restoration failure fails the build; no image
checkpoint or output may be published afterward. Setup failures also restore
already-installed targets. A successful mount scope never exports its temporary
contents, including at intermediate instruction checkpoints.

**These are ordinary on-disk files, not tmpfs, immutable mounts or a secret-taint
system.** SIGKILL of the builder, OOM termination, machine failure or power loss
can prevent all cleanup code and leave secrets/backups in private failed work.
Supplied-secret builds restrict their owned work directory to 0700 before
injection. Do not reuse failed work. Confirm descendants have stopped before
using the existing owned-work cleanup flow; explicitly managed external work may
require careful manual removal. Package namespaces stay protected from cleanup.
No automatic restart recovery or secure disk erasure is promised.

RUN is trusted code with host process/device interfaces. It can deliberately copy
secrets to other files, derive values, transmit them, or use unrelated logging
channels. Such exfiltration is outside this profile; suppression and cleanup are
not an isolation boundary. Do not put credentials directly in Dockerfile text,
ARG/ENV, package caches or build context. Tests use synthetic markers only.

## Local verification

`cargo test --test run_mounts` covers source/target confinement, byte/metadata
bounds, inherited metadata, rollback, cancellation and exclusive lock waits.
The offline real-worker suite requires Linux root, ptrace/chroot and a static
`/bin/busybox`:

```sh
cargo test --test run_mounts_cli -- --ignored
```

It checks USER credentials, suppression, intermediate checkpoints, managed cache
defaults, `--no-cache` reuse, final export exclusion and SIGTERM cleanup. It does
not claim a live pip/npm/apt network installation or a Docker equivalence oracle.
