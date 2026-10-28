# Compatibility fixtures

These are inputs for the reference comparison corpus. All assertions live
in `expectations.json`. Basic, multistage, numeric non-root, and deletion/config
fixtures use a caller-supplied digest-pinned Alpine base. Their `RUN` steps have
network disabled. Base pulls still require registry access or a local registry.
The multistage scratch output is data, not a runnable application.

`default-apt` requires a pinned Ubuntu base, explicit fixture selection and
`--allow-network`. It uses ordinary apt sandbox defaults, installs and removes
`hello`, and has **mutable repository dependencies**. It is a separate network
smoke test, not a reproducible package baseline. No apt sandbox workaround is
injected. Resource stress tests are deferred; this corpus makes no cgroup or
memory-enforcement claim.

## Local checks (no Docker)

```text
python tests/compatibility.py --self-test
python tests/compatibility.py --mode compare
```

The first command runs stdlib unit tests. The second emits JSON and exits **2**
because this corpus has no Weld command adapter. Weld's build command and its
separate integration tests exist. Compare mode invokes neither Docker nor Weld;
adding the adapter and proving equivalent output remains a compatibility gate.

## Explicit reference run on a Docker-capable Linux worker

Supply the Docker executable and any context options as a JSON argv array;
the driver never invokes a shell. For example, in a POSIX shell, replacing
every placeholder with reviewed values from the actual worker/registry:

```sh
python tests/compatibility.py --mode reference \
  --docker-command '["docker", "--context", "YOUR_CONTEXT"]' \
  --reference-version ACTUAL_REVIEWED_SERVER_VERSION \
  --base alpine=YOUR_ALPINE_IMAGE@sha256:ACTUAL_64_HEX_DIGEST \
  --report reference-result.json
```

Add `--fixture default-apt --allow-network` and
`--base ubuntu=YOUR_UBUNTU_IMAGE@sha256:ACTUAL_64_HEX_DIGEST` for apt only.
No pins are supplied or invented in this repository. Missing/malformed base
digests and missing reference version fail before commands run. The observed
Docker server version must exactly match the required pin before pulling or
building. `DOCKER_BUILDKIT=1` selects Docker's bundled builder/frontend, with no
external `# syntax` download. A separately managed buildx worker is outside this
first driver contract. A full release lock should additionally attest the
Docker distribution and bundled BuildKit/frontend artifacts; a server version
match alone does not attest those binaries.

The JSON report records full observed Docker version metadata, requested base
digests, actual base inspections, fixture context hashes, and output image
config IDs/rootfs diff IDs/available repository digests. A locally built image
normally has no registry manifest digest: the driver records what exists and
does not relabel the config ID as a manifest digest. Reference success exits 0
with `status: reference-passed` and `candidate.status: skipped`; **it is not a
candidate compatibility pass**. Failures exit 1.

Builds run without cache. The driver creates unique local image tags and stopped
containers, exports their filesystems without starting them, checks file bytes,
selected ownership/modes, deletions and image config, then removes its containers
and tags. It does not prune shared caches or remove pulled bases. Commands time
out after 600 seconds by default (`--timeout`); stopping the Docker client cannot
guarantee cancellation of daemon work. Cleanup failures fail the run and are
reported. Execute only on a test worker you intend to use for these builds.

Flattened Docker exports test final deletion semantics, not the encoding of
whiteout entries or independent OCI layer replay. Whole-tree comparison, named
users, warm-cache comparison, OCI validation, restricted-Pod execution and actual
candidate builds remain future gates. Input fixtures use LF; preserve those
bytes when copying to a Linux worker.
