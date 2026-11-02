# 0.2.0 release validation: publication withheld

On 2026-11-02, candidate `45a398d5212c2eee64a2195a38e0fb103ab1185f`
passed Linux CI and offline packaging, but its real managed Nemotron cold build
hit the unchanged 3,600-second limit during final stage checkpoint verification.
No phase reached independent image acceptance. Warm and application-edit builds
did not run. **Do not tag or publish this candidate as the accepted 0.2.0 release.**

The [machine-readable receipt](release-0.2.0-validation.json) records exact
artifact hashes, measured scopes, limitations and verified teardown. This report
does not replace the older trial records or turn an interrupted image into an
accepted artifact.

## Fixes and package checks that passed

The candidate promotes the sealed Nemotron oracle into the repository and fixes
its rejection of literal backslashes in Linux layer names. Only layer scanning
selects POSIX name handling; host-source path validation stays strict. Absolute
paths, NULs, parent traversal and length limits remain rejected. Raw/gzip path
regressions reproduced the old failure and passed after the correction. All 80
runner/oracle/supervisor tests passed in an exclusive native Linux directory.

A release CI run also exposed the existing transient `store_busy` fixture race
in the cleanup crash test. The single affected call now uses its existing bounded
busy-only retry. Production locking and all crash/recovery assertions remain
unchanged. Three default-parallel cleanup runs passed before the final CI run.

- [CI run 41501191014](https://github.com/kodxana/Runpod-Weld/actions/runs/41501191014): passed.
- [Linux artifact run 41501233402](https://github.com/kodxana/Runpod-Weld/actions/runs/41501233402): passed; publication intentionally skipped.

The artifact run passed formatting, Linux tests, real managed RUN/mount/output
checks, strict Clippy, documentation, validator regressions, static compilation,
offline portable/deb installs, authenticated TLS push/pull, corresponding-source
collection and checksums. The actual portable artifact from this run was used on
the Pod. Its static binary reports `rpweld 0.2.0` and the exact candidate commit.

Binary SHA-256:
`68671f7f25eb7a725504cc96b6f2dcbbce6bcc94917110b691ef12493423e86b`

Portable archive SHA-256:
`6709b4fc7383f9248446401e4dbc05241371268dabae4d15c08b424934a52376`

These are retained candidate artifacts, not a published release. The complete
package receipt includes the Debian package, matching sources and build metadata.

## Real workload and outcome

The trial used the unchanged Nemotron source archive at
`91ee1316e21f624082c90cc07fcbbec1d9499550`, normal managed defaults, and the
recorded `--run-timeout-seconds 3600` override. The supervisor separately enforced
the 3,600-second whole cold-build cap. No retries or deadline extensions occurred.

The temporary Secure US-WA-1 Pod had an A100 SXM, 32 allocated vCPUs, 250 GB
allocated RAM and a 1000 GB ephemeral disk. Storage qualification passed for
overlay backed by local XFS/MD/PCI NVMe. Package/source bytes and modes, pinned
transport, live process accounting and exit/reap behavior passed preflight.

The cold build exited with code 2 after timeout cancellation at **3,600.104 s**.
The supervisor reaped it and reported no surviving descendants. The terminal
Weld message was `image blob: blob operation cancelled`.

Useful log observations from this run:

- The final stage's model COPY took 528.323 s, including 206.801 s checkpoint
  export, 76.709 s delta verification and 210.450 s instruction-cache publication.
- The final small JSON COPY took 40.559 s, including 34.913 s export, 0.506 s
  delta verification and 0.416 s publication.
- Final stage image publication reported completion in 143.320 s. Subsequent
  stage checkpoint verification was interrupted after 11.384 s by the overall
  cold timeout. Stage-image publication is not completed-build acceptance.

These are nested scopes, not additive whole-build totals. There is no matched
baseline on this hardware, so they establish neither a speedup nor the sole
cause of the timeout. The corrected external oracle was never reached in this
trial. No claim is made about the completeness of the interrupted public layout.

## Measurement limits and next gate

The runner used explicit `correctness` mode. Exited-child `/proc/PID/io` access
was denied with errno 13; live samples and successful `wait4` evidence were
retained. Final I/O is null, `metrics_complete=false` and
`benchmark_complete=false`. Wall time and CPU/RSS observations do not substitute
for missing final I/O. No GPU inference was attempted.

The next performance investigation should isolate final stage export,
verification and cache publication, including the metadata-only suffix after
the last COPY. Preserve independent output inodes, full final verification,
durable cache behavior and the existing corruption/retry tests. This trace does
not justify removing checks or simply extending the acceptance deadline.

A new candidate still needs the same bounded cold/warm/edit trial with mandatory
independent image acceptance for every phase. The package pass is retained;
the real-image gate remains open.

## Evidence and cleanup

The sealed collector retained 18 files with no omissions. Every file and the
archive manifest were verified locally. Archive SHA-256:
`e553c4388e33e169cadaebe2687e76ff6edf8ce4cd2ba9685fa393c589df0ea7`

Raw evidence remains in the ignored task directory
`.research-private/release-v0.2.0-20261102/verified-evidence/`; the public JSON
receipt contains the relevant measurements and hashes without credentials.

Pod `z1pno99yx11ce4` was deleted after collection: delete returned 204, a fresh
get returned 404, and the complete inventory was empty. Deletion was verified
at 19:59:43 UTC, well before the 21:24:08 UTC deadline. No monitoring schedule
remains. The observed lifecycle was about 65 minutes; compute plus prorated disk
cost is estimated at **$2.10**, not a settled billing figure.
