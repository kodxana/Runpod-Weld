# Implementation gaps and next stable release

Audit baseline: `a3ce37f6a951a388a1c81d19ae93597fbd74914e`, 2026-10-28.
This is a scoped audit of Weld's application behavior, implementation paths,
tests and recorded validation, not an exhaustive Docker/BuildKit compatibility
audit or a new benchmark. Source links below are pinned to that revision.
Concurrent small-COPY performance work is outside this snapshot.

**The next stable candidate should improve small-COPY checkpoint cost and clear
the real-image acceptance gate before adding compatibility features.** Candidate
`5860971` passed synthetic and packaging gates, but its real managed Nemotron
cold build reached the 3,600-second limit during final export, with no published
image index or manifest. Warm/edit builds and independent final-image acceptance
did not run. These results are compatible: the synthetic pass does not certify
large-image performance. [Real result: lines 3-15][real-result];
[candidate gates: lines 20-39, 55-77][candidate-gates].

## Implemented supported subset: retain, do not reopen as missing

| Area | What exists at the audit baseline | Implementation / regression evidence |
| --- | --- | --- |
| Build graph and bases | Linux amd64 builds from scratch, registry or local OCI; named stages, target selection, stage inheritance, literal stage/image `COPY --from`; global/stage ARG and automatic platform args. Other platforms are rejected. | [README:128-194][build-profile]; `src/build.rs:2026-2028`; [tests/multistage_cli.rs:114-324][multistage-tests] covers external COPY, target selection, inheritance and cache; [tests/platform_cli.rs:27-53][platform-tests] checks rejection before pull/store mutation. |
| COPY and context | Plain/JSON COPY, directory merges, bounded wildcards, `.dockerignore`, image-local chown and octal chmod, selected metadata preservation. Source hardlinks become separate copied files; symlinks inside copied directories are supported. | [src/context.rs:1-24][copy-contract]; [tests/dockerignore_cli.rs:139-260][ignore-tests]; [tests/dockerfile_config.rs:140-219][copy-config-tests] covers expanded flags, cache invalidation and invalid inputs. |
| Execution and config | Shell/exec RUN, actual kernel USER credentials, WORKDIR, SHELL, ENV, LABEL, CMD/ENTRYPOINT, EXPOSE, STOPSIGNAL and HEALTHCHECK metadata. Healthchecks are not executed by the builder. | [README:128-203][build-profile]; [tests/user_cli.rs:350-457][user-tests] includes environment-dependent real-worker cases; [tests/runtime_metadata_config.rs:61-183][metadata-tests] checks the stored Docker oracle, inheritance and cache boundaries. |
| Heredocs and RUN mounts | Single bare RUN heredoc; single inline COPY heredoc; file secrets and persisted package caches with bounded options and cleanup. The exact first-line `# syntax=docker/dockerfile:1` is accepted as a subset declaration. | [src/build_plan.rs:360-372][directives]; [tests/heredoc_cli.rs:278-413][heredoc-tests]; [src/run_mounts.rs:115-210][mount-parser]; [tests/run_mounts.rs:65-295][mount-tests]. |
| OCI and instruction caching | Layered output with incremental instruction deltas, flattened override, raw/gzip new layers, verified base reuse and durable instruction prefixes. Fresh layered checkpoints retain the working root; hits apply only the next delta. | [README:407-465][checkpoint-contract]; [tests/instruction_cache_engine.rs:153-280][checkpoint-tests]; [tests/gzip_export_cli.rs:99-223][gzip-tests]; [tests/base_cache.rs:97-299][base-tests]. |
| Existing performance improvements | Initial replay receipts avoid a second baseline replay; eligible last FROM consumers take an owned root; no-cache COPY-only stages avoid image serialization; managed publication sessions reuse bounded evidence for previously admitted physical objects. These are already implemented. | [README:438-485][checkpoint-contract]; [tests/instruction_cache_engine.rs:296-624][reuse-tests]; [docs/publication-session-implementation.md:11-61][session-contract]; [src/publication_session_tests.rs:25-190][session-tests]. |
| Operations and packaging | Authenticated TLS registry pull/push, tags, bundled offline packages, resource admission/monitoring, storage inventory, build records and explicit owned-build/cache-v2 cleanup. | [README:64-101][registry-doc]; [README:518-545][cleanup-doc]; [tests/cache_cleanup.rs:201-386][cleanup-tests]; [docs/stable-candidate-validation.md:20-39][candidate-gates]. |

The named tests demonstrate coverage, not a fresh execution result from this
audit. Some real-worker tests are ignored by ordinary `cargo test`; release CI
explicitly runs selected privileged suites. [README:251-262][test-scope].

## Unsupported features and bounded differences

These are concrete limits of the inspected implementation, not newly discovered
regressions or a claim to enumerate everything Docker supports. Keep them
documented for the small release; prioritize additions only for an actual blocked
workload, with a pinned reference fixture and a separate implementation review.

| Area | Missing or deliberately restricted behavior | Evidence |
| --- | --- | --- |
| Dockerfile instructions and frontend | ADD, ONBUILD declarations and VOLUME are outside the parser dispatch; inherited nonempty OnBuild fails preflight. No external frontend execution, alternate syntax version, `# escape` or `# check`; legacy ENV/LABEL forms and some continuation/whitespace syntax are rejected. | [src/build_plan.rs:15-22][parser-profile], [532-763][parser-dispatch], [1085-1119][parser-negative]; `src/build.rs:572-573`; [directives:360-372][directives]. The accepted exact syntax declaration is an exception, not frontend support. |
| COPY and paths | No dynamic/forward/self `--from`; only `--from`, `--chown`, `--chmod` flags, so `--link`, `--parents` and `--exclude` are not accepted. No symbolic chmod, recursive COPY `**`, explicit source symlink or symlink-ancestor traversal. JSON COPY embedded quotes/backslashes and WORKDIR parent/symlink traversal are restricted. | [src/build_plan.rs:596-633][copy-parser]; [src/context.rs:1-24][copy-contract], `87-93`; [src/build.rs:292-350][path-rules], `998-1000`; [tests/dockerfile_config.rs:200-219][copy-config-tests]. Directory-contained symlinks must not be misclassified as wholly unsupported. |
| RUN flags/mounts | Only bounded secret/cache mounts: no bind/tmpfs/SSH, environment secret source/target, cache `private`, readonly/from/source, or mixed secret+cache RUN. Shared and locked both serialize exclusively; cache xattrs/timestamps and seeding from inherited target contents are outside the profile. Unknown RUN flags fail. | [src/run_mounts.rs:115-210][mount-parser]; [docs/run-mounts.md:43-66][mount-limits]; [tests/run_mounts.rs:65-93][mount-tests] includes mixed mounts, env secrets and private sharing rejection. |
| Complex heredocs | No multiple/mixed local-inline sources, inline `COPY --from`, command-bearing or fd-prefixed RUN heredocs, bare RUN shebang dispatch, ADD/ONBUILD heredocs or non-identifier delimiters. Inline COPY timestamps are deterministic, not a promise of BuildKit creation-time parity. | [tests/heredoc_engine.rs:33-68][heredoc-negative]; [README:687-706][heredoc-limits]. |
| Platform and image formats | Linux amd64 execution only, no emulation/multi-platform output. Export offers raw tar/gzip only; registry preflight rejects other layer compression. Replay rejects sparse/device/special entries, global PAX and unsupported metadata encodings. Nested OCI indexes/artifact manifests are rejected. | `src/build.rs:2026-2028`; [src/export_compression.rs:18-26][compression]; [src/registry.rs:438-449][registry-compression]; [src/layer.rs:630-689][layer-rejections]; [tests/layer_formats.rs:192-209][layer-tests]; `src/image.rs:166-169,202`; [tests/platform_cli.rs:27-53][platform-tests]. |
| Registry integration | No global Docker `credsStore` fallback; per-registry helpers are supported. Signed tag/index pulls whose signing identity would change under digest pinning fail explicitly. This is narrower than saying authentication or signature policy is absent. | [README:78-95][registry-doc]; `src/registry.rs:547-553,969`; [src/registry.rs:1747-1787][registry-negative] checks metadata/platform/compression refusal. |
| BuildKit/runtime interface | No BuildKit backend or unchanged `docker buildx` interface; no container run service. RUN still requires `/bin/sh` for its dispatch wrapper even with a custom SHELL or exec form. HEALTHCHECK flags on NONE are deliberately rejected, a recorded Docker-oracle difference. | [README:199-203][runtime-doc], [513-516][buildkit-limit]; `src/build.rs:6`; [src/main.rs:35-98][cli-profile]; [tests/runtime_metadata_config.rs:61-85][metadata-tests]. |

## Known performance problems and release blockers

**P0: full-root checkpoint work after a small COPY.** The final tiny JSON COPY
took **191.467 s**: 153.937 s exporting, 35.376 s verifying and 0.364 s publishing
its instruction cache. The real run accumulated 1,342.108 s of completed
instruction exports, 341.546 s of delta verification and 612.899 s of instruction
publication. These are nested subphases, not additive whole-build totals.
[Real timings: lines 65-99][real-timing].

The inspected path exports then verifies each checkpoint
([src/build.rs:3227-3396][checkpoint-path]); delta planning inventories the root
([src/export_delta.rs:731-758][delta-plan]) and hashes every unique regular-file
payload ([297-331][delta-hash]). This establishes repeated full-tree work, not
the sole cause of the observed elapsed time. Incremental COPY inventory is still
missing at this revision. The smallest next change should bound the optimized
case to engine-known COPY effects, retain conservative fallback for unknown
effects, and demonstrate less unrelated-data processing. Do not skip final
verification or make a metadata match alone certify unchanged contents.

**P0: the real managed workload has no successful final artifact.** Final export
was interrupted; in-build package/model checks are not independent output
acceptance. The successful 1 GiB synthetic run and historical 20m05s no-cache
Nemotron run cannot replace this gate or provide a matched speed ratio.
[Real result:3-25][real-result], [timing limits:97-99][real-timing];
[candidate limitations:95-106][release-decision]. Measure final export and final
stage publication separately: optimizing instruction publication alone is not
sufficient evidence that the complete build now fits.

**P1: measurement readiness remains open; the sampler defect is already fixed.**
The old sampler lost final exit/wall/CPU/RSS/I/O evidence after an exited-child
`/proc` permission error. Commit `d9aa87b` now preserves available `wait4` data,
records unavailable I/O and keeps build failure primary. Do not list that code
fix as still missing. The corrected sampler has local regression coverage but
was not rerun on a fresh Pod; successful benchmark acceptance still requires
final I/O counters. Qualify that access before another long run.
[docs/real-nemotron-5860971.md:101-120][sampler-report];
[cold_metrics.py:79-108][sampler-code];
[test_final_counter_denial_preserves_exit_and_wait4_evidence:196-227][sampler-test].

**P1: a new release identity and final-source validation are outstanding.** The
validated packages still say `0.1.0`; they must not replace that existing release.
A new candidate needs its own version/notes and artifacts built from the final
source, with the same packaging and source-distribution checks. Historical checks
do not certify later production changes. [Candidate report:3-8][candidate-identity],
[102-106][release-decision]. This audit performs no release, push or cloud work.

## Unvalidated behavior and unresolved observations

- **Real warm/edit behavior, full-image oracle and GPU inference:** none ran in
  the latest real-image experiment. The 300-second default RUN timeout was also
  not tested there; the run used 3,600 seconds per RUN plus a separate whole-build
  cap. Do not infer a runtime/GPU pass from successful model downloads.
  [Real report:3-8,19-51][real-result].
- **Startup stall cause:** the earlier approximately 26-second blocked interval
  remains unexplained; later eight synthetic builds captured no qualifying
  unchanged D-state stall. Neither result proves a fix or a persistent regression.
  [Candidate report:73-77][candidate-gates]. Capture a useful wait-channel/syscall
  sample if it recurs and retain the full observed wall time.
- **Broad automated Docker comparison:** `tests/compatibility.py` still has no
  candidate adapter; compare mode reports blocked/unsupported. Focused Docker
  oracle fixtures already exist for features such as runtime metadata, so this
  does not mean no compatibility testing exists.
  [tests/compatibility.py:285-298][comparison-code];
  [tests/runtime_metadata_config.rs:61-85][metadata-tests].
- **Wider environment guarantees:** current observations do not establish every
  Pod/filesystem, all package-manager behaviors or full-build storage fit. Logical
  metadata sizing is not a calibrated RSS conversion; current-space checks reserve
  nothing and cannot enforce disk/memory quotas against arbitrary RUN growth.
  [docs/build-resources.md:5-15][resource-limits].
- **Abrupt failure and package-cache breadth:** handled failure/SIGTERM tests do
  not establish cleanup after SIGKILL/OOM/power loss. The documented mount suite
  does not claim a live pip/npm/apt cache-install equivalence oracle. Secrets can
  remain in private failed work after abrupt termination.
  [docs/run-mounts.md:126-161,174-176][mount-failure].

## Deliberate non-goals and operational limits

- Trusted builds and a cooperative stable local store are the contract. Hostile
  RUN isolation, malicious same-user writers and a general container runtime are
  not promises to add in this performance release.
  [README:5][project-scope]; [publication contract:53-61][session-contract].
- Verification and ownership boundaries are intentional: every new physical
  copy gets first-admission verification, final publication stays conservative,
  completed instruction prefixes remain durable, and public outputs have
  independent inodes. Public callback APIs do not inherit managed-session trust.
  [Publication contract:20-61][session-contract].
- Exact Docker history/layer counts, ctime preservation across checkpoints and
  automatic hits when preserved timestamps change are not promised.
  [README:407-452][checkpoint-contract].
- Resource observations are not reservations/quotas; cancellation cannot bound
  uninterruptible filesystem work or descendants. These constraints must remain
  visible rather than be described as solved by a faster COPY path.
  [docs/build-resources.md:5-15][resource-limits]; `src/main.rs:63-69`.
- Explicit cleanup already exists. Automatic GC and package-cache eviction are
  missing; legacy cache-v1, base-cache generations and unowned/unknown objects
  remain protected. Expanding deletion authority is later work, not a small
  checkpoint fix. [README:66][registry-doc], [557-564][retention-doc];
  [docs/run-mounts.md:83-89][package-retention].

## Next stable candidate: acceptance gates in order

These are proposed gates for the subsequent implementation owner, not completed
checks or authorization to allocate infrastructure or publish a release.

| Gate | Required evidence / pass condition |
| --- | --- |
| 1. Narrow optimization | A named supported small-COPY case avoids repeated inventory/payload processing of unrelated large files. Use deterministic counters plus a fixture that varies unrelated tree/payload size; identify remaining verification cost separately. Unknown writes/unsupported topology/budget exhaustion use the conservative path. No Dockerfile feature expansion or cache-format change is required by this plan. |
| 2. Preserve correctness | Compare optimized and conservative outputs, including raw/gzip, content, config, layer/diff IDs, ownership/modes, timestamps, xattrs, hardlinks/symlinks and directory effects. Test corruption, interruption, stale/invalid evidence, cumulative limits and fallback. Keep durable prefixes, source immutability and public-inode isolation. Existing anchors: [instruction-cache tests:693-880][correctness-tests], [publication fault tests:275-417][session-faults], [fallback/isolation tests:635-778][session-limits]. Add focused regressions for the new optimization's boundary. |
| 3. Local integration and synthetic measurements | Run locked Linux fmt/test/strict Clippy/rustdoc and selected ignored worker/mount/control tests; report skips explicitly. Repeat balanced baseline/candidate cold, warm, application-edit and no-cache cases with identical inputs and resources. Record complete wall/CPU/I/O/RSS, phase costs, retained storage and independent acceptance. Set a numerical performance target before the run; report every sample and unexplained delay. Existing synthetic success is a baseline, not this gate's result. [Prior gates][candidate-gates]; [measurement contract][measurement-contract]. |
| 4. Real workload | After qualifying final process counters, build the original pinned Nemotron workload with normal managed defaults and the explicit recorded timeout override. Complete cold export/publication within the existing 3,600-second whole-build cap; then complete unchanged warm and controlled application-edit runs and independent final-image acceptance. Retain source/binary/package hashes, output identities and complete metrics. Record GPU inference separately if claiming application readiness. No synthetic substitution or speed ratio against the unmatched historical no-cache run. [Required follow-up:140-146][real-followup]. |
| 5. Final artifacts | Select a new version, update notes and rebuild the exact final source through offline portable/deb installation, permissions, nonroot invocation, registry preflight/TLS roundtrip, fixture builds, checksum and corresponding-source gates. Preserve evidence for the actual packaged binary. Publication remains a separate authorized action. [Release requirements][release-decision]; [package checks:27-56][package-checks]. |

Later roadmap: extend the reference corpus with a Weld adapter; reconcile stale
overview wording; consider a concrete blocked syntax/mount/platform/format case;
evaluate explicit base/package-cache retirement and calibrated capacity guidance.
Any broader final-export, parallelism or remote-build/cache project needs its own
profile and measurements. None is silently included in the small-COPY change.

## Evidence precedence and audit checks

Stale statements must not become invented implementation gaps:

- [tests/fixtures/README.md:23-26][stale-fixtures] says the candidate has no build
  command. The current driver says **no adapter for this reference corpus**;
  the build command and integration tests exist. [README:262][test-scope] already
  makes that distinction.
- [README:467-471][stale-real] says full Nemotron has not been remeasured with
  managed publication reuse. The later real report records the attempted run,
  confirms that optimization was active, and records its timeout. Use that later
  evidence, not the older sentence. Historical design/performance notes describe
  their own revisions; they do not override the implemented session contract.
- [README:702-703][heredoc-limits] broadly excludes parser directives, but the
  current parser accepts the exact first-line syntax declaration described above.
  [src/build_plan.rs:360-372][directives] is the narrower current contract.

At this baseline, `git diff 5860971..a3ce37f -- src Cargo.toml Cargo.lock` is empty:
the later changes are documentation and sampler tests/code, not a new Rust
performance implementation. This connects the recorded candidate measurements
to the audited builder without relabeling their executable hashes or revisions.

For this documentation audit, the seven offline
`python -B tests/compatibility.py --self-test` tests passed, and compare mode
reported blocked/unsupported as expected. Rust fmt/Clippy/tests were not rerun:
`cargo` and `rustc` were absent from this Windows shell's PATH. Prior Linux pass
counts are cited evidence only. No Docker oracle, package install, benchmark,
GPU inference or cloud run was performed; no production code or tests changed.

[project-scope]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L3-L5
[real-result]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/real-nemotron-5860971.md#L3-L51
[real-timing]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/real-nemotron-5860971.md#L65-L99
[real-followup]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/real-nemotron-5860971.md#L140-L146
[candidate-identity]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/stable-candidate-validation.md#L3-L8
[candidate-gates]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/stable-candidate-validation.md#L20-L77
[release-decision]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/stable-candidate-validation.md#L95-L106
[build-profile]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L128-L203
[multistage-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/multistage_cli.rs#L114-L324
[platform-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/platform_cli.rs#L27-L53
[copy-contract]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/context.rs#L1-L24
[ignore-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/dockerignore_cli.rs#L139-L260
[copy-config-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/dockerfile_config.rs#L140-L219
[user-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/user_cli.rs#L350-L457
[metadata-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/runtime_metadata_config.rs#L61-L183
[directives]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/build_plan.rs#L360-L372
[heredoc-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/heredoc_cli.rs#L278-L413
[mount-parser]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/run_mounts.rs#L115-L210
[mount-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/run_mounts.rs#L65-L295
[checkpoint-contract]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L407-L485
[checkpoint-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/instruction_cache_engine.rs#L153-L280
[gzip-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/gzip_export_cli.rs#L99-L223
[base-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/base_cache.rs#L97-L299
[reuse-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/instruction_cache_engine.rs#L296-L624
[session-contract]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/publication-session-implementation.md#L11-L61
[session-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/publication_session_tests.rs#L25-L190
[registry-doc]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L64-L101
[cleanup-doc]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L518-L545
[cleanup-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/cache_cleanup.rs#L201-L386
[test-scope]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L251-L262
[parser-profile]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/build_plan.rs#L15-L22
[parser-dispatch]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/build_plan.rs#L532-L763
[parser-negative]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/build_plan.rs#L1085-L1119
[copy-parser]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/build_plan.rs#L596-L633
[path-rules]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/build.rs#L292-L350
[mount-limits]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/run-mounts.md#L43-L66
[heredoc-negative]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/heredoc_engine.rs#L33-L68
[heredoc-limits]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L687-L706
[compression]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/export_compression.rs#L18-L26
[registry-compression]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/registry.rs#L438-L449
[layer-rejections]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/layer.rs#L630-L689
[layer-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/layer_formats.rs#L192-L209
[registry-negative]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/registry.rs#L1747-L1787
[runtime-doc]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L199-L203
[buildkit-limit]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L513-L516
[cli-profile]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/main.rs#L35-L98
[checkpoint-path]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/build.rs#L3227-L3396
[delta-plan]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/export_delta.rs#L731-L758
[delta-hash]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/export_delta.rs#L297-L331
[sampler-report]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/real-nemotron-5860971.md#L101-L120
[sampler-code]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/fixtures/v02-performance/cold_metrics.py#L79-L108
[sampler-test]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/fixtures/v02-performance/test_proc_stall.py#L196-L227
[comparison-code]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/compatibility.py#L285-L298
[resource-limits]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/build-resources.md#L5-L15
[mount-failure]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/run-mounts.md#L126-L176
[retention-doc]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L557-L564
[package-retention]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/run-mounts.md#L83-L89
[correctness-tests]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/instruction_cache_engine.rs#L693-L880
[session-faults]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/publication_session_tests.rs#L275-L417
[session-limits]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/src/publication_session_tests.rs#L635-L778
[measurement-contract]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/managed-session-performance.md#L56-L102
[package-checks]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/docs/release-packaging-checks.md#L27-L56
[stale-fixtures]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/tests/fixtures/README.md#L23-L26
[stale-real]: https://github.com/kodxana/Runpod-Weld/blob/a3ce37f6a951a388a1c81d19ae93597fbd74914e/README.md#L467-L471
