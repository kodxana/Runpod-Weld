use serde_json::json;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static CANCELLED: AtomicBool = AtomicBool::new(false);

const HELP: &str = "Runpod Weld (rpweld) — development preview

Usage:
  rpweld doctor [--json]   Inspect Pod capabilities and cgroup resources
  rpweld scan [DOCKERFILE] [--json]   Check the initial Dockerfile profile
  rpweld --version
  rpweld --help

  rpweld images [--json]
  rpweld image inspect TAG [--json]
  rpweld cache ls [--json]
  rpweld cache du [--json]
  rpweld builds ls [--json]
  rpweld builds inspect BUILD_ID [--json]
  rpweld cache prune [--dry-run] [--json]
  rpweld builds prune [--dry-run] [--json]
  rpweld builds rm BUILD_ID [--dry-run] [--json]
  rpweld image rm TAG [--dry-run] [--json]

  rpweld login REGISTRY [--username USER] [--password-stdin] [--authfile FILE] [--cert-dir DIR]
  rpweld logout REGISTRY [--authfile FILE]
  rpweld push TAG [--authfile FILE] [--cert-dir DIR]
  rpweld build [-f DOCKERFILE] [-t TAG] [--push] [--authfile FILE] [--cert-dir DIR] CONTEXT

  rpweld build -f DOCKERFILE [--base NAME=LAYOUT] [--base-ref NAME=REFERENCE]
    --output NEWDIR --work-dir NEWDIR [--build-arg KEY=VALUE] [--host-dns] [--verbose]
    [--target STAGE] [--no-cache] [--pull] [--platform linux/amd64]
    [--max-rootfs-bytes N] [--max-layer-bytes N] [--metadata-budget N]
    [--run-timeout-seconds N] CONTEXT

Experimental build: Linux amd64, multi-stage, registry/local OCI bases or scratch.
Default Dockerfile: CONTEXT/Dockerfile. Verified cached bases are reused offline.
--pull refreshes base tags using verified TLS; digest references remain reusable.
Failed refreshes fail the build and preserve the previous base cache.
Managed builds create private state under RPWELD_HOME (default ~/.local/share/rpweld).
One -t tag per build; push retries use 'rpweld push TAG'. Images/work are retained.
Managed builds/push hold a persistent store lease; cross-store inputs are rejected.
Cancellation waits for all descendants; uninterruptible tasks can delay it indefinitely.
Managed defaults: 2 GiB rootfs/layer, 64 MiB metadata; temporary host DNS enabled
(--no-host-dns disables it). Explicit output/work without -t keep legacy defaults.
Bindings match ARG-expanded FROM names; --base-ref selects an OCI ref annotation.
Without --base-ref the layout must have an unambiguous image selection.
Local COPY supports plain/JSON paths, directory merges and multiple sources
(destination must end in /), relative to WORKDIR. Basic $NAME/${NAME} expansion
and Docker word quotes are supported; JSON embedded quotes/backslashes rejected.
Sources support bounded wildcards (*, ?, character classes); no parent paths or explicit symlinks.
COPY --chmod accepts octal modes; --chown resolves image users/groups. Both support ARG expansion.
.dockerignore filters local COPY sources. COPY --from accepts literal prior stages.
Global ARG expands FROM; stage ARG redeclares globals. SHELL JSON overrides subsequent
shell RUN/CMD/ENTRYPOINT. LABEL and shell/JSON CMD/ENTRYPOINT inherit from bases.
--target selects a named stage and its dependencies. Managed builds cache completed
stages locally; --no-cache bypasses stage reads/writes only. No container run command yet. COPY bytes/entries/metadata accumulate across steps
under the rootfs/layer limits; rootfs is also checked after each step.
Syntax/ignore checks precede mutation; later filesystem failures may follow RUN.
Legacy defaults: rootfs 268435456 bytes; layer/replay 268435456 bytes;
metadata 16777216 bytes per subsystem; 100000 entries; 1024 descriptors;
RUN timeout 300 seconds (maximum 86400). Budgets accept positive decimal bytes.
Dockerfile/parser source cap: 1048576 bytes. Parser/metadata budgets are
separate from RUN memory; no memory or disk quota enforcement is guaranteed.
Rootfs is checked between operations. No host RAM sizing or capacity guesses.
Trusted images/commands and stable paths required; this is not a sandbox.
Work/output must be new, disjoint paths outside context/base; failures retain them.
Doctor is read-only. Observed resource limits are not per-build enforcement.
Storage inspection is read-only, Linux-only, bounded best-effort observation.
Missing stores are empty. Inspect uses an exact normalized tag or full build ID.
Complete means structurally complete, not digest-verified. Unknown stays unknown.
Usage is not reclaimable space. Cleanup applies unless --dry-run is specified.
";

fn execute(args: &[String], out: &mut impl Write) -> Result<(), String> {
    match args {
        [] => write!(out, "{HELP}").map_err(|e| e.to_string()),
        [arg] if arg == "--help" || arg == "-h" => write!(out, "{HELP}").map_err(|e| e.to_string()),
        [arg] if arg == "--version" || arg == "-V" => {
            writeln!(out, "rpweld {}", env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())
        }
        [cmd] if cmd == "doctor" => doctor(out, false),
        [cmd, flag] if cmd == "doctor" && flag == "--json" => doctor(out, true),
        [cmd, rest @ ..] if cmd == "scan" => scan(rest, out),
        [cmd, rest @ ..] if cmd == "build" => run_build(rest, out),
        [cmd, rest @ ..] if ["images", "image", "cache", "builds"].contains(&cmd.as_str()) => {
            storage_command(cmd, rest, out)
        }
        [cmd, rest @ ..] if ["login", "logout", "push"].contains(&cmd.as_str()) => {
            registry_command(cmd, rest, out)
        }
        [cmd, ..] if cmd == "run" => Err(format!(
            "'{cmd}' is not implemented in this development preview; no build or container was started"
        )),
        _ => Err("unrecognized command or option; use 'rpweld --help'".into()),
    }
}

fn storage_command(cmd: &str, args: &[String], out: &mut impl Write) -> Result<(), String> {
    if args.first().is_some_and(|s| s == "prune" || s == "rm") {
        return cleanup_command(cmd, args, out);
    }
    use rpweld::store_inventory::{Limits, inspect_existing};
    let json_output = args.last().is_some_and(|v| v == "--json");
    let args = if json_output {
        &args[..args.len() - 1]
    } else {
        args
    };
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let (operation, lookup) = match (cmd, words.as_slice()) {
        ("images", []) => ("images", None),
        ("image", ["inspect", tag]) if !tag.starts_with('-') => {
            ("image", Some(rpweld::registry::reference(tag, false)?))
        }
        ("cache", ["ls"]) => ("cache", None),
        ("cache", ["du"]) => ("usage", None),
        ("builds", ["ls"]) => ("builds", None),
        ("builds", ["inspect", id])
            if id.starts_with("build-")
                && !id.contains(['/', '\\'])
                && !id.chars().any(char::is_control) =>
        {
            ("build", Some((*id).to_owned()))
        }
        _ => return Err("invalid storage command or option; use 'rpweld --help'".into()),
    };
    if !cfg!(target_os = "linux") {
        return Err(
            "storage inventory is unsupported on this platform; requires Linux openat2".into(),
        );
    }
    let inventory = inspect_existing(Limits::default(), || CANCELLED.load(Ordering::Relaxed))
        .map_err(|e| format!("cannot inspect store: {e}"))?;
    // Convert fallibly before json!: its Serialize errors would otherwise panic.
    let serialized = serde_json::to_value(&inventory).map_err(|e| e.to_string())?;
    let data = match operation {
        "images" => json!({"tags": serialized["tags"]}),
        "image" => {
            json!({"tag": serde_json::to_value(inventory.image_inspect(lookup.as_deref().unwrap())
            .ok_or("image tag not found in observed store (lookup uses exact normalized tags)")?)
            .map_err(|e| e.to_string())?})
        }
        "cache" => {
            json!({"base_refs": serialized["base_refs"], "generations": serialized["generations"],
            "stages": serialized["stages"]})
        }
        "usage" => json!({"usage": serialized["cache_usage"]}),
        "builds" => json!({"builds": serialized["builds"]}),
        "build" => {
            json!({"build": serde_json::to_value(inventory.build_inspect(lookup.as_deref().unwrap())
            .ok_or("build ID not found in observed store")?).map_err(|e| e.to_string())?})
        }
        _ => unreachable!(),
    };
    let report = json!({"schema_version": 1, "store": serialized["store"],
        "status": serialized["status"], "best_effort": serialized["best_effort"],
        "partial": serialized["partial"], "issues": serialized["issues"], "data": data});
    if json_output {
        serde_json::to_writer_pretty(&mut *out, &report).map_err(|e| e.to_string())?;
        return writeln!(out).map_err(|e| e.to_string());
    }
    // JSON escapes U+0000..001F; also escape DEL and non-ASCII for terminals.
    let safe = |value: &serde_json::Value| {
        value
            .to_string()
            .chars()
            .map(|c| {
                if c.is_ascii() && !c.is_ascii_control() {
                    c.to_string()
                } else {
                    c.escape_default().to_string()
                }
            })
            .collect::<String>()
    };
    writeln!(
        out,
        "Store {}: {} (best effort; partial={})",
        safe(&report["store"]),
        safe(&report["status"]),
        report["partial"]
    )
    .map_err(|e| e.to_string())?;
    for (kind, value) in report["data"].as_object().unwrap() {
        if let Some(rows) = value.as_array() {
            writeln!(out, "{kind}: {}", rows.len()).map_err(|e| e.to_string())?;
            for row in rows {
                writeln!(out, "  {}", safe(row)).map_err(|e| e.to_string())?;
            }
        } else {
            writeln!(out, "{kind}: {}", safe(value)).map_err(|e| e.to_string())?;
        }
    }
    for issue in report["issues"].as_array().unwrap() {
        writeln!(out, "issue: {}", safe(issue)).map_err(|e| e.to_string())?;
    }
    writeln!(out, "Complete = structural only, not digest-verified; ownership/targets may be unknown.\nAll entries protected; usage is not reclaimable space.").map_err(|e| e.to_string())
}

fn cleanup_command(cmd: &str, args: &[String], out: &mut impl Write) -> Result<(), String> {
    use rpweld::cleanup_plan::{BuildId, Request, TagId};
    let mut dry_run = false;
    let mut machine = false;
    let mut words = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--dry-run" if !dry_run => dry_run = true,
            "--json" if !machine => machine = true,
            word if !word.starts_with('-') => words.push(word),
            _ => return Err("invalid cleanup option; use 'rpweld --help'".into()),
        }
    }
    let request = match (cmd, words.as_slice()) {
        ("cache", ["prune"]) => Request::CachePrune,
        ("builds", ["prune"]) => Request::BuildsPrune,
        ("builds", ["rm", id]) => Request::BuildRemove(BuildId::parse(id)?),
        ("image", ["rm", tag]) => Request::ImageRemove(TagId::parse(tag)?),
        _ => return Err("invalid cleanup command; use 'rpweld --help'".into()),
    };
    let store = rpweld::store_inventory::resolve_store().map_err(|e| e.to_string())?;
    if !dry_run {
        let report = rpweld::cleanup_apply::apply(
            &store,
            request,
            rpweld::store_inventory::Limits::default(),
            || CANCELLED.load(Ordering::Relaxed),
        )
        .map_err(|e| format!("cannot apply cleanup: {e}"))?;
        if machine {
            serde_json::to_writer_pretty(&mut *out, &report).map_err(|e| e.to_string())?;
            writeln!(out).map_err(|e| e.to_string())?;
        } else {
            writeln!(
                out,
                "Cleanup: {}. {} complete removals; {} recovered transactions.",
                report.status,
                report.removed.len(),
                report.recovered.len()
            )
            .map_err(|e| e.to_string())?;
            for item in &report.removed {
                let safe = serde_json::to_string(item).map_err(|e| e.to_string())?;
                writeln!(out, "removed: {}", safe.escape_default()).map_err(|e| e.to_string())?;
            }
            writeln!(out, "Protected entries and unknown siblings retained. Plan quantities are estimates, not guaranteed freed bytes.").map_err(|e| e.to_string())?;
        }
        return match report.failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        };
    }
    let plan = rpweld::cleanup_plan::inspect(
        &store,
        request,
        rpweld::store_inventory::Limits::default(),
        || CANCELLED.load(Ordering::Relaxed),
    )
    .map_err(|e| format!("cannot plan cleanup: {e}"))?;
    if machine {
        serde_json::to_writer_pretty(&mut *out, &plan).map_err(|e| e.to_string())?;
        writeln!(out).map_err(|e| e.to_string())?;
    } else {
        writeln!(
            out,
            "Dry run: {}. {} candidates; {} protected. Nothing changed.",
            plan.status,
            plan.candidates.len(),
            plan.protected.len()
        )
        .map_err(|e| e.to_string())?;
        for (kind, items) in [
            ("candidate", &plan.candidates),
            ("protected", &plan.protected),
        ] {
            for item in items {
                let safe: String = serde_json::to_string(item)
                    .map_err(|e| e.to_string())?
                    .chars()
                    .flat_map(char::escape_default)
                    .collect();
                writeln!(out, "{kind}: {safe}").map_err(|e| e.to_string())?;
            }
        }
        writeln!(out, "Selected unique logical bytes: {}; estimated reclaim: {}..{} bytes (not a promise).\nPoint-in-time plan, not authorization; future deletion requires a fresh scan.", plan.estimate.unique_logical_bytes, plan.estimate.reclaim_lower_bytes, plan.estimate.reclaim_upper_bytes.map_or_else(|| "unknown".into(), |n| n.to_string())).map_err(|e| e.to_string())?;
    }
    if plan.status == "store_busy" {
        return Err("store busy; nothing selected; no force option".into());
    }
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct BuildCli {
    record: Option<rpweld::build_record::BuildRecord>,
    dockerfile: String,
    options: rpweld::build::BuildOptions,
    tag: Option<String>,
    push: bool,
    pull: bool,
    registry: rpweld::registry::Options,
}

fn parse_build_args(args: &[String]) -> Result<BuildCli, String> {
    let mut values = BTreeMap::new();
    let mut bases = BTreeMap::new();
    let mut references = BTreeMap::new();
    let mut build_args = BTreeMap::new();
    let mut context = None;
    let mut host_dns = false;
    let mut no_host_dns = false;
    let mut no_cache = false;
    let mut verbose = false;
    let mut push = false;
    let mut pull = false;
    let mut positional = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg.contains('\0') {
            return Err("NUL in argument".into());
        }
        if !positional && arg == "--" {
            positional = true;
            continue;
        }
        if !positional && arg == "--push" {
            if push {
                return Err("duplicate --push".into());
            }
            push = true;
        } else if !positional && arg == "--pull" {
            if pull {
                return Err("duplicate --pull".into());
            }
            pull = true;
        } else if !positional && arg == "--no-cache" {
            no_cache = true;
        } else if !positional && arg == "--verbose" {
            verbose = true;
        } else if !positional && arg == "--no-host-dns" {
            if no_host_dns {
                return Err("duplicate --no-host-dns".into());
            }
            no_host_dns = true;
        } else if !positional && arg == "--host-dns" {
            if host_dns {
                return Err("duplicate --host-dns".into());
            }
            host_dns = true;
        } else if !positional && arg.starts_with('-') {
            if ![
                "-f",
                "--base",
                "--base-ref",
                "--output",
                "--work-dir",
                "--build-arg",
                "--max-rootfs-bytes",
                "--max-layer-bytes",
                "--metadata-budget",
                "--run-timeout-seconds",
                "-t",
                "--tag",
                "--authfile",
                "--cert-dir",
                "--target",
                "--platform",
            ]
            .contains(&arg.as_str())
            {
                return Err(format!("unknown build option: {arg}"));
            }
            let value = iter
                .next()
                .filter(|v| !v.is_empty() && !v.starts_with('-') && !v.contains('\0'))
                .ok_or_else(|| format!("missing value for {arg}"))?;
            if ["--base", "--base-ref", "--build-arg"].contains(&arg.as_str()) {
                let (key, val) = value
                    .split_once('=')
                    .ok_or_else(|| format!("{arg} requires NAME=VALUE"))?;
                if key.is_empty()
                    || key.chars().any(char::is_whitespace)
                    || (arg != "--build-arg" && val.is_empty())
                {
                    return Err(format!("invalid {arg} mapping"));
                }
                if arg == "--build-arg"
                    && !key.chars().enumerate().all(|(i, c)| {
                        c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                    })
                {
                    return Err("invalid build argument name".into());
                }
                let map = match arg.as_str() {
                    "--base" => &mut bases,
                    "--base-ref" => &mut references,
                    _ => &mut build_args,
                };
                if map.insert(key.to_owned(), val.to_owned()).is_some() {
                    return Err(format!("duplicate {arg} name: {key}"));
                }
            } else if values
                .insert(
                    if arg == "--tag" { "-t" } else { arg.as_str() },
                    value.as_str(),
                )
                .is_some()
            {
                return Err(format!("duplicate {arg}"));
            }
        } else if arg.is_empty() || context.replace(arg.clone()).is_some() {
            return Err("exactly one context directory is required".into());
        }
    }
    if values
        .get("--platform")
        .is_some_and(|v| *v != "linux/amd64")
    {
        return Err(
            "only --platform linux/amd64 is supported; cross-architecture execution is unavailable"
                .into(),
        );
    }
    let context: std::path::PathBuf = context.ok_or("missing context directory")?.into();
    let dockerfile = values
        .get("-f")
        .map(|s| s.to_string())
        .unwrap_or_else(|| context.join("Dockerfile").to_string_lossy().into_owned());
    let output = values.get("--output").copied().unwrap_or("").into();
    let work = values.get("--work-dir").copied().unwrap_or("").into();
    let tag = values
        .get("-t")
        .map(|s| rpweld::registry::reference(s, false))
        .transpose()?;
    if push && tag.is_none() {
        return Err("--push requires -t TAG".into());
    }
    if no_host_dns && host_dns {
        return Err("--host-dns conflicts with --no-host-dns".into());
    }
    let managed =
        tag.is_some() || !values.contains_key("--output") || !values.contains_key("--work-dir");
    host_dns = host_dns || (managed && !no_host_dns);
    let budget = |key, default: u64| -> Result<u64, String> {
        match values.get(key) {
            None => Ok(default),
            Some(v) if v.bytes().all(|c| c.is_ascii_digit()) => v
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("invalid positive budget: {key}")),
            _ => Err(format!("invalid positive budget: {key}")),
        }
    };
    let default_bytes = if managed {
        2 * 1024 * 1024 * 1024
    } else {
        256 * 1024 * 1024
    };
    let root = budget("--max-rootfs-bytes", default_bytes)?;
    let layer = budget("--max-layer-bytes", default_bytes)?;
    let metadata = budget(
        "--metadata-budget",
        if managed {
            64 * 1024 * 1024
        } else {
            16 * 1024 * 1024
        },
    )?;
    let plan_bytes =
        usize::try_from(metadata).map_err(|_| "metadata budget exceeds platform size")?;
    let timeout = budget("--run-timeout-seconds", 300)?;
    if timeout > 86400 {
        return Err("RUN timeout must be 1..86400 seconds".into());
    }
    for name in references.keys() {
        if !bases.contains_key(name) {
            return Err(format!("--base-ref has no --base binding: {name}"));
        }
    }
    if bases.contains_key("scratch") {
        return Err("scratch cannot have a base binding".into());
    }
    Ok(BuildCli {
        record: None,
        dockerfile: dockerfile.clone(),
        tag,
        push,
        pull,
        registry: rpweld::registry::Options {
            authfile: values.get("--authfile").map(std::path::PathBuf::from),
            cert_dir: values.get("--cert-dir").map(std::path::PathBuf::from),
        },
        options: rpweld::build::BuildOptions {
            dockerfile: Some(dockerfile.into()),
            work,
            output,
            context,
            host_dns,
            verbose,
            target: values.get("--target").map(|s| s.to_string()),
            cache: None,
            no_cache,
            args: build_args,
            bases: bases
                .into_iter()
                .map(|(name, layout)| {
                    let reference = references.remove(&name);
                    (
                        name,
                        rpweld::build::LocalBase {
                            layout: layout.into(),
                            reference,
                        },
                    )
                })
                .collect(),
            limits: rpweld::build::Limits {
                image: rpweld::image::Limits {
                    max_metadata_bytes: metadata,
                    max_total_metadata_bytes: metadata,
                    max_descriptors: 1024,
                    max_layer_bytes: layer,
                    max_total_layer_bytes: layer,
                },
                layer: rpweld::layer::Limits {
                    max_blob_bytes: layer,
                    max_uncompressed_bytes: layer,
                    max_entries: 100_000,
                    max_metadata_bytes: metadata,
                    max_gzip_header_bytes: 65536,
                },
                export: rpweld::export::Limits {
                    max_layer_bytes: layer,
                    max_entries: 100_000,
                    max_metadata_bytes: metadata,
                },
                max_replay_bytes: layer,
                max_replay_entries: 100_000,
                max_rootfs_bytes: root,
                max_rootfs_entries: 100_000,
                max_plan_bytes: plan_bytes,
                run_timeout_seconds: timeout,
            },
        },
    })
}

fn read_build_source(path: &str) -> Result<String, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOATIME);
    }
    let file = options.open(path).map_err(|e| format!("{path}: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("{path}: expected a regular Dockerfile"));
    }
    let cap = rpweld::build_plan::MAX_SOURCE_BYTES;
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > cap {
        return Err(format!(
            "Dockerfile exceeds parser source limit ({cap} bytes)"
        ));
    }
    String::from_utf8(bytes).map_err(|_| format!("{path}: expected UTF-8"))
}

fn run_build(args: &[String], out: &mut impl Write) -> Result<(), String> {
    if args == ["--help"] || args == ["-h"] {
        return write!(out, "{HELP}").map_err(|e| e.to_string());
    }
    let mut cli = parse_build_args(args)?;
    // An explicitly selected Dockerfile can itself be a managed input.
    let early_lease = source_lease(std::path::Path::new(&cli.dockerfile))?;
    let source = read_build_source(&cli.dockerfile)?;
    let lease = prepare_build(&source, &mut cli, early_lease, out)?;
    let result = match lease.as_ref() {
        Some(lease) => {
            #[cfg(target_os = "linux")]
            if let Some(r) = cli.record.as_mut() {
                rpweld::build::build_recorded(&source, &cli.options, lease, r, || {
                    CANCELLED.load(Ordering::Relaxed)
                })
            } else {
                rpweld::build::build_with_lease(&source, &cli.options, lease, || {
                    CANCELLED.load(Ordering::Relaxed)
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                rpweld::build::build_with_lease(&source, &cli.options, lease, || {
                    CANCELLED.load(Ordering::Relaxed)
                })
            }
        }
        None => rpweld::build::build(&source, &cli.options, || CANCELLED.load(Ordering::Relaxed)),
    }
    .map_err(|e| e.to_string());
    let result = result?;
    writeln!(
        out,
        "Experimental OCI build: {}\nManifest: {}\nRetained work: {}",
        result.output.display(),
        result.manifest.digest,
        result.work.display()
    )
    .map_err(|e| e.to_string())?;
    let finished = finish_build(&mut cli, lease.as_ref(), out);
    #[cfg(target_os = "linux")]
    if let (Some(r), Some(l)) = (cli.record.as_mut(), lease.as_ref()) {
        r.update(l, |r| {
            if finished.is_ok() {
                r.phase = rpweld::build_record::Phase::Complete;
            }
        })
        .map_err(|e| e.to_string())?;
    }
    finished
}

#[cfg(target_os = "linux")]
fn source_lease(path: &std::path::Path) -> Result<Option<rpweld::store_lease::StoreLease>, String> {
    if rpweld::store_access::validate_path(path, None).is_ok() {
        return Ok(None);
    }
    let store = rpweld::registry::store_dir()?;
    let lease =
        rpweld::store_lease::StoreLease::shared(&store, &|| CANCELLED.load(Ordering::Relaxed))
            .map_err(|e| e.to_string())?;
    rpweld::store_access::validate_path(path, Some(&lease)).map_err(|e| e.to_string())?;
    Ok(Some(lease))
}
#[cfg(not(target_os = "linux"))]
fn source_lease(_: &std::path::Path) -> Result<Option<rpweld::store_lease::StoreLease>, String> {
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
fn prepare_build(
    _: &str,
    _: &mut BuildCli,
    _: Option<rpweld::store_lease::StoreLease>,
    _: &mut impl Write,
) -> Result<Option<rpweld::store_lease::StoreLease>, String> {
    Err("build requires Linux amd64".into())
}
#[cfg(not(target_os = "linux"))]
fn finish_build(
    _: &mut BuildCli,
    _: Option<&rpweld::store_lease::StoreLease>,
    _: &mut impl Write,
) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_build(
    source: &str,
    cli: &mut BuildCli,
    early_lease: Option<rpweld::store_lease::StoreLease>,
    out: &mut impl Write,
) -> Result<Option<rpweld::store_lease::StoreLease>, String> {
    use rpweld::{build_plan::Base, registry};
    let plan =
        rpweld::build::resolve_plan(source, &cli.options.args, cli.options.limits.max_plan_bytes)
            .map_err(|e| e.to_string())?;
    let selected = rpweld::build::selected_stages(&plan, cli.options.target.as_deref())
        .map_err(|e| e.to_string())?;
    let mut pulls = std::collections::BTreeSet::new();
    for n in selected {
        if let Base::Image(name) = &plan.stages[n].base
            && name != "scratch"
            && !cli.options.bases.contains_key(name)
        {
            pulls.insert(name.clone());
        }
    }
    let pull = !pulls.is_empty();
    if let Some(cert_dir) = &cli.registry.cert_dir {
        let context = std::fs::canonicalize(&cli.options.context).map_err(|e| e.to_string())?;
        let cert_dir = std::fs::canonicalize(cert_dir).map_err(|e| e.to_string())?;
        if cert_dir.starts_with(&context) {
            return Err(
                "certificate directory must be outside the build context to prevent COPY leaking credentials"
                    .into(),
            );
        }
        cli.registry.cert_dir = Some(cert_dir);
    }
    let managed = early_lease.is_some()
        || cli.options.output.as_os_str().is_empty()
        || cli.options.work.as_os_str().is_empty()
        || cli.tag.is_some()
        || cli.registry.authfile.is_some()
        || pull
        || [&cli.options.work, &cli.options.output, &cli.options.context]
            .into_iter()
            .chain(cli.options.bases.values().map(|b| &b.layout))
            .filter(|p| !p.as_os_str().is_empty())
            .any(|p| rpweld::store_access::validate_path(p, None).is_err());
    if !managed {
        // The library validates explicit paths too; managed inputs never opt out.
        return Ok(None);
    }
    let context = std::fs::canonicalize(&cli.options.context).map_err(|e| e.to_string())?;
    let store = registry::store_dir()?;
    let lease = match early_lease {
        Some(lease) => lease,
        None => {
            rpweld::store_lease::StoreLease::shared(&store, &|| CANCELLED.load(Ordering::Relaxed))
                .map_err(|e| e.to_string())?
        }
    };
    rpweld::store_access::validate_root(&store, &lease).map_err(|e| e.to_string())?;
    for path in [&cli.options.work, &cli.options.output, &cli.options.context]
        .into_iter()
        .chain(cli.options.bases.values().map(|b| &b.layout))
    {
        if !path.as_os_str().is_empty() {
            rpweld::store_access::validate_path(path, Some(&lease)).map_err(|e| e.to_string())?;
        }
    }
    if store.starts_with(&context) || context.starts_with(&store) {
        return Err(
            "build context and Weld store must be disjoint; set RPWELD_HOME outside the context"
                .into(),
        );
    }
    cli.options.cache = Some(registry::private_dir(&store.join("cache-v1"))?);
    let auth = registry::auth_path(&cli.registry)?;
    registry::check_cache_secret_paths(&cli.registry, &store)?;
    if auth.starts_with(&context) {
        return Err(
            "authfile must be outside the build context to prevent COPY leaking credentials".into(),
        );
    }
    cli.record = Some(
        rpweld::build_record::BuildRecord::allocate(
            &store,
            &lease,
            (!cli.options.work.as_os_str().is_empty()).then_some(cli.options.work.as_path()),
            (!cli.options.output.as_os_str().is_empty()).then_some(cli.options.output.as_path()),
            cli.tag.iter().cloned().collect(),
            cli.push,
        )
        .map_err(|e| e.to_string())?,
    );
    let run = cli.record.as_ref().unwrap().path.clone();
    let preparation = (|| -> Result<(), String> {
        writeln!(out, "Build state: {}", run.display()).map_err(|e| e.to_string())?;
        if cli.options.work.as_os_str().is_empty() {
            cli.options.work = run.join("work");
        }
        if cli.options.output.as_os_str().is_empty() {
            cli.options.output = run.join("image");
        }
        let mut resolved = BTreeMap::new();
        for name in pulls {
            let reference = registry::reference(&name, true)?;
            let layout = if let Some(layout) = resolved.get(&reference) {
                std::path::PathBuf::clone(layout)
            } else {
                let layout = registry::cached_base(
                    &store,
                    &lease,
                    &reference,
                    cli.pull,
                    cli.options.limits.image,
                    || CANCELLED.load(Ordering::Relaxed),
                    |reference, layout| {
                        writeln!(out, "Pulling {reference} (linux/amd64, verified TLS)...")
                            .map_err(|e| e.to_string())?;
                        out.flush().map_err(|e| e.to_string())?;
                        registry::Transport::new(&cli.registry)?.pull(
                            &lease,
                            reference,
                            layout,
                            &|| CANCELLED.load(Ordering::Relaxed),
                        )
                    },
                )?;
                resolved.insert(reference, layout.clone());
                layout
            };
            cli.options.bases.insert(
                name.clone(),
                rpweld::build::LocalBase {
                    layout,
                    reference: None,
                },
            );
        }
        Ok(())
    })();
    if preparation.is_err() {
        cli.record
            .as_mut()
            .unwrap()
            .update(&lease, |r| r.phase = rpweld::build_record::Phase::Failed)
            .map_err(|e| e.to_string())?;
    }
    preparation?;
    Ok(Some(lease))
}

#[cfg(target_os = "linux")]
fn finish_build(
    cli: &mut BuildCli,
    lease: Option<&rpweld::store_lease::StoreLease>,
    out: &mut impl Write,
) -> Result<(), String> {
    if let Some(tag) = &cli.tag {
        let store = rpweld::registry::store_dir()?;
        let lease = lease.ok_or("tagging requires store lease")?;
        rpweld::registry::save_tag(&store, lease, tag, &cli.options.output)?;
        writeln!(out, "Tagged {tag}").map_err(|e| e.to_string())?;
        if cli.push {
            let pushed = push_image_path(lease, tag, &cli.options.output, &cli.registry, out);
            if let Some(r) = cli.record.as_mut() {
                r.update(lease, |r| {
                    r.push = if pushed.is_ok() {
                        rpweld::build_record::PushResult::Succeeded
                    } else {
                        rpweld::build_record::PushResult::Failed
                    }
                })
                .map_err(|e| e.to_string())?;
            }
            pushed?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn push_image(
    tag: &str,
    options: &rpweld::registry::Options,
    out: &mut impl Write,
) -> Result<(), String> {
    let store = rpweld::registry::store_dir()?;
    let lease =
        rpweld::store_lease::StoreLease::shared(&store, &|| CANCELLED.load(Ordering::Relaxed))
            .map_err(|e| e.to_string())?;
    let image = rpweld::registry::tagged_image(&store, &lease, tag)?;
    push_image_path(&lease, tag, &image, options, out)
}

#[cfg(target_os = "linux")]
fn push_image_path(
    lease: &rpweld::store_lease::StoreLease,
    tag: &str,
    image: &std::path::Path,
    options: &rpweld::registry::Options,
    out: &mut impl Write,
) -> Result<(), String> {
    // Verify local content before sending. Skopeo then verifies transfer digests.
    rpweld::image::load_layout(
        image,
        None,
        rpweld::image::Limits {
            max_metadata_bytes: 64 * 1024 * 1024,
            max_total_metadata_bytes: 64 * 1024 * 1024,
            max_descriptors: 1024,
            max_layer_bytes: u64::MAX,
            max_total_layer_bytes: u64::MAX,
        },
        || CANCELLED.load(Ordering::Relaxed),
    )
    .map_err(|e| e.to_string())?;
    writeln!(out, "Pushing {tag} (verified TLS)...").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    rpweld::registry::Transport::new(options)?
        .push(lease, tag, image, &|| CANCELLED.load(Ordering::Relaxed))?;
    writeln!(out, "Pushed {tag}").map_err(|e| e.to_string())
}

fn registry_command(cmd: &str, args: &[String], out: &mut impl Write) -> Result<(), String> {
    if args == ["--help"] || args == ["-h"] {
        return write!(out, "{HELP}").map_err(|e| e.to_string());
    }
    let mut options = rpweld::registry::Options::default();
    let mut target = None;
    let mut username = None;
    let mut password_stdin = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--authfile" | "--cert-dir" | "--username" | "-u" => {
                let v=iter.next().filter(|s|!s.is_empty() && !s.starts_with('-') && !s.contains('\0')).ok_or("missing option value")?;
                match arg.as_str() {
                    "--authfile" if options.authfile.is_none()=>options.authfile=Some(v.into()),
                    "--cert-dir" if options.cert_dir.is_none()=>options.cert_dir=Some(v.into()),
                    "--username" | "-u" if cmd=="login" && username.is_none()=>username=Some(v.as_str()),
                    _=>return Err("duplicate or unsupported registry option".into()),
                }
            },
            "--password-stdin" if cmd=="login" && !password_stdin=>password_stdin=true,
            v if !v.starts_with('-') && target.is_none()=>target=Some(v),
            _=>return Err("invalid registry arguments; passwords must use a hidden prompt or --password-stdin".into()),
        }
    }
    let target = target.ok_or("registry hostname or image tag required")?;
    let target = if cmd == "push" {
        rpweld::registry::reference(target, false)?
    } else {
        rpweld::registry::registry(target)?
    };
    #[cfg(target_os = "linux")]
    {
        match cmd {
            "login" => {
                rpweld::registry::login(&target, username, password_stdin, &options, &|| {
                    CANCELLED.load(Ordering::Relaxed)
                })?;
                writeln!(out,"Logged in to {target}. File credentials are encoded, not encrypted; configure credHelpers for external storage.").map_err(|e|e.to_string())
            }
            "logout" => {
                rpweld::registry::logout(&target, &options, &|| CANCELLED.load(Ordering::Relaxed))?;
                writeln!(out, "Logged out of {target}").map_err(|e| e.to_string())
            }
            "push" => push_image(&target, &options, out),
            _ => unreachable!(),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target, options, username, password_stdin, out);
        Err("registry operations require Linux".into())
    }
}

#[cfg(target_os = "linux")]
fn install_build_signals() -> Result<(), String> {
    extern "C" fn cancel(_: libc::c_int) {
        CANCELLED.store(true, Ordering::Relaxed);
    }
    // The handler performs only a lock-free atomic store, never allocation or I/O.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = cancel as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }
    }
    Ok(())
}

fn scan(args: &[String], out: &mut impl Write) -> Result<(), String> {
    let mut path = None;
    let mut machine = false;
    for arg in args {
        if arg == "--json" && !machine {
            machine = true;
        } else if !arg.starts_with('-') && path.is_none() {
            path = Some(arg.as_str());
        } else {
            return Err("usage: rpweld scan [DOCKERFILE] [--json]".into());
        }
    }
    let path = path.unwrap_or("Dockerfile");
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Opening a FIFO must not block before the regular-file check.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| format!("{path}: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("{path}: expected a regular Dockerfile"));
    }
    let mut bytes = Vec::new();
    file.take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1_048_576 {
        return Err("Dockerfile exceeds the 1 MiB scan limit".into());
    }
    let source = std::str::from_utf8(&bytes).map_err(|e| format!("{path}: expected UTF-8: {e}"))?;
    render_scan(path, source, machine, out)
}

fn render_scan(
    path: &str,
    source: &str,
    machine: bool,
    out: &mut impl Write,
) -> Result<(), String> {
    let report =
        serde_json::to_value(rpweld::dockerfile::scan(source)).map_err(|e| e.to_string())?;
    if machine {
        serde_json::to_writer_pretty(&mut *out, &json!({"path": path, "report": report}))
            .map_err(|e| e.to_string())?;
        writeln!(out).map_err(|e| e.to_string())?;
    } else {
        writeln!(out, "{path}: initial Dockerfile profile scan\nThis is a partial static check, not experimental build readiness.").map_err(|e| e.to_string())?;
        if let Some(diagnostics) = report["diagnostics"].as_array() {
            for item in diagnostics {
                writeln!(
                    out,
                    "{}:{}: {} [{}] {}",
                    path,
                    item["line"],
                    item["severity"].as_str().unwrap_or("diagnostic"),
                    item["code"].as_str().unwrap_or("unknown"),
                    item["message"].as_str().unwrap_or("")
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    if report["policy_status"] != "no_known_policy_issues" || report["scan_complete"] != true {
        return Err(
            "Dockerfile has compatibility errors or requires review; no build was started".into(),
        );
    }
    Ok(())
}

fn doctor(out: &mut impl Write, machine: bool) -> Result<(), String> {
    let report = json!({
        "schema_version": 1,
        "tool": "rpweld",
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": rpweld::capabilities::inspect(),
        "resources": rpweld::resources::discover(),
    });
    if machine {
        serde_json::to_writer_pretty(&mut *out, &report).map_err(|e| e.to_string())?;
        writeln!(out).map_err(|e| e.to_string())
    } else {
        write!(out, "{}", summary(&report)).map_err(|e| e.to_string())
    }
}

fn summary(report: &serde_json::Value) -> String {
    let resources = &report["resources"];
    if resources["supported"] != true {
        return "Runpod Weld — resource inspection requires Linux.\nUse --json for diagnostic details.\n".into();
    }
    let bytes = |value: &serde_json::Value| {
        value
            .as_u64()
            .map(|n| format!("{:.2} GiB ({n} bytes)", n as f64 / 1_073_741_824.0))
            .unwrap_or_else(|| "unknown".into())
    };
    let cpus = resources["cpu"]["observed_capacity_cpus"]
        .as_f64()
        .map(|n| format!("{n:.2}"))
        .unwrap_or_else(|| "unknown".into());
    let mut result = format!(
        "Runpod Weld — environment report\nCPU capacity observed: {cpus}\nMemory ceiling observed: {}\nMemory headroom observed: {}\nEnforcement: observe-only; shared Pod limits\n",
        bytes(&resources["memory"]["observed_hard_ceiling_bytes"]),
        bytes(&resources["memory"]["observed_operating_headroom_bytes"])
    );
    let nofile = &report["capabilities"]["nofile"];
    let limit = |v: &serde_json::Value| match (v.as_u64(), v.as_str()) {
        (Some(n), _) => n.to_string(),
        (_, Some("unlimited")) => "unlimited".into(),
        _ => "unknown".into(),
    };
    result.push_str(&format!(
        "Open-file limits observed: soft {}, hard {} (per process)\nReplay adjusts soft only as needed within hard; GPU/CPU/RAM size does not set this ceiling.\n",
        limit(&nofile["soft"]), limit(&nofile["hard"])
    ));
    if resources["memory"]["explicit_budget_required"] == true {
        result.push_str("Automatic memory sizing unavailable; an explicit budget is required.\n");
    }
    if let Some(warnings) = resources["warnings"].as_array() {
        for warning in warnings.iter().filter_map(|v| v.as_str()) {
            result.push_str(&format!("Warning: {warning}\n"));
        }
    }
    result.push_str("Experimental build supports multi-stage registry/local OCI or scratch with restricted local COPY; no multistage. See build --help for registry and COPY options. RUN resources require external enforcement. Use --json for raw observations.\n");
    result
}

fn main() {
    // The tracer owns process-wide signal and child-reaping state. Dispatch only
    // in a fresh executable, before the builder initializes threads or children.
    #[cfg(target_os = "linux")]
    {
        let mut args = std::env::args_os().skip(1);
        if args.next().as_deref() == Some(std::ffi::OsStr::new("__lease-guard")) {
            rpweld::lease_process::entry(args);
        }
    }
    let mut worker_args = std::env::args_os().skip(1);
    if worker_args.next().as_deref() == Some(std::ffi::OsStr::new("__trace-worker")) {
        rpweld::trace_worker::worker_entry(worker_args);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| {
        [
            "build", "push", "login", "logout", "images", "image", "cache", "builds",
        ]
        .contains(&arg.as_str())
    }) && let Err(error) = install_build_signals()
    {
        eprintln!("rpweld: cannot install cancellation handlers: {error}");
        std::process::exit(2);
    }
    if let Err(error) = execute(&args, &mut io::stdout().lock()) {
        eprintln!("rpweld: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn build_push_keeps_its_output_after_concurrent_retag() {
        const CHILD: &str = "RPWELD_RETAG_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let home = tempfile::tempdir().unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::build_push_keeps_its_output_after_concurrent_retag",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("HOME", home.path())
                .env("RPWELD_HOME", home.path().join("store"))
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        struct RetagWriter {
            text: Vec<u8>,
            store: std::path::PathBuf,
            replacement: std::path::PathBuf,
            retagged: bool,
            verified: bool,
        }
        const TAG: &str = "localhost:1/test/retag:latest";
        impl Write for RetagWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.text.extend_from_slice(bytes);
                let text = String::from_utf8_lossy(&self.text);
                if !self.retagged && text.contains(&format!("Tagged {TAG}\n")) {
                    rpweld::registry::save_tag(
                        &self.store,
                        &rpweld::store_lease::StoreLease::shared(&self.store, &|| false).unwrap(),
                        TAG,
                        &self.replacement,
                    )
                    .unwrap();
                    self.retagged = true;
                }
                if text.contains("Pushing ") {
                    self.verified = true;
                    // Stop after local verification, before any registry transport.
                    return Err(io::Error::other("stop before transport"));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let context = tmp.path().join("context");
        std::fs::create_dir(&context).unwrap();
        std::fs::write(context.join("Dockerfile"), "FROM scratch\nCOPY . /\n").unwrap();
        let replacement = tmp.path().join("invalid-image");
        std::fs::create_dir(&replacement).unwrap();
        let mut writer = RetagWriter {
            text: Vec::new(),
            store: rpweld::registry::store_dir().unwrap(),
            replacement,
            retagged: false,
            verified: false,
        };
        let error = run_build(
            &[
                "-t".into(),
                TAG.into(),
                "--push".into(),
                context.to_str().unwrap().into(),
            ],
            &mut writer,
        )
        .unwrap_err();
        assert_eq!(error, "stop before transport");
        assert!(writer.retagged && writer.verified);
        assert_eq!(
            rpweld::registry::tagged_image(
                &writer.store,
                &rpweld::store_lease::StoreLease::shared(&writer.store, &|| false).unwrap(),
                TAG
            )
            .unwrap(),
            writer.replacement
        );
        // Standalone push resolves the current tag and rejects its invalid layout.
        let mut output = Vec::new();
        assert!(push_image(TAG, &rpweld::registry::Options::default(), &mut output).is_err());
        assert!(
            output.is_empty(),
            "invalid layout must fail before transport"
        );
    }

    fn build_args(extra: &[&str]) -> Vec<String> {
        [
            "-f",
            "missing",
            "--output",
            "out",
            "--work-dir",
            "work",
            "context",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn build_parser_maps_references_without_path_delimiters() {
        let cli = parse_build_args(&build_args(&[
            "--base-ref",
            "ubuntu:24.04=release=one",
            "--base",
            "ubuntu:24.04=/tmp/layout=one",
            "--build-arg",
            "EMPTY=",
            "--host-dns",
        ]))
        .unwrap();
        let base = &cli.options.bases["ubuntu:24.04"];
        assert_eq!(base.layout, std::path::Path::new("/tmp/layout=one"));
        assert_eq!(base.reference.as_deref(), Some("release=one"));
        assert_eq!(cli.options.args["EMPTY"], "");
        assert!(cli.options.host_dns);
        assert!(!cli.options.verbose);
        assert!(
            parse_build_args(&build_args(&["--verbose"]))
                .unwrap()
                .options
                .verbose
        );
        assert_eq!(cli.options.limits.max_rootfs_bytes, 268435456);
        assert_eq!(cli.options.limits.image.max_total_metadata_bytes, 16777216);
    }

    #[test]
    fn build_parser_rejects_duplicates_missing_values_and_bad_budgets() {
        for extra in [
            vec!["-f", "again"],
            vec!["--output", "again"],
            vec!["--base", "a=x", "--base", "a=y"],
            vec!["--base", "a=x", "--base-ref", "a=x", "--base-ref", "a=y"],
            vec!["--build-arg", "A=x", "--build-arg", "A=y"],
            vec!["--host-dns", "--host-dns"],
            vec!["--base-ref", "a=x"],
            vec!["--base", "scratch=x"],
            vec!["--base", "a="],
            vec!["--build-arg", "1A=x"],
            vec!["--unknown"],
            vec!["--max-rootfs-bytes", "0"],
            vec!["--max-layer-bytes", "-1"],
            vec!["--metadata-budget", "18446744073709551616"],
            vec!["--metadata-budget", "1MiB"],
            vec!["--run-timeout-seconds", "86401"],
            vec!["--base"],
            vec!["--output"],
            vec!["second-context"],
        ] {
            assert!(parse_build_args(&build_args(&extra)).is_err(), "{extra:?}");
        }
        for args in [vec![], vec!["-f", "x"], vec!["--push", "ctx"]] {
            assert!(
                parse_build_args(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err()
            );
        }
        let cli = parse_build_args(&build_args(&[
            "--max-rootfs-bytes",
            "123",
            "--max-layer-bytes",
            "456",
            "--metadata-budget",
            "789",
        ]))
        .unwrap();
        assert_eq!(cli.options.limits.max_rootfs_bytes, 123);
        assert_eq!(cli.options.limits.layer.max_uncompressed_bytes, 456);
        assert_eq!(cli.options.limits.export.max_metadata_bytes, 789);
    }

    #[test]
    fn build_source_requires_bounded_regular_utf8_file() {
        let temp = tempfile::tempdir().unwrap();
        assert!(read_build_source(temp.path().to_str().unwrap()).is_err());
        let path = temp.path().join("Dockerfile");
        std::fs::write(&path, [255]).unwrap();
        assert!(
            read_build_source(path.to_str().unwrap())
                .unwrap_err()
                .contains("UTF-8")
        );
        std::fs::write(&path, vec![b' '; rpweld::build_plan::MAX_SOURCE_BYTES + 1]).unwrap();
        assert!(
            read_build_source(path.to_str().unwrap())
                .unwrap_err()
                .contains("source limit")
        );
        std::fs::write(&path, "FROM scratch\n").unwrap();
        assert_eq!(
            read_build_source(path.to_str().unwrap()).unwrap(),
            "FROM scratch\n"
        );
    }

    #[test]
    fn unsupported_commands_do_not_report_success() {
        for command in ["build", "run", "push", "unknown"] {
            let mut out = Vec::new();
            assert!(execute(&[command.into()], &mut out).is_err());
            assert!(out.is_empty());
        }
    }

    #[test]
    fn rejects_unknown_doctor_flags() {
        assert!(execute(&["doctor".into(), "--fix".into()], &mut Vec::new()).is_err());
    }

    #[test]
    fn scan_reports_user_with_line_and_nonzero_result() {
        let mut out = Vec::new();
        assert!(
            render_scan(
                "Dockerfile",
                "FROM ubuntu:24.04\nUSER 1234\n",
                true,
                &mut out
            )
            .is_err()
        );
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["path"], "Dockerfile");
        assert!(
            value["report"]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["line"] == 2 && d["severity"] == "error")
        );
    }

    #[test]
    fn scan_does_not_treat_shell_text_as_user_instruction() {
        let mut out = Vec::new();
        render_scan(
            "Dockerfile",
            "FROM ubuntu:24.04\nRUN echo USER root\n",
            false,
            &mut out,
        )
        .unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("partial static check")
        );
    }

    #[test]
    fn scan_rejects_unknown_options_before_reading() {
        assert!(execute(&["scan".into(), "--execute".into()], &mut Vec::new()).is_err());
    }

    #[test]
    fn version_matches_package() {
        let mut out = Vec::new();
        execute(&["--version".into()], &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn unknown_capacity_is_not_rendered_as_zero_or_host_memory() {
        let report =
            json!({"resources": {"supported": true, "memory": {"explicit_budget_required": true}}});
        let text = summary(&report);
        assert!(text.contains("Memory ceiling observed: unknown"));
        assert!(text.contains("Open-file limits observed: soft unknown, hard unknown"));
        assert!(text.contains("explicit budget is required"));
        assert!(!text.contains("0.00 GiB"));
    }

    #[test]
    fn doctor_renders_process_limits_without_hardware_inference() {
        for (soft, hard, expected) in [
            (json!(1024), json!(4096), "soft 1024, hard 4096"),
            (json!(1024), json!("unlimited"), "soft 1024, hard unlimited"),
        ] {
            let report = json!({"resources": {"supported": true},
                "capabilities": {"nofile": {"soft": soft, "hard": hard}}});
            let text = summary(&report);
            assert!(text.contains(expected), "{text}");
            assert!(text.contains("per process"));
        }
    }
}
