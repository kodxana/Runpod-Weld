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

  rpweld build -f DOCKERFILE [--base NAME=LAYOUT] [--base-ref NAME=REFERENCE]
    --output NEWDIR --work-dir NEWDIR [--build-arg KEY=VALUE] [--host-dns]
    [--max-rootfs-bytes N] [--max-layer-bytes N] [--metadata-budget N]
    [--run-timeout-seconds N] CONTEXT

Experimental build: Linux amd64, single stage, local OCI bases or scratch.
Bindings match literal FROM names; --base-ref selects an OCI ref annotation.
Without --base-ref the layout must have an unambiguous image selection.
No COPY, multistage, registry pull/push or container run command yet.
Defaults: rootfs 268435456 bytes; layer/replay 268435456 bytes;
metadata 16777216 bytes per subsystem; 100000 entries; 1024 descriptors;
RUN timeout 300 seconds (maximum 86400). Budgets accept positive decimal bytes.
Dockerfile/parser source cap: 1048576 bytes. Parser/metadata budgets are
separate from RUN memory; no memory or disk quota enforcement is guaranteed.
Rootfs is checked between operations. No host RAM sizing or capacity guesses.
Trusted images/commands and stable paths required; this is not a sandbox.
Work/output must be new, disjoint paths outside context/base; failures retain them.
Doctor is read-only. Observed resource limits are not per-build enforcement.
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
        [cmd, ..] if ["push", "run"].contains(&cmd.as_str()) => Err(format!(
            "'{cmd}' is not implemented in this development preview; no build or container was started"
        )),
        _ => Err("unrecognized command or option; use 'rpweld --help'".into()),
    }
}

struct BuildCli {
    dockerfile: String,
    options: rpweld::build::BuildOptions,
}

fn parse_build_args(args: &[String]) -> Result<BuildCli, String> {
    let mut values = BTreeMap::new();
    let mut bases = BTreeMap::new();
    let mut references = BTreeMap::new();
    let mut build_args = BTreeMap::new();
    let mut context = None;
    let mut host_dns = false;
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
        if !positional && arg == "--host-dns" {
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
            } else if values.insert(arg.as_str(), value.as_str()).is_some() {
                return Err(format!("duplicate {arg}"));
            }
        } else if arg.is_empty() || context.replace(arg.clone()).is_some() {
            return Err("exactly one context directory is required".into());
        }
    }
    let required = |key| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("missing required {key}"))
    };
    let dockerfile = required("-f")?.to_owned();
    let output = required("--output")?.into();
    let work = required("--work-dir")?.into();
    let context = context.ok_or("missing context directory")?.into();
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
    let root = budget("--max-rootfs-bytes", 256 * 1024 * 1024)?;
    let layer = budget("--max-layer-bytes", 256 * 1024 * 1024)?;
    let metadata = budget("--metadata-budget", 16 * 1024 * 1024)?;
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
        dockerfile,
        options: rpweld::build::BuildOptions {
            work,
            output,
            context,
            host_dns,
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
        options.custom_flags(libc::O_NONBLOCK);
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
    let cli = parse_build_args(args)?;
    let source = read_build_source(&cli.dockerfile)?;
    let result = rpweld::build::build(&source, &cli.options, || CANCELLED.load(Ordering::Relaxed))
        .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "Experimental OCI build: {}\nManifest: {}\nRetained work: {}",
        result.output.display(),
        result.manifest.digest,
        result.work.display()
    )
    .map_err(|e| e.to_string())
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
    if resources["memory"]["explicit_budget_required"] == true {
        result.push_str("Automatic memory sizing unavailable; an explicit budget is required.\n");
    }
    if let Some(warnings) = resources["warnings"].as_array() {
        for warning in warnings.iter().filter_map(|v| v.as_str()) {
            result.push_str(&format!("Warning: {warning}\n"));
        }
    }
    result.push_str("Experimental build supports single-stage local OCI or scratch only; no COPY, multistage, pull or push. RUN resources require external enforcement. Use --json for raw observations.\n");
    result
}

fn main() {
    // The tracer owns process-wide signal and child-reaping state. Dispatch only
    // in a fresh executable, before the builder initializes threads or children.
    let mut worker_args = std::env::args_os().skip(1);
    if worker_args.next().as_deref() == Some(std::ffi::OsStr::new("__trace-worker")) {
        rpweld::trace_worker::worker_entry(worker_args);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "build")
        && let Err(error) = install_build_signals()
    {
        eprintln!("rpweld: cannot install build cancellation handlers: {error}");
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
        for args in [
            vec![],
            vec!["-f", "x"],
            vec!["--output", "x", "--work-dir", "y", "ctx"],
        ] {
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
        assert!(text.contains("explicit budget is required"));
        assert!(!text.contains("0.00 GiB"));
    }
}
