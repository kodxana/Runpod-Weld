use serde_json::json;
use std::io::{self, Write};

const HELP: &str = "Runpod Weld (rpweld) — development preview

Usage:
  rpweld doctor [--json]   Inspect Pod capabilities and cgroup resources
  rpweld --version
  rpweld --help

Image build, push and run commands are not implemented yet.
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
        [cmd, ..] if ["build", "push", "run"].contains(&cmd.as_str()) => Err(format!(
            "'{cmd}' is not implemented in this development preview; no build or container was started"
        )),
        _ => Err("unrecognized command or option; use 'rpweld --help'".into()),
    }
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
    result.push_str("Image building is not implemented yet. Use --json for raw observations.\n");
    result
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = execute(&args, &mut io::stdout().lock()) {
        eprintln!("rpweld: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
