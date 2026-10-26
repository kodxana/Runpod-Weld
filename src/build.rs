//! Minimal, trusted/stable Linux amd64 builds from local OCI bindings or scratch.
//! Supports dependency-selected stages: FROM, RUN, local/stage/image COPY, ARG, ENV, WORKDIR,
//! SHELL, USER, LABEL, shell/JSON CMD/ENTRYPOINT, EXPOSE.
//! COPY supports bounded patterns and --chown/--chmod. OnBuild and complex
//! expansion fail closed. RUN exec and custom shell argv
//! form uses `/bin/sh -c 'exec ...'` with every argv element literally quoted.
//! This is not a sandbox. Caller owns stable ancestors and trusted image/commands;
//! no concurrent writers, mounts or external hardlinks are allowed. WORKDIR
//! rejects symlink components (including absolute image symlinks), never follows
//! them on the host. No synthetic /dev or /proc files are created.
//! Budgets are explicit; rootfs budgets are checked between operations, not disk
//! quotas or RUN memory limits. Caller must provision/enforce RUN resources.
//! Errors leave partial owned work/output directories for manual inspection;
//! nothing recursively deletes user trees. Never reuse a failed build directory.

#[cfg(not(target_os = "linux"))]
use std::process::Command;

use crate::{
    build_plan::{self, Base, CopySource, InstructionKind as I, Protocol, Run},
    context, export, image, layer,
    oci::{BlobStore, Descriptor},
    rootfs,
};
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::Stdio,
};

/// Errors include underlying parser, image, filesystem, worker and export errors.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

fn copy_limits(limits: Limits, used: &context::Summary) -> context::Limits {
    context::Limits {
        max_bytes: limits
            .max_rootfs_bytes
            .min(limits.layer.max_uncompressed_bytes)
            .saturating_sub(used.bytes_written),
        max_entries: limits
            .max_rootfs_entries
            .min(limits.layer.max_entries)
            .saturating_sub(used.entries),
        max_metadata_bytes: limits
            .layer
            .max_metadata_bytes
            .saturating_sub(used.metadata_bytes),
    }
}

/// Exact expanded FROM or literal COPY image name -> local OCI layout/ref annotation.
#[derive(Clone, Debug)]
pub struct LocalBase {
    pub layout: PathBuf,
    pub reference: Option<String>,
}

/// Explicit budgets; replay totals bound all decompressed base layers together.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub image: image::Limits,
    pub layer: layer::Limits,
    pub export: export::Limits,
    pub max_replay_bytes: u64,
    pub max_replay_entries: usize,
    pub max_rootfs_bytes: u64,
    pub max_rootfs_entries: usize,
    /// Maximum evaluated instruction/config/environment bytes (logical, not RSS).
    pub max_plan_bytes: usize,
    pub run_timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExportMode {
    Flattened,
    #[default]
    Layered,
}

/// Work/output must be new paths with existing, stable parents, disjoint from
/// each other, context and base layouts. Work owns rootfs, spool and worker state.
#[derive(Clone)]
pub struct BuildOptions {
    pub work: PathBuf,
    pub output: PathBuf,
    pub context: PathBuf,
    /// Selected Dockerfile; its sibling .dockerignore takes precedence, even when empty.
    /// None uses only the context-root policy.
    pub dockerfile: Option<PathBuf>,
    pub bases: BTreeMap<String, LocalBase>,
    pub args: BTreeMap<String, String>,
    pub limits: Limits,
    /// Opt in to temporary host /etc/resolv.conf only when the image's file is
    /// missing/empty. Original file metadata is restored by rename before export.
    pub host_dns: bool,
    /// Show low-level runner compatibility diagnostics.
    pub verbose: bool,
    /// Append-only engine progress; RUN streams and diagnostics remain visible when false.
    pub progress: bool,
    pub export_mode: ExportMode,
    pub target: Option<String>,
    pub cache: Option<PathBuf>,
    /// Explicit managed store for shared checkpoint blobs; mutually exclusive with cache.
    pub managed_cache: Option<PathBuf>,
    pub no_cache: bool,
}

/// Successful OCI publication and retained engine work directory.
#[derive(Debug)]
pub struct BuildResult {
    pub manifest: Descriptor,
    pub output: PathBuf,
    pub work: PathBuf,
}

#[derive(Debug)]
enum Step {
    Directory {
        path: String,
        // Inherited initial WorkingDir is not an explicit USER-owned mkdir.
        user: Option<String>,
    },
    Copy {
        from: Option<CopySource>,
        inline: Option<String>,
        sources: Vec<String>,
        destination: String,
        chown: Option<String>,
        chmod: Option<u32>,
    },
    Run {
        command: String,
        workdir: String,
        env: Vec<String>,
        user: String,
        absent_secret: Option<String>,
    },
}

struct Checkpoint {
    end: usize,
    ordinal: usize,
    operation: &'static str,
    config: Value,
    args: BTreeMap<String, String>,
}

/// Verify absence without reading data, following links, or modifying the image.
/// Like the rest of the builder this requires an exclusively owned, stable tree.
#[cfg(target_os = "linux")]
fn validate_absent_secret(root: &Path, id: &str) -> Result<()> {
    use std::os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    };
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let path = std::ffi::CString::new(format!("run/secrets/{id}"))?;
    let how = How {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        // NO_XDEV | NO_MAGICLINKS | NO_SYMLINKS | BENEATH. Even dangling
        // symlinks reject; only ENOENT proves this profile's absence.
        resolve: 1 | 2 | 4 | 8,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<How>(),
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(format!(
            "optional absent secret {id}: cannot prove /run/secrets/{id} absent: {error}"
        )
        .into());
    }
    drop(unsafe { OwnedFd::from_raw_fd(fd as i32) });
    Err(format!("optional absent secret {id}: /run/secrets/{id} exists; refusing inherited secret path (no secret supplied)").into())
}

#[cfg(not(target_os = "linux"))]
fn validate_absent_secret(_root: &Path, _id: &str) -> Result<()> {
    Err("optional absent secret validation requires Linux".into())
}

// The stage directory is newly created and leased before this function. Source
// names come only from validated delimiter identifiers, never container paths.
fn prepare_inline_sources(steps: &[Step], work: &Path, cancelled: &dyn Fn() -> bool) -> Result<()> {
    use std::io::Write;
    for (index, step) in steps.iter().enumerate() {
        if let Step::Copy {
            inline: Some(body),
            sources,
            ..
        } = step
        {
            check(&cancelled)?;
            let dir = work.join(format!("inline-{index}"));
            fs::create_dir(&dir)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(&sources[0]))?;
            for chunk in body.as_bytes().chunks(65536) {
                check(&cancelled)?;
                file.write_all(chunk)?;
            }
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o644))?;
            }
            file.set_times(
                fs::FileTimes::new()
                    .set_accessed(std::time::UNIX_EPOCH)
                    .set_modified(std::time::UNIX_EPOCH),
            )?;
        }
    }
    Ok(())
}

fn check(cancelled: &impl Fn() -> bool) -> Result<()> {
    if cancelled() {
        Err("build cancelled; partial directories retained".into())
    } else {
        Ok(())
    }
}
fn identifier(s: &str) -> bool {
    let mut c = s.chars();
    c.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && c.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
fn text(s: &str) -> Result<()> {
    if s.contains('\0') {
        Err("NUL in configuration".into())
    } else {
        Ok(())
    }
}

fn map_bytes(values: &BTreeMap<String, String>, cap: usize) -> Result<usize> {
    let mut size = 0usize;
    for (key, value) in values {
        size = size
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .filter(|n| *n <= cap)
            .ok_or("environment/argument budget exceeded")?;
    }
    Ok(size)
}

// Basic Docker word expansion only; modifiers are rejected even in unused ARGs.
fn expand(raw: &str, vars: &BTreeMap<String, String>, cap: usize) -> Result<String> {
    expand_mode(raw, vars, cap, false)
}

fn expand_mode(
    raw: &str,
    vars: &BTreeMap<String, String>,
    cap: usize,
    raw_quotes: bool,
) -> Result<String> {
    let mut chars = raw.chars().peekable();
    let mut out = String::new();
    let mut quote = None;
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' if quote.is_none() && !raw_quotes => quote = Some(c),
            c if Some(c) == quote => quote = None,
            '\\' if quote != Some('\'') => {
                let next = chars.next().ok_or("unfinished escape")?;
                if quote == Some('"') && !matches!(next, '$' | '"' | '\\') {
                    return Err("unsupported double-quoted escape".into());
                }
                out.push(next);
            }
            '$' if quote != Some('\'') => {
                let braced = chars.peek() == Some(&'{');
                if braced {
                    chars.next();
                }
                let mut name = String::new();
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    name.push(chars.next().unwrap());
                }
                if !identifier(&name) || (braced && chars.next() != Some('}')) {
                    return Err(
                        "unsupported expansion; only $NAME and ${NAME} expansion supported".into(),
                    );
                }
                let value = vars.get(&name).map(String::as_str).unwrap_or("");
                if value.len() > cap.saturating_sub(out.len()) {
                    return Err("expanded value budget exceeded".into());
                }
                out.push_str(value);
            }
            _ => out.push(c),
        }
        if out.len() > cap {
            return Err("expanded value budget exceeded".into());
        }
    }
    if quote.is_some() {
        return Err("unfinished quote".into());
    }
    text(&out)?;
    Ok(out)
}

fn path(current: &str, value: &str) -> Result<String> {
    text(value)?;
    if value.is_empty() {
        return Err("empty WORKDIR".into());
    }
    let full = if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("{current}/{value}")
    };
    let mut parts = Vec::new();
    for part in full.split('/') {
        match part {
            "" | "." => (),
            // Reject rather than normalize across a potentially symlinked component.
            ".." => return Err("WORKDIR parent components unsupported".into()),
            p => parts.push(p),
        }
    }
    if parts.len() > 256 || full.len() > 4096 {
        return Err("WORKDIR path limit exceeded".into());
    }
    Ok(format!("/{}", parts.join("/")))
}

fn copy_words(
    paths: &build_plan::Arguments,
    vars: &BTreeMap<String, String>,
    cap: usize,
) -> Result<Vec<String>> {
    match paths {
        build_plan::Arguments::Words(words) => {
            words.iter().map(|w| expand(&w.raw, vars, cap)).collect()
        }
        build_plan::Arguments::Json(words) => words
            .iter()
            .map(|w| {
                // Reject ambiguous shell quoting after JSON decoding rather than
                // silently interpreting JSON quotes as Docker word delimiters.
                if w.contains(['\'', '"', '\\']) {
                    return Err("COPY JSON embedded quotes/backslashes unsupported".into());
                }
                expand(w, vars, cap)
            })
            .collect(),
    }
}

fn copy_path(value: &str, absolute: bool) -> Result<()> {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('/') != absolute
        || value.bytes().any(|b| b"\0$\\".contains(&b))
        || (absolute && value.contains(['*', '?', '[']))
        || value.split('/').any(|p| p == "..")
        || value.split('/').count() > 128
    {
        return Err("COPY requires bounded context-relative patterns and literal image destinations; no parent or unresolved variable syntax".into());
    }
    Ok(())
}

fn check_copy_sources(
    steps: &[Step],
    options: &BuildOptions,
    policy: &crate::dockerignore::Policy,
    c: &impl Fn() -> bool,
) -> Result<()> {
    for step in steps {
        if let Step::Copy {
            from: None,
            inline: None,
            sources,
            ..
        } = step
        {
            context::validate_sources(
                &options.context,
                &sources.iter().map(String::as_str).collect::<Vec<_>>(),
                policy,
                c,
            )?;
        }
    }
    Ok(())
}

fn array(config: &Value, key: &str) -> Result<Vec<String>> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                let s = v.as_str().ok_or("base config array must contain strings")?;
                text(s)?;
                Ok(s.to_owned())
            })
            .collect(),
        _ => Err(format!("invalid base config.{key}").into()),
    }
}

fn shell_argv(shell: &[String], command: &str) -> Vec<String> {
    let mut argv = shell.to_vec();
    argv.push(command.to_owned());
    argv
}

fn exec_command(argv: &[String]) -> String {
    format!(
        "exec {}",
        argv.iter()
            .map(|s| format!("'{}'", s.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn global_args(
    plan: &build_plan::BuildPlan,
    supplied: &BTreeMap<String, String>,
    cap: usize,
) -> Result<BTreeMap<String, String>> {
    map_bytes(supplied, cap)?;
    for (name, value) in supplied {
        if !identifier(name) {
            return Err("invalid build argument name".into());
        }
        text(value)?;
    }
    // These describe the supported worker/target, never the CLI host OS.
    let mut globals: BTreeMap<String, String> = [
        ("BUILDPLATFORM", "linux/amd64"),
        ("BUILDOS", "linux"),
        ("BUILDARCH", "amd64"),
        ("BUILDVARIANT", ""),
        ("TARGETPLATFORM", "linux/amd64"),
        ("TARGETOS", "linux"),
        ("TARGETARCH", "amd64"),
        ("TARGETVARIANT", ""),
    ]
    .into_iter()
    .map(|(name, value)| {
        (
            name.to_owned(),
            supplied
                .get(name)
                .cloned()
                .unwrap_or_else(|| value.to_owned()),
        )
    })
    .collect();
    map_bytes(&globals, cap)?;
    for instruction in &plan.global_args {
        if let I::Arg { name, default } = &instruction.kind {
            let default = default
                .as_deref()
                .map(|s| expand(s, &globals, cap))
                .transpose()?;
            if let Some(value) = supplied.get(name).cloned().or(default) {
                globals.insert(name.clone(), value);
                map_bytes(&globals, cap)?;
            }
        }
    }
    Ok(globals)
}

/// Resolve FROM using global ARGs before dependency selection or registry/cache work.
/// Dynamic aliases may select only backward stages; COPY --from stays literal.
pub fn resolve_plan(
    source: &str,
    supplied: &BTreeMap<String, String>,
    cap: usize,
) -> Result<build_plan::BuildPlan> {
    let mut plan = build_plan::parse(source)?;
    let globals = global_args(&plan, supplied, cap)?;
    let mut charged = map_bytes(&globals, cap)?;
    for index in 0..plan.stages.len() {
        if let I::From {
            platform: Some(platform),
            ..
        } = &mut plan.stages[index].instructions[0].kind
        {
            let value = expand(platform, &globals, cap)?;
            charged = charged
                .checked_add(value.len())
                .filter(|n| *n <= cap)
                .ok_or("resolved FROM budget exceeded")?;
            *platform = normalize_platform(&value)?.to_owned();
        }
        let Base::Image(raw) = &plan.stages[index].base else {
            continue;
        };
        let name = expand(raw, &globals, cap)?;
        charged = charged
            .checked_add(name.len())
            .filter(|n| *n <= cap)
            .ok_or("resolved FROM budget exceeded")?;
        let alias = plan.stages.iter().position(|s| {
            s.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(&name))
        });
        let base = if let Some(previous) = alias.filter(|n| *n < index) {
            Base::Stage(previous)
        } else {
            // A literal self-named stage can still use an image with that name.
            // Dynamic forward/self aliases are rejected rather than accidentally pulled.
            if raw.contains('$') && alias.is_some() {
                return Err("dynamic FROM must reference a backward stage".into());
            }
            crate::registry::reference(&name, true)
                .map_err(|e| format!("invalid FROM {name:?}: {e}"))?;
            Base::Image(name)
        };
        plan.stages[index].base = base.clone();
        if let I::From {
            base: instruction_base,
            ..
        } = &mut plan.stages[index].instructions[0].kind
        {
            *instruction_base = base;
        }
    }
    Ok(plan)
}

/// containerd-compatible normalization restricted to the supported worker.
pub fn normalize_platform(value: &str) -> Result<&'static str> {
    let lower = value.to_ascii_lowercase();
    let parts: Vec<_> = lower.splitn(4, '/').collect();
    let arch = |s: &str| matches!(s, "amd64" | "x86_64" | "x86-64");
    let supported = match parts.as_slice() {
        [one] => *one == "linux" || arch(one),
        [os, a] => *os == "linux" && arch(a),
        [os, a, variant] => *os == "linux" && arch(a) && *variant == "v1",
        _ => false,
    };
    if !supported {
        return Err(format!(
            "invalid or unsupported FROM platform {value:?}; only linux/amd64 is supported"
        )
        .into());
    }
    Ok("linux/amd64")
}

fn preflight_stage(
    plan: &build_plan::BuildPlan,
    index: usize,
    options: &BuildOptions,
    config: Value,
    inherited_args: BTreeMap<String, String>,
) -> Result<(Value, Vec<Step>, BTreeMap<String, String>)> {
    preflight_checkpoints(plan, index, options, config, inherited_args, None)
}

fn preflight_checkpoints(
    plan: &build_plan::BuildPlan,
    index: usize,
    options: &BuildOptions,
    mut config: Value,
    inherited_args: BTreeMap<String, String>,
    mut checkpoints: Option<&mut Vec<Checkpoint>>,
) -> Result<(Value, Vec<Step>, BTreeMap<String, String>)> {
    let cap = options.limits.max_plan_bytes;
    if config.get("config").is_none_or(Value::is_null) {
        config["config"] = json!({});
    }
    let cfg = &mut config["config"];
    if !cfg.is_object() {
        return Err("invalid base config object".into());
    }
    let mut user = match cfg.get("User") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        _ => return Err("invalid base User: expected a string".into()),
    };
    crate::user::validate_user_spec(&user)?;
    if !array(cfg, "OnBuild")?.is_empty() {
        return Err("base OnBuild unsupported".into());
    }
    let mut shell = array(cfg, "Shell")?;
    if shell.first().is_some_and(String::is_empty) {
        return Err("base Shell requires a nonempty executable".into());
    }
    if shell.is_empty() {
        shell = vec!["/bin/sh".into(), "-c".into()];
    }
    if let Some(labels) = cfg.get("Labels").filter(|v| !v.is_null()) {
        for (k, v) in labels.as_object().ok_or("invalid base Labels")? {
            text(k)?;
            text(v.as_str().ok_or("base Labels values must be strings")?)?;
        }
    }
    array(cfg, "Cmd")?;
    array(cfg, "Entrypoint")?;
    if let Some(signal) = cfg.get("StopSignal").filter(|v| !v.is_null()) {
        let signal = signal
            .as_str()
            .ok_or("invalid base StopSignal: expected a string")?;
        if !signal.is_empty() {
            build_plan::validate_stop_signal(signal)?;
        }
    }
    if let Some(health) = cfg.get("Healthcheck").filter(|v| !v.is_null()) {
        if !health.is_object() {
            return Err("invalid base Healthcheck: expected an object".into());
        }
        let test = array(health, "Test")?;
        if !test.is_empty() && !matches!(test[0].as_str(), "NONE" | "CMD" | "CMD-SHELL") {
            return Err("unsupported base Healthcheck Test".into());
        }
        for field in [
            "Interval",
            "Timeout",
            "StartPeriod",
            "StartInterval",
            "Retries",
        ] {
            if let Some(value) = health.get(field).filter(|v| !v.is_null()) {
                let limit = if field == "Retries" {
                    i32::MAX as i64
                } else {
                    i64::MAX
                };
                if !value.as_i64().is_some_and(|n| (0..=limit).contains(&n)) {
                    return Err(format!("invalid base Healthcheck {field}").into());
                }
            }
        }
    }
    if let Some(ports) = cfg.get("ExposedPorts").filter(|v| !v.is_null()) {
        let ports = ports.as_object().ok_or("invalid base ExposedPorts")?;
        for (port, value) in ports {
            let (n, protocol) = port.split_once('/').ok_or("invalid base port")?;
            if n.parse::<u16>().ok().filter(|n| *n > 0).is_none()
                || !matches!(protocol, "tcp" | "udp")
                || !value.is_object()
            {
                return Err("invalid base ExposedPorts entry".into());
            }
        }
    }
    let mut env = BTreeMap::new();
    for entry in array(cfg, "Env")? {
        let (name, value) = entry.split_once('=').ok_or("invalid base Env")?;
        if !identifier(name) {
            return Err("unsupported base environment name".into());
        }
        env.insert(name.to_owned(), value.to_owned());
        map_bytes(&env, cap)?;
    }
    let mut wd = match cfg.get("WorkingDir") {
        None | Some(Value::Null) => "/".into(),
        Some(Value::String(s)) if s.is_empty() => "/".into(),
        Some(Value::String(s)) if s.starts_with('/') => path("/", s)?,
        _ => return Err("invalid base WorkingDir".into()),
    };
    let mut supplied_bytes = 0usize;
    for (k, v) in &options.args {
        if !identifier(k) {
            return Err("invalid build argument name".into());
        }
        text(v)?;
        supplied_bytes = supplied_bytes
            .checked_add(k.len() + v.len())
            .ok_or("argument budget overflow")?;
    }
    if supplied_bytes > cap {
        return Err("argument budget exceeded".into());
    }
    let globals = global_args(plan, &options.args, cap)?;
    let mut args = inherited_args;
    let mut steps = vec![Step::Directory {
        path: wd.clone(),
        user: None,
    }];
    let mut charge = supplied_bytes + wd.len() + map_bytes(&globals, cap)?;
    let mut cmd_set = false;
    let mut checkpoint_bytes = 0usize;
    for (ordinal, i) in plan.stages[index].instructions.iter().enumerate() {
        let mut vars = args.clone();
        vars.extend(env.clone()); // ENV shadows ARG, including empty values.
        match &i.kind {
            I::From { .. } => (),
            I::Copy {
                from,
                paths,
                chown,
                chmod,
            } => {
                let mut chown = chown
                    .as_deref()
                    .map(|s| expand(s, &vars, cap))
                    .transpose()?;
                if let Some(owner) = &chown {
                    context::validate_chown(owner)?;
                }
                let chmod = chmod
                    .as_deref()
                    .map(|s| Ok::<_, Error>(context::parse_chmod(&expand(s, &vars, cap)?)?))
                    .transpose()?;
                let mut values = copy_words(paths, &vars, cap)?;
                let dest = values.pop().ok_or("COPY destination missing")?;
                let inline = i
                    .heredoc
                    .as_ref()
                    .map(|doc| {
                        values = vec![doc.delimiter.clone()];
                        chown.get_or_insert_with(|| "0:0".into());
                        if doc.expand {
                            expand_mode(&doc.body, &vars, cap, true)
                        } else {
                            Ok(doc.body.clone())
                        }
                    })
                    .transpose()?;
                if let Some(body) = &inline {
                    charge = charge
                        .checked_add(body.len())
                        .ok_or("plan budget overflow")?;
                    if body.len() as u64
                        > options
                            .limits
                            .max_rootfs_bytes
                            .min(options.limits.layer.max_uncompressed_bytes)
                        || options
                            .limits
                            .max_rootfs_entries
                            .min(options.limits.layer.max_entries)
                            == 0
                    {
                        return Err("inline COPY budget exceeded".into());
                    }
                }
                for source in &mut values {
                    if from.is_some() {
                        *source = source.trim_start_matches('/').to_owned();
                        if source.is_empty() {
                            *source = ".".into();
                        }
                    }
                    copy_path(source, false)?;
                }
                if dest.is_empty() || (values.len() > 1 && !dest.ends_with('/')) {
                    return Err("COPY multiple sources require a trailing slash destination".into());
                }
                let mut destination = path(&wd, &dest)?;
                if dest.ends_with('/') && !destination.ends_with('/') {
                    destination.push('/');
                }
                copy_path(&destination, true)?;
                if inline.is_some()
                    && (512 + values[0].len() + destination.len()) as u64
                        > options.limits.layer.max_metadata_bytes
                {
                    return Err("inline COPY metadata budget exceeded".into());
                }
                charge = charge
                    .checked_add(destination.len())
                    .and_then(|n| {
                        n.checked_add(match from {
                            Some(CopySource::Image(name)) => name.len(),
                            _ => 0,
                        })
                    })
                    .and_then(|n| n.checked_add(chown.as_ref().map_or(0, String::len)))
                    .and_then(|n| values.iter().try_fold(n, |n, s| n.checked_add(s.len())))
                    .ok_or("plan budget overflow")?;
                steps.push(Step::Copy {
                    from: from.clone(),
                    inline,
                    sources: values,
                    destination,
                    chown,
                    chmod,
                });
            }
            I::Arg { name, default } => {
                let default = default
                    .as_deref()
                    .map(|s| expand(s, &vars, cap))
                    .transpose()?;
                let value = options
                    .args
                    .get(name)
                    .cloned()
                    .or(default)
                    .or_else(|| globals.get(name).cloned())
                    .or_else(|| args.get(name).cloned());
                if let Some(value) = value {
                    args.insert(name.clone(), value);
                }
            }
            I::Env(words) => {
                for word in words {
                    let (name, value) = word.raw.split_once('=').ok_or("invalid ENV")?;
                    env.insert(name.into(), expand(value, &vars, cap)?);
                    map_bytes(&env, cap)?;
                }
            }
            I::Label(words) => {
                if cfg.get("Labels").is_none_or(Value::is_null) {
                    cfg["Labels"] = json!({});
                }
                for word in words {
                    let (key, value) = word.raw.split_once('=').ok_or("invalid LABEL")?;
                    let key = expand(key, &vars, cap)?;
                    if key.is_empty() {
                        return Err("empty LABEL key".into());
                    }
                    cfg["Labels"][key] = json!(expand(value, &vars, cap)?);
                }
            }
            I::Shell(argv) => {
                shell = argv.clone();
                cfg["Shell"] = json!(argv);
            }
            I::Workdir(word) => {
                wd = path(&wd, &expand(&word.raw, &vars, cap)?)?;
                steps.push(Step::Directory {
                    path: wd.clone(),
                    user: Some(user.clone()),
                });
            }
            I::User(word) => {
                user = expand(&word.raw, &vars, cap)?;
                if user.is_empty() {
                    return Err("USER must evaluate to a nonempty identity".into());
                }
                crate::user::validate_user_spec(&user)?;
                cfg["User"] = json!(user);
            }
            I::StopSignal(word) => {
                let signal = expand(&word.raw, &vars, cap)
                    .map_err(|e| format!("line {}: STOPSIGNAL: {e}", i.line))?;
                build_plan::validate_stop_signal(&signal)
                    .map_err(|e| format!("line {}: {e}", i.line))?;
                cfg["StopSignal"] = json!(signal);
            }
            I::Healthcheck(health) => {
                cfg["Healthcheck"] = serde_json::to_value(health)?;
            }
            I::Cmd(argv) => {
                cfg["Cmd"] = json!(argv);
                cmd_set = true;
            }
            I::ShellCmd(command) => {
                cfg["Cmd"] = json!(shell_argv(&shell, command));
                cmd_set = true;
            }
            I::ShellEntrypoint(command) => {
                cfg["Entrypoint"] = json!(shell_argv(&shell, command));
                if !cmd_set {
                    cfg["Cmd"] = Value::Null;
                }
            }
            I::Entrypoint(argv) => {
                cfg["Entrypoint"] = json!(argv);
                if !cmd_set {
                    cfg["Cmd"] = Value::Null;
                }
            }
            I::Expose(ports) => {
                if cfg.get("ExposedPorts").is_none_or(Value::is_null) {
                    cfg["ExposedPorts"] = json!({});
                }
                for p in ports {
                    let protocol = match p.protocol {
                        Protocol::Tcp => "tcp",
                        Protocol::Udp => "udp",
                    };
                    cfg["ExposedPorts"][format!("{}/{protocol}", p.number)] = json!({});
                }
            }
            I::Run(run) => {
                let command = match run {
                    Run::Shell(s) => exec_command(&shell_argv(
                        &shell,
                        i.heredoc
                            .as_ref()
                            .map_or(s.as_str(), |doc| doc.body.as_str()),
                    )),
                    Run::Exec(argv) => exec_command(argv),
                };
                // This string is the actual worker argv element, after JSON
                // decoding and shell quoting; the worker does not JSON-encode it.
                if command.len() > build_plan::MAX_LINE_BYTES {
                    return Err(format!(
                        "line {}: RUN command exceeds 64 KiB worker argument profile",
                        i.line
                    )
                    .into());
                }
                let entries: Vec<_> = vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
                charge = charge
                    .checked_add(
                        command.len()
                            + i.absent_secret.as_ref().map_or(0, String::len)
                            + wd.len()
                            + user.len()
                            + entries.iter().map(String::len).sum::<usize>(),
                    )
                    .ok_or("plan budget overflow")?;
                steps.push(Step::Run {
                    command,
                    workdir: wd.clone(),
                    env: entries,
                    user: user.clone(),
                    absent_secret: i.absent_secret.clone(),
                });
            }
        }
        charge = charge
            .checked_add(
                wd.len()
                    + user.len()
                    + env
                        .iter()
                        .chain(args.iter())
                        .map(|(k, v)| k.len() + v.len())
                        .sum::<usize>(),
            )
            .ok_or("plan budget overflow")?;
        if charge > cap {
            return Err("evaluated plan budget exceeded".into());
        }
        // Metadata instructions are evaluated cheaply; capture their state at the
        // next filesystem boundary, never the final preflight configuration.
        let operation = match i.kind {
            I::From { .. } => Some("FROM"),
            I::Copy { .. } => Some("COPY"),
            I::Run(_) => Some("RUN"),
            I::Workdir(_) => Some("WORKDIR"),
            _ => None,
        };
        if let (Some(checkpoints), Some(operation)) = (checkpoints.as_deref_mut(), operation) {
            let mut snapshot = cfg.clone();
            snapshot["Env"] = json!(
                env.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
            );
            snapshot["WorkingDir"] = json!(wd);
            checkpoint_bytes = checkpoint_bytes
                .checked_add(serde_json::to_vec(&snapshot)?.len())
                .and_then(|n| n.checked_add(map_bytes(&args, cap).ok()?))
                .filter(|n| *n <= cap)
                .ok_or("checkpoint metadata budget exceeded")?;
            checkpoints.push(Checkpoint {
                end: steps.len(),
                ordinal: ordinal + 1,
                operation,
                config: snapshot,
                args: args.clone(),
            });
        }
    }
    cfg["Env"] = json!(
        env.iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
    );
    cfg["WorkingDir"] = json!(wd);
    if serde_json::to_vec(&config)?.len() > cap.saturating_sub(charge) {
        return Err("config budget exceeded".into());
    }
    Ok((config, steps, args))
}

fn fresh(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or("new directory needs a final name")?;
    let parent = fs::canonicalize(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let result = parent.join(name);
    match fs::symlink_metadata(&result) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(result),
        Err(e) => Err(e.into()),
        Ok(_) => Err("work/output already exists".into()),
    }
}
fn disjoint(paths: &[PathBuf]) -> Result<()> {
    for (i, a) in paths.iter().enumerate() {
        for b in &paths[i + 1..] {
            if a.starts_with(b) || b.starts_with(a) {
                return Err("context, base, work and output must be disjoint".into());
            }
        }
    }
    Ok(())
}

// Caller guarantees no concurrent mutation: lstat each ancestor before joining.
fn directory(root: &Path, image_path: &str, user: Option<&str>) -> Result<PathBuf> {
    let mut target = root.to_path_buf();
    let mut owner = None;
    for part in image_path.split('/').filter(|p| !p.is_empty()) {
        if matches!(part, "." | "..") {
            return Err("invalid directory component".into());
        }
        target.push(part);
        match fs::symlink_metadata(&target) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => (),
            Ok(_) => return Err("WORKDIR/DNS path traverses symlink or nondirectory".into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Resolve only when this instruction actually needs to create a directory.
                if owner.is_none()
                    && let Some(user) = user
                {
                    owner = Some(crate::user::resolve_user(root, user)?);
                }
                fs::create_dir(&target)?;
                if let Some(owner) = &owner {
                    #[cfg(target_os = "linux")]
                    std::os::unix::fs::chown(&target, Some(owner.uid), Some(owner.gid))?;
                    #[cfg(not(target_os = "linux"))]
                    return Err(format!(
                        "WORKDIR ownership requires Linux: {}:{}",
                        owner.uid, owner.gid
                    )
                    .into());
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(target)
}

#[derive(Default)]
struct RootUsage {
    bytes: u64,
    entries: usize,
    #[cfg(target_os = "linux")]
    unique_payload_bytes: u64,
}

fn root_budget(root: &Path, limits: Limits, c: &impl Fn() -> bool) -> Result<RootUsage> {
    fn walk(
        p: &Path,
        usage: &mut RootUsage,
        _payloads: &mut std::collections::BTreeSet<(u64, u64)>,
        depth: usize,
        l: Limits,
        c: &impl Fn() -> bool,
    ) -> Result<()> {
        check(c)?;
        if depth > 256 {
            return Err("rootfs depth budget exceeded".into());
        }
        // Budget inspection must not change the metadata that COPY will export.
        let directory = fs::File::open(p)?;
        let accessed = directory.metadata()?.accessed()?;
        let result = (|| {
            for entry in fs::read_dir(p)? {
                check(c)?;
                let p = entry?.path();
                let m = fs::symlink_metadata(&p)?;
                usage.entries = usage
                    .entries
                    .checked_add(1)
                    .ok_or("rootfs entry overflow")?;
                usage.bytes = usage
                    .bytes
                    .checked_add(m.len())
                    .ok_or("rootfs byte overflow")?;
                if usage.entries > l.max_rootfs_entries || usage.bytes > l.max_rootfs_bytes {
                    return Err("rootfs budget exceeded".into());
                }
                // Replay expands sparse files but preserves hardlink payload sharing.
                #[cfg(target_os = "linux")]
                if m.is_file() {
                    use std::os::unix::fs::MetadataExt;
                    if m.nlink() == 1 || _payloads.insert((m.dev(), m.ino())) {
                        usage.unique_payload_bytes = usage
                            .unique_payload_bytes
                            .checked_add(m.len())
                            .ok_or("rootfs allocation overflow")?;
                    }
                }
                if m.is_dir() {
                    walk(&p, usage, _payloads, depth + 1, l, c)?;
                }
            }
            Ok(())
        })();
        directory.set_times(fs::FileTimes::new().set_accessed(accessed))?;
        result
    }
    let mut usage = RootUsage::default();
    walk(
        root,
        &mut usage,
        &mut std::collections::BTreeSet::new(),
        0,
        limits,
        c,
    )?;
    Ok(usage)
}

fn check_replay_space(
    resources: Option<&crate::build_resources::Policy>,
    root: &Path,
    verified: &layer::VerifiedLayer,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    if resources.is_none() {
        return Ok(());
    }
    let (bytes, inodes) = replay_allocation(root, verified.entries(), cancelled)?;
    resource_check(
        resources,
        "replaying verified layer (additional allocation estimate)",
        &[crate::build_resources::Requirement {
            path: root.to_owned(),
            bytes,
            inodes,
        }],
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn replay_allocation(
    root: &Path,
    entries: &[layer::Entry],
    cancelled: &impl Fn() -> bool,
) -> Result<(u64, u64)> {
    use layer::EntryKind;
    use std::{collections::BTreeSet, ffi::OsStr, os::unix::ffi::OsStrExt};
    let mut removed = BTreeSet::new();
    let mut opaque = BTreeSet::new();
    let mut lower = true;
    for entry in entries {
        check(cancelled)?;
        let split = entry
            .path
            .iter()
            .rposition(|b| *b == b'/')
            .map_or(0, |i| i + 1);
        let name = &entry.path[split..];
        if let Some(target) = name.strip_prefix(b".wh.") {
            // Whiteouts run before all records. Never inspect a host path through
            // a lower symlink; an aliased deletion conservatively invalidates credit.
            for end in entry.path[..split]
                .iter()
                .enumerate()
                .filter_map(|(i, b)| (*b == b'/').then_some(i))
            {
                check(cancelled)?;
                match fs::symlink_metadata(root.join(OsStr::from_bytes(&entry.path[..end]))) {
                    Ok(m) if m.file_type().is_symlink() => {
                        lower = false;
                        break;
                    }
                    Ok(m) if m.is_dir() => (),
                    Ok(_) => break,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                    Err(e) => return Err(e.into()),
                }
            }
            if name == b".wh..wh..opq" {
                opaque.insert(&entry.path[..split.saturating_sub(1)]);
            } else {
                let mut path = entry.path[..split].to_vec();
                path.extend_from_slice(target);
                removed.insert(path);
            }
        }
    }
    // Keys borrow bounded verified paths; only distinct component prefixes are
    // retained. A false value means replay creates the directory, hiding lower data.
    let mut directories = BTreeMap::<&[u8], bool>::new();
    let mut replaced = BTreeSet::<&[u8]>::new();
    let mut aliases = BTreeSet::<&[u8]>::new();
    let mut bytes = 0u64;
    let mut inodes = 1u64;
    for entry in entries {
        check(cancelled)?;
        if entry
            .path
            .rsplit(|b| *b == b'/')
            .next()
            .unwrap()
            .starts_with(b".wh.")
            || entry.path.is_empty()
        {
            continue;
        }
        if !lower {
            // Once traversal involves aliases, retain the conservative per-record
            // parent allowance rather than crediting uncertain physical locations.
            directories.clear();
        }
        let mut existing = lower && !opaque.contains(b"".as_slice());
        let mut parent = b"".as_slice();
        let ends = entry
            .path
            .iter()
            .enumerate()
            .filter_map(|(i, b)| (*b == b'/').then_some(i))
            .chain((entry.kind == EntryKind::Directory).then_some(entry.path.len()));
        for end in ends {
            check(cancelled)?;
            let path = &entry.path[..end];
            if aliases.contains(path) {
                directories.clear();
                lower = false;
                existing = false;
            }
            if let Some(known) = directories.get(path) {
                existing = *known;
            } else {
                existing &=
                    !removed.contains(path) && !opaque.contains(parent) && !replaced.contains(path);
                if existing {
                    // All preceding components were real directories. lstat never
                    // follows the leaf or reads directory contents/timestamps.
                    existing = match fs::symlink_metadata(root.join(OsStr::from_bytes(path))) {
                        Ok(m) if m.file_type().is_symlink() => {
                            directories.clear();
                            lower = false;
                            false
                        }
                        Ok(m) => m.is_dir(),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                        Err(e) => return Err(e.into()),
                    };
                }
                if !existing {
                    inodes = inodes
                        .checked_add(1)
                        .ok_or("replay inode estimate overflow")?;
                    bytes = bytes
                        .checked_add(4096)
                        .ok_or("replay space estimate overflow")?;
                }
                directories.insert(path, existing);
            }
            parent = path;
        }
        if entry.kind != EntryKind::Directory {
            // Replacement records can retain old pinned inodes. Hardlinks allocate
            // directory entries, but neither another payload nor another inode.
            let payload = if entry.kind == EntryKind::File {
                entry.size
            } else {
                0
            };
            let payload = payload.checked_add(4095).ok_or("replay size overflow")? / 4096 * 4096;
            bytes = bytes
                .checked_add(payload)
                .and_then(|n| n.checked_add(4096))
                .ok_or("replay space estimate overflow")?;
            inodes = inodes
                .checked_add(u64::from(entry.kind != EntryKind::Hardlink))
                .ok_or("replay inode estimate overflow")?;
            // Remove only this subtree's cached directories, with cancellable work
            // proportional to prefixes inserted, including repeated replacements.
            let path = entry.path.as_slice();
            directories.remove(path);
            let mut prefix = path.to_vec();
            prefix.push(b'/');
            loop {
                check(cancelled)?;
                let next = directories
                    .range(prefix.as_slice()..)
                    .next()
                    .map(|(p, _)| *p);
                match next {
                    Some(p) if p.starts_with(&prefix) => {
                        directories.remove(p);
                    }
                    _ => break,
                }
            }
            replaced.insert(path);
            if matches!(entry.kind, EntryKind::Symlink | EntryKind::Hardlink) {
                aliases.insert(path);
            } else {
                aliases.remove(path);
            }
        }
    }
    Ok((bytes, inodes))
}

#[cfg(not(target_os = "linux"))]
fn replay_allocation(_: &Path, _: &[layer::Entry], _: &impl Fn() -> bool) -> Result<(u64, u64)> {
    Err("layer replay requires Linux".into())
}

fn check_spool_space(
    resources: Option<&crate::build_resources::Policy>,
    spool: &Path,
    descriptor: &Descriptor,
) -> Result<()> {
    // Plain tar size is known before spooling. Compressed expansion is unknown;
    // its streaming cancellation callback still rechecks current disk reserves.
    if descriptor.media_type.ends_with(".tar") {
        resource_check(
            resources,
            "verifying uncompressed layer spool",
            &[crate::build_resources::Requirement {
                path: spool.to_owned(),
                bytes: u64::try_from(descriptor.size).map_err(|_| "negative layer size")?,
                inodes: 1,
            }],
        )?;
    }
    Ok(())
}

fn check_layout_space(
    resources: Option<&crate::build_resources::Policy>,
    source: &Path,
    destination: &Path,
    shared_pool: Option<&Path>,
    limits: Limits,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    if resources.is_none() {
        return Ok(());
    }
    let mut bytes = 65536u64;
    let mut inodes = 8u64;
    let mut count = 0usize;
    for entry in fs::read_dir(source.join("blobs/sha256"))? {
        check(cancelled)?;
        count = count
            .checked_add(1)
            .ok_or("layout descriptor count overflow")?;
        if count > limits.image.max_descriptors {
            return Err("layout resource scan descriptor limit".into());
        }
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("layout resource scan requires regular blob files".into());
        }
        // Existing managed blobs are verified by publication; this observation
        // only avoids reserving a second payload when no copy will be made.
        let reused = shared_pool.is_some_and(|p| p.join(entry.file_name()).exists());
        if !reused {
            bytes = bytes
                .checked_add(metadata.len())
                .and_then(|n| n.checked_add(4096))
                .ok_or("layout copy space overflow")?;
        }
        inodes = inodes
            .checked_add(if shared_pool.is_some() { 3 } else { 1 })
            .ok_or("layout inode estimate overflow")?;
    }
    resource_check(
        resources,
        "publishing image/checkpoint (measured blobs plus metadata allowance)",
        &[crate::build_resources::Requirement {
            path: destination.to_owned(),
            bytes,
            inodes,
        }],
    )?;
    Ok(())
}

/// Parse/static-preflight completely before creating directories. Spawns the
/// current executable's `__trace-worker` and `__lease-guard` dispatches.
/// Embedders must implement both, before threads and signal handlers.
/// Cancellation is cooperative for I/O; RUN cancellation signals its dedicated
/// worker through the lease guard, waiting for descendant-safe cleanup.
struct StageResult {
    work: PathBuf,
    image: Option<BuildResult>,
    args: BTreeMap<String, String>,
    prepared: Option<PreparedStage>,
}

struct PreparedStage {
    receipt: rootfs::ReplayReceipt,
    manifest: Descriptor,
    replay_usage: (u64, usize),
}

/// COPY may observe symlinks and change source atimes, so only FROM-only parents
/// are eligible. Their last selected reader can consume the exclusively owned root.
fn root_handoffs(plan: &build_plan::BuildPlan, selected: &[usize]) -> BTreeMap<usize, usize> {
    let mut last_from = BTreeMap::new();
    let mut copied = std::collections::BTreeSet::new();
    for &n in selected {
        if let Base::Stage(base) = plan.stages[n].base {
            last_from.insert(base, n);
        }
        for instruction in &plan.stages[n].instructions {
            if let I::Copy {
                from: Some(CopySource::Stage(base)),
                ..
            } = instruction.kind
            {
                copied.insert(base);
            }
        }
    }
    last_from
        .into_iter()
        .filter(|(base, _)| !copied.contains(base))
        .map(|(base, child)| (child, base))
        .collect()
}

fn copy_input(
    source: &CopySource,
    previous: &BTreeMap<usize, StageResult>,
    external: &BTreeMap<String, (PathBuf, String)>,
) -> (PathBuf, Option<String>) {
    match source {
        CopySource::Stage(n) => (
            previous[n].work.join("rootfs"),
            previous[n]
                .image
                .as_ref()
                .map(|image| image.manifest.digest.to_string()),
        ),
        CopySource::Image(name) => {
            let (root, identity) = &external[name];
            (root.clone(), Some(identity.clone()))
        }
    }
}

fn verify_checkpoint(
    layout: &Path,
    config: &Value,
    root: Option<&Path>,
    spool: &Path,
    limits: Limits,
    resources: Option<&crate::build_resources::Policy>,
    cancelled: &impl Fn() -> bool,
) -> Result<Descriptor> {
    for suffix in ["", "blobs", "blobs/sha256"] {
        let m = fs::symlink_metadata(layout.join(suffix))?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err("invalid checkpoint blob directory".into());
        }
    }
    let metadata = image::load_layout(layout, None, limits.image, cancelled)?;
    if metadata.config["config"] != *config {
        return Err("checkpoint config does not match evaluated instruction".into());
    }
    let store = BlobStore::open(layout)?;
    let mut bytes = 0u64;
    let mut entries = 0usize;
    for (descriptor, diff) in metadata.layers.iter().zip(&metadata.diff_ids) {
        check(cancelled)?;
        let mut budget = limits.layer;
        budget.max_uncompressed_bytes = budget
            .max_uncompressed_bytes
            .min(limits.max_replay_bytes.saturating_sub(bytes));
        budget.max_entries = budget
            .max_entries
            .min(limits.max_replay_entries.saturating_sub(entries));
        check_spool_space(resources, spool, descriptor)?;
        let mut verified = layer::verify(&store, descriptor, diff, spool, budget, cancelled)?;
        bytes += verified.size();
        entries += verified.physical_header_count();
        if let Some(root) = root {
            check_replay_space(resources, root, &verified, cancelled)?;
            rootfs::apply_layer(root, &mut verified, cancelled)?;
            root_budget(root, limits, cancelled)?;
        }
    }
    Ok(metadata.selected)
}

/// Fresh exports copy the already-verified base prefix unchanged. Verify stored
/// blob hashes again, but decode only the newly generated layer. Cache hits still
/// use full verification and replay; this evidence never crosses build lifetimes.
#[allow(clippy::too_many_arguments)]
fn verify_fresh_checkpoint(
    layout: &Path,
    config: &Value,
    base: Option<&image::ImageMetadata>,
    base_usage: (u64, usize),
    spool: &Path,
    limits: Limits,
    resources: Option<&crate::build_resources::Policy>,
    cancelled: &impl Fn() -> bool,
) -> Result<(Descriptor, (u64, usize))> {
    let metadata = image::load_layout(layout, None, limits.image, cancelled)?;
    let base_layers = base.map_or(&[][..], |m| m.layers.as_slice());
    let base_ids = base.map_or(&[][..], |m| m.diff_ids.as_slice());
    if metadata.config["config"] != *config
        || metadata.layers.len() != base_layers.len() + 1
        || !metadata.layers.starts_with(base_layers)
        || !metadata.diff_ids.starts_with(base_ids)
    {
        return Err("fresh checkpoint differs from verified base/config".into());
    }
    let mut budget = limits.layer;
    budget.max_uncompressed_bytes = budget.max_uncompressed_bytes.min(
        limits
            .max_replay_bytes
            .checked_sub(base_usage.0)
            .ok_or("replay byte budget exceeded")?,
    );
    budget.max_entries = budget.max_entries.min(
        limits
            .max_replay_entries
            .checked_sub(base_usage.1)
            .ok_or("replay entry budget exceeded")?,
    );
    let descriptor = metadata.layers.last().unwrap();
    check_spool_space(resources, spool, descriptor)?;
    let verified = layer::verify(
        &BlobStore::open(layout)?,
        descriptor,
        metadata.diff_ids.last().unwrap(),
        spool,
        budget,
        cancelled,
    )?;
    Ok((
        metadata.selected,
        (
            base_usage
                .0
                .checked_add(verified.size())
                .ok_or("replay byte count overflow")?,
            base_usage
                .1
                .checked_add(verified.physical_header_count())
                .ok_or("replay entry count overflow")?,
        ),
    ))
}

struct StageCache<'a> {
    root: PathBuf,
    lease: Option<&'a crate::store_lease::StoreLease>,
    #[cfg(target_os = "linux")]
    managed: Option<crate::oci::ManagedCache<'a>>,
}

impl StageCache<'_> {
    fn lookup(
        &self,
        entry: &Path,
        limits: Limits,
        instructions: usize,
        cancelled: &impl Fn() -> bool,
    ) -> Result<bool> {
        #[cfg(target_os = "linux")]
        if let Some(managed) = &self.managed {
            let key = entry
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("invalid cache key")?;
            return Ok(managed
                .lookup(
                    key,
                    limits.image,
                    limits.layer.max_metadata_bytes,
                    instructions,
                    cancelled,
                )?
                .is_some());
        }
        let _ = (limits, instructions, cancelled);
        crate::build_cache::lookup(entry, self.lease)
    }

    fn publish(
        &self,
        source: &Path,
        entry: &Path,
        targets: &[Vec<Vec<u8>>],
        limits: Limits,
        resources: Option<&crate::build_resources::Policy>,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        let shared_pool = {
            #[cfg(target_os = "linux")]
            {
                self.managed
                    .as_ref()
                    .map(|_| self.root.parent().unwrap().join("content/blobs/sha256"))
            }
            #[cfg(not(target_os = "linux"))]
            {
                None::<PathBuf>
            }
        };
        check_layout_space(
            resources,
            source,
            entry,
            shared_pool.as_deref(),
            limits,
            cancelled,
        )?;
        #[cfg(target_os = "linux")]
        if let Some(managed) = &self.managed {
            let key = entry
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("invalid cache key")?;
            managed.publish(
                source,
                key,
                limits.image,
                targets,
                limits.layer.max_metadata_bytes,
                cancelled,
            )?;
            return Ok(());
        }
        crate::build_cache::publish(
            source,
            self.lease,
            entry,
            Some((targets, limits.layer.max_metadata_bytes)),
            cancelled,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn export_stage(
    root: &Path,
    destination: &Path,
    config: &Value,
    baseline: Option<&export::Baseline>,
    limits: export::Limits,
    resources: Option<&crate::build_resources::Policy>,
    receipt: Option<(&mut Option<rootfs::ReplayReceipt>, u64)>,
    cancelled: &impl Fn() -> bool,
    created: impl FnOnce() -> std::io::Result<()>,
) -> Result<Descriptor> {
    Ok(export::export_created_with_resources(
        root,
        destination,
        config,
        baseline,
        limits,
        resources,
        receipt,
        cancelled,
        created,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn restore_checkpoint(
    layout: &Path,
    config: &Value,
    work: &Path,
    retained: &str,
    spool: &Path,
    limits: Limits,
    resources: Option<&crate::build_resources::Policy>,
    cancelled: &impl Fn() -> bool,
) -> Result<Descriptor> {
    let replacement = work.join(format!("checkpoint-{retained}"));
    create_image_root(&replacement)?;
    let manifest = verify_checkpoint(
        layout,
        config,
        Some(&replacement),
        spool,
        limits,
        resources,
        cancelled,
    )?;
    check(cancelled)?;
    let root = work.join("rootfs");
    fs::rename(&root, work.join(retained))?;
    fs::rename(&replacement, &root)?;
    Ok(manifest)
}

fn create_image_root(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    // This is image '/', not private host state. Replay may override this baseline.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Select the target and only its transitive FROM/COPY dependencies.
/// Plans containing FROM templates must pass through resolve_plan first.
pub fn selected_stages(plan: &build_plan::BuildPlan, target: Option<&str>) -> Result<Vec<usize>> {
    if plan
        .stages
        .iter()
        .any(|s| matches!(&s.base, Base::Image(name) if name.contains('$')))
    {
        return Err("resolve FROM arguments before selecting stages".into());
    }
    let last = match target {
        Some(name) => plan
            .stages
            .iter()
            .position(|s| {
                s.name
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
            .ok_or("unknown target stage")?,
        None => plan
            .stages
            .len()
            .checked_sub(1)
            .ok_or("Dockerfile needs a stage")?,
    };
    let mut selected = std::collections::BTreeSet::new();
    let mut pending = vec![last];
    while let Some(n) = pending.pop() {
        if !selected.insert(n) {
            continue;
        }
        if let Base::Stage(base) = plan.stages[n].base {
            pending.push(base);
        }
        for i in &plan.stages[n].instructions {
            if let I::Copy {
                from: Some(CopySource::Stage(from)),
                ..
            } = i.kind
            {
                pending.push(from);
            }
        }
    }
    Ok(selected.into_iter().collect())
}

/// External FROM/COPY images needed by the selected stages, before local bindings.
pub fn selected_images(
    plan: &build_plan::BuildPlan,
    selected: &[usize],
) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for &n in selected {
        if let Base::Image(name) = &plan.stages[n].base
            && name != "scratch"
        {
            names.insert(name.clone());
        }
        for instruction in &plan.stages[n].instructions {
            if let I::Copy {
                from: Some(CopySource::Image(name)),
                ..
            } = &instruction.kind
            {
                names.insert(name.clone());
            }
        }
    }
    names
}

/// Compatibility entry point for truly unmanaged paths only.
pub fn build(
    source: &str,
    options: &BuildOptions,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    build_inner(source, options, None, None, None, cancelled)
}

/// Caller keeps this lease through use of returned managed paths, tagging and push.
pub fn build_with_lease(
    source: &str,
    options: &BuildOptions,
    lease: &crate::store_lease::StoreLease,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    build_inner(source, options, Some(lease), None, None, cancelled)
}

#[cfg(target_os = "linux")]
pub fn build_recorded(
    source: &str,
    options: &BuildOptions,
    lease: &crate::store_lease::StoreLease,
    record: &mut crate::build_record::BuildRecord,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    record.update(lease, |r| r.phase = crate::build_record::Phase::Building)?;
    let result = build_inner(source, options, Some(lease), Some(record), None, cancelled);
    if result.is_err() && record.record.manifest.is_none() {
        record.update(lease, |r| r.phase = crate::build_record::Phase::Failed)?;
    }
    result
}

/// Managed CLI entry point with current-capacity checks. These are observations,
/// not quotas; trusted RUN commands can allocate faster than cooperative polling.
#[cfg(target_os = "linux")]
pub fn build_recorded_with_resources(
    source: &str,
    options: &BuildOptions,
    lease: &crate::store_lease::StoreLease,
    record: &mut crate::build_record::BuildRecord,
    resources: &crate::build_resources::Policy,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    record.update(lease, |r| r.phase = crate::build_record::Phase::Building)?;
    let result = build_inner(
        source,
        options,
        Some(lease),
        Some(record),
        Some(resources),
        cancelled,
    );
    if result.is_err() && record.record.manifest.is_none() {
        record.update(lease, |r| r.phase = crate::build_record::Phase::Failed)?;
    }
    result
}

// Reuse normal cancellation and descendant cleanup when resources shrink during
// a RUN or streamed write, but report the capacity error instead of "cancelled".
fn with_resource_checks<T>(
    mut recheck: impl FnMut() -> std::result::Result<(), String>,
    cancelled: impl Fn() -> bool,
    run: impl FnOnce(&dyn Fn() -> bool) -> Result<T>,
) -> Result<T> {
    use std::cell::{Cell, RefCell};
    check(&cancelled)?;
    recheck()?;
    let recheck = RefCell::new(recheck);
    let last = Cell::new(std::time::Instant::now());
    let failure = RefCell::new(None);
    let stop = || {
        if cancelled() || failure.borrow().is_some() {
            return true;
        }
        if last.get().elapsed() >= std::time::Duration::from_secs(1) {
            last.set(std::time::Instant::now());
            if let Err(error) = (recheck.borrow_mut())() {
                *failure.borrow_mut() = Some(error);
                return true;
            }
        }
        false
    };
    let result = run(&stop);
    // Do not turn an already-published success into a failure after the fact.
    match (result, failure.into_inner()) {
        (Err(original), Some(error)) => {
            Err(format!("{error}; stopped operation: {original}").into())
        }
        (result, _) => result,
    }
}

fn build_inner(
    source: &str,
    options: &BuildOptions,
    lease: Option<&crate::store_lease::StoreLease>,
    record: Option<&mut crate::build_record::BuildRecord>,
    resources: Option<&crate::build_resources::Policy>,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    match resources {
        Some(policy) => with_resource_policy(policy, "build in progress", cancelled, |stop| {
            build_inner_checked(source, options, lease, record, resources, stop)
        }),
        None => build_inner_checked(source, options, lease, record, None, cancelled),
    }
}

/// Apply current-space checks to a cooperative managed operation, including
/// registry transfers. The callback must stop and clean up when asked to cancel.
pub fn with_resource_policy<T>(
    resources: &crate::build_resources::Policy,
    operation: &str,
    cancelled: impl Fn() -> bool,
    run: impl FnOnce(&dyn Fn() -> bool) -> Result<T>,
) -> Result<T> {
    with_resource_checks(|| resources.recheck(operation, &[]), cancelled, run)
}

fn resource_check(
    resources: Option<&crate::build_resources::Policy>,
    operation: &str,
    requirements: &[crate::build_resources::Requirement],
) -> std::result::Result<(), String> {
    resources.map_or(Ok(()), |p| p.recheck(operation, requirements))
}

fn build_inner_checked(
    source: &str,
    options: &BuildOptions,
    lease: Option<&crate::store_lease::StoreLease>,
    mut record: Option<&mut crate::build_record::BuildRecord>,
    resources: Option<&crate::build_resources::Policy>,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err("build requires Linux amd64".into());
    }
    check(&cancelled)?;
    if options.cache.is_some() && options.managed_cache.is_some() {
        return Err("choose either an external cache or a managed cache store".into());
    }
    for path in [&options.work, &options.output, &options.context]
        .into_iter()
        .chain(options.bases.values().map(|b| &b.layout))
        .chain(options.cache.iter().filter(|_| !options.no_cache))
        .chain(options.managed_cache.iter().filter(|_| !options.no_cache))
        .chain(options.dockerfile.iter())
    {
        crate::store_access::validate_path(path, lease)?;
    }
    let plan = resolve_plan(source, &options.args, options.limits.max_plan_bytes)?;
    let policy = context::load_policy(&options.context, options.dockerfile.as_deref(), &cancelled)?;
    let selected = selected_stages(&plan, options.target.as_deref())?;
    let target = *selected.last().unwrap();
    let work = fresh(&options.work)?;
    let output = fresh(&options.output)?;
    let context = fs::canonicalize(&options.context)?;
    let mut paths = vec![work.clone(), output, context];
    disjoint(&paths)?;
    for base in options.bases.values() {
        paths.push(fs::canonicalize(&base.layout)?);
    }
    // Multiple aliases may intentionally bind the same immutable base.
    paths.sort();
    paths.dedup();
    disjoint(&paths)?;
    if let Some(cache) = options.cache.as_ref().filter(|_| !options.no_cache) {
        let cache = fs::canonicalize(cache)?;
        for path in &paths {
            disjoint(&[cache.clone(), path.clone()])?;
        }
    }
    if let Some(store) = options.managed_cache.as_ref().filter(|_| !options.no_cache) {
        let lease = lease.ok_or("managed cache requires a borrowed store lease")?;
        crate::store_access::validate_root(store, lease)?;
        let cache = fs::canonicalize(store)?.join("cache-v2");
        for path in &paths {
            disjoint(&[cache.clone(), path.clone()])?;
        }
    }
    // Evaluate all selected stages before any RUN, with inherited config/ARG scopes.
    let mut evaluated: BTreeMap<usize, (Value, BTreeMap<String, String>)> = BTreeMap::new();
    let mut evaluated_bytes = 0usize;
    for &n in &selected {
        check(&cancelled)?;
        let (config, args) = match &plan.stages[n].base {
            Base::Stage(base) => evaluated[base].clone(),
            Base::Image(name) if name == "scratch" => (
                json!({"os":"linux", "architecture":"amd64", "config":{}}),
                BTreeMap::new(),
            ),
            Base::Image(name) => {
                let b = options
                    .bases
                    .get(name)
                    .ok_or_else(|| format!("no local base binding for {name}"))?;
                (
                    image::load_layout(
                        &b.layout,
                        b.reference.as_deref(),
                        options.limits.image,
                        &cancelled,
                    )?
                    .config,
                    BTreeMap::new(),
                )
            }
        };
        let (config, steps, args) = preflight_stage(&plan, n, options, config, args)?;
        check_copy_sources(&steps, options, &policy, &cancelled)?;
        evaluated_bytes = evaluated_bytes
            .checked_add(serde_json::to_vec(&config)?.len())
            .and_then(|n| n.checked_add(args.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()))
            .ok_or("multi-stage metadata overflow")?;
        if evaluated_bytes > options.limits.max_plan_bytes {
            return Err("multi-stage evaluated metadata budget exceeded".into());
        }
        evaluated.insert(n, (config, args));
    }
    let copy_names: std::collections::BTreeSet<_> = selected
        .iter()
        .flat_map(|&n| {
            plan.stages[n]
                .instructions
                .iter()
                .filter_map(|i| match &i.kind {
                    I::Copy {
                        from: Some(CopySource::Image(name)),
                        ..
                    } => Some(name.clone()),
                    _ => None,
                })
        })
        .collect();
    let intermediate = if selected.len() > 1 || !copy_names.is_empty() {
        #[cfg(target_os = "linux")]
        if let Some(r) = record.as_deref_mut() {
            let path = r.path.join("stages");
            fs::create_dir(&path)?;
            r.created(&path, lease.unwrap())?;
            Some(path)
        } else {
            Some(
                tempfile::Builder::new()
                    .prefix(".weld-stages-")
                    .tempdir_in(work.parent().unwrap())?
                    .keep(),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            None::<PathBuf>
        }
    } else {
        None
    };
    let mut external = BTreeMap::new();
    for (index, name) in copy_names.iter().enumerate() {
        let phase = crate::progress::Phase::start(
            options.progress,
            format!("Preparing COPY image {}/{}", index + 1, copy_names.len()),
        );
        let cancelled = || {
            phase.tick();
            cancelled()
        };
        check(&cancelled)?;
        let binding = options
            .bases
            .get(name)
            .ok_or_else(|| format!("no local base binding for COPY image {name}"))?;
        let layout = fs::canonicalize(&binding.layout)?;
        for suffix in ["", "blobs", "blobs/sha256"] {
            let m = fs::symlink_metadata(binding.layout.join(suffix))?;
            if !m.is_dir() || m.file_type().is_symlink() {
                return Err("COPY image blob directories must be real directories".into());
            }
        }
        let metadata = image::load_layout(
            &layout,
            binding.reference.as_deref(),
            options.limits.image,
            cancelled,
        )?;
        let directory = intermediate
            .as_ref()
            .unwrap()
            // Reserve IDs after Dockerfile stages in the existing owned-work schema.
            .join(format!("stage-{}-work", plan.stages.len() + index));
        fs::create_dir(&directory)?;
        #[cfg(target_os = "linux")]
        if let Some(r) = record.as_deref_mut() {
            r.created(&directory, lease.unwrap())?;
        }
        let root = directory.join("rootfs");
        let spool = directory.join("spool");
        create_image_root(&root)?;
        fs::create_dir(&spool)?;
        let store = BlobStore::open(&layout)?;
        let (mut bytes, mut entries) = (0u64, 0usize);
        for (descriptor, diff) in metadata.layers.iter().zip(&metadata.diff_ids) {
            check(&cancelled)?;
            let mut budget = options.limits.layer;
            budget.max_uncompressed_bytes = budget
                .max_uncompressed_bytes
                .min(options.limits.max_replay_bytes.saturating_sub(bytes));
            budget.max_entries = budget
                .max_entries
                .min(options.limits.max_replay_entries.saturating_sub(entries));
            check_spool_space(resources, &spool, descriptor)?;
            let mut verified = layer::verify(&store, descriptor, diff, &spool, budget, cancelled)?;
            bytes += verified.size();
            entries += verified.physical_header_count();
            check_replay_space(resources, &root, &verified, &cancelled)?;
            rootfs::apply_layer(&root, &mut verified, cancelled)?;
            root_budget(&root, options.limits, &cancelled)?;
        }
        external.insert(name.clone(), (root, metadata.selected.digest.to_string()));
        phase.finish();
    }
    let mut previous = BTreeMap::new();
    let mut notice = false;
    // COPY consumes an owned root directly; FROM still requires a verified OCI image.
    let inherited_stages: std::collections::BTreeSet<_> = selected
        .iter()
        .filter_map(|&n| match plan.stages[n].base {
            Base::Stage(base) => Some(base),
            Base::Image(_) => None,
        })
        .collect();
    let handoffs = if options.no_cache && options.export_mode == ExportMode::Layered {
        root_handoffs(&plan, &selected)
    } else {
        BTreeMap::new()
    };
    let mut receipts_remaining = options.limits.export.max_metadata_bytes;
    for n in selected {
        let mut stage_options = options.clone();
        if n != target {
            let parent = intermediate.as_ref().unwrap();
            stage_options.work = parent.join(format!("stage-{n}-work"));
            stage_options.output = parent.join(format!("stage-{n}-image"));
        }
        let phase = crate::progress::Phase::start(
            options.progress,
            format!("Stage {}/{}", n + 1, plan.stages.len()),
        );
        let prepared_base = handoffs.get(&n).and_then(|base| {
            let parent: &mut StageResult = previous.get_mut(base)?;
            parent
                .prepared
                .take()
                .map(|prepared| (parent.work.join("rootfs"), prepared))
        });
        if let Some((_, prepared)) = &prepared_base {
            receipts_remaining = receipts_remaining
                .checked_add(prepared.receipt.metadata_bytes())
                .ok_or("root receipt metadata overflow")?;
        }
        let result = build_stage(
            &plan,
            n,
            &stage_options,
            &previous,
            &external,
            &mut notice,
            &policy,
            record.as_deref_mut(),
            n == target,
            !options.no_cache || n == target || inherited_stages.contains(&n),
            prepared_base,
            handoffs
                .values()
                .any(|&parent| parent == n)
                .then_some(receipts_remaining),
            lease,
            resources,
            || {
                phase.tick();
                cancelled()
            },
        );
        let result = result?;
        if let Some(prepared) = &result.prepared {
            receipts_remaining = receipts_remaining
                .checked_sub(prepared.receipt.metadata_bytes())
                .ok_or("retained root receipts exceed metadata budget")?;
        }
        previous.insert(n, result);
        phase.finish();
    }
    previous
        .remove(&target)
        .unwrap()
        .image
        .ok_or_else(|| "target stage image missing".into())
}

#[allow(clippy::too_many_arguments)] // Keep the operation lease explicit at each call boundary.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables, unused_mut))]
fn build_stage(
    plan: &build_plan::BuildPlan,
    index: usize,
    options: &BuildOptions,
    previous: &BTreeMap<usize, StageResult>,
    external: &BTreeMap<String, (PathBuf, String)>,
    notice: &mut bool,
    policy: &crate::dockerignore::Policy,
    mut record: Option<&mut crate::build_record::BuildRecord>,
    final_stage: bool,
    export_image: bool,
    prepared_base: Option<(PathBuf, PreparedStage)>,
    prepare_handoff: Option<u64>,
    lease: Option<&crate::store_lease::StoreLease>,
    resources: Option<&crate::build_resources::Policy>,
    cancelled: impl Fn() -> bool,
) -> Result<StageResult> {
    check(&cancelled)?;
    // Syntax-only pass: inherited ENV must not be guessed before loading config.
    for instruction in plan
        .global_args
        .iter()
        .chain(plan.stages[index].instructions.iter())
    {
        let empty = BTreeMap::new();
        match &instruction.kind {
            I::Arg {
                default: Some(s), ..
            } => {
                expand(s, &empty, options.limits.max_plan_bytes)?;
            }
            I::StopSignal(w) => {
                expand(&w.raw, &empty, options.limits.max_plan_bytes)
                    .map_err(|e| format!("line {}: STOPSIGNAL: {e}", instruction.line))?;
            }
            I::Workdir(w) | I::User(w) => {
                expand(&w.raw, &empty, options.limits.max_plan_bytes)?;
            }
            I::Env(words) => {
                for w in words {
                    expand(&w.raw, &empty, options.limits.max_plan_bytes)?;
                }
            }
            _ => (),
        }
    }
    if !(1..=86400).contains(&options.limits.run_timeout_seconds) {
        return Err("RUN timeout must be 1..86400 seconds".into());
    }
    let work = fresh(&options.work)?;
    let output = fresh(&options.output)?;
    let context = fs::canonicalize(&options.context)?;
    if !context.is_dir() {
        return Err("context must be a directory".into());
    }
    let mut paths = vec![work.clone(), output.clone(), context];
    let stage_base = match plan.stages[index].base {
        Base::Stage(n) => Some(LocalBase {
            layout: previous[&n]
                .image
                .as_ref()
                .ok_or("inherited stage image missing")?
                .output
                .clone(),
            reference: None,
        }),
        _ => None,
    };
    let binding = match &plan.stages[index].base {
        Base::Image(name) if name == "scratch" => None,
        Base::Image(name) => Some(
            options
                .bases
                .get(name)
                .ok_or_else(|| format!("no local base binding for {name}"))?,
        ),
        Base::Stage(_) => stage_base.as_ref(),
    };
    let mut base_path = binding.map(|b| fs::canonicalize(&b.layout)).transpose()?;
    if let Some(p) = &base_path {
        for suffix in ["", "blobs", "blobs/sha256"] {
            let m = fs::symlink_metadata(p.join(suffix))?;
            if !m.is_dir() || m.file_type().is_symlink() {
                return Err("base blob directories must be real populated directories".into());
            }
        }
        paths.push(p.clone());
    }
    disjoint(&paths)?;
    let mut metadata = match (binding, &base_path) {
        (Some(b), Some(p)) => Some(image::load_layout(
            p,
            b.reference.as_deref(),
            options.limits.image,
            &cancelled,
        )?),
        _ => None,
    };
    let config = metadata
        .as_ref()
        .map(|m| m.config.clone())
        .unwrap_or_else(|| json!({"os":"linux", "architecture":"amd64", "config":{}}));
    let inherited = match plan.stages[index].base {
        Base::Stage(n) => previous[&n].args.clone(),
        _ => BTreeMap::new(),
    };
    let mut checkpoints = Vec::new();
    let (config, mut steps, args) = preflight_checkpoints(
        plan,
        index,
        options,
        config,
        inherited.clone(),
        Some(&mut checkpoints),
    )?;
    check_copy_sources(&steps, options, policy, &cancelled)?;
    let stage_cache = if options.no_cache {
        None
    } else if let Some(store) = &options.managed_cache {
        #[cfg(target_os = "linux")]
        {
            let lease = lease.ok_or("managed cache requires a borrowed store lease")?;
            let managed = crate::oci::ManagedCache::open(store, lease, &cancelled)?;
            Some(StageCache {
                root: fs::canonicalize(store)?.join("cache-v2/entries"),
                lease: Some(lease),
                managed: Some(managed),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = store;
            return Err("managed cache requires Linux".into());
        }
    } else {
        options.cache.as_ref().map(|root| StageCache {
            root: root.clone(),
            lease,
            #[cfg(target_os = "linux")]
            managed: None,
        })
    };
    let cache_entry = if let Some(cache) = &stage_cache {
        let dependencies: Vec<_> = plan.stages[index]
            .instructions
            .iter()
            .filter_map(|i| match &i.kind {
                I::Copy { from: Some(n), .. } => Some(
                    copy_input(n, previous, external)
                        .1
                        .ok_or("cached COPY source image missing"),
                ),
                _ => None,
            })
            .collect::<std::result::Result<_, _>>()?;
        let input = format!(
            "{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{}\n{:?}\n{:?}",
            plan.global_args,
            plan.stages[index],
            options.args,
            options.limits,
            // Later ARG instructions can overwrite values consumed by earlier steps.
            inherited,
            metadata.as_ref().map(|m| &m.selected.digest),
            options.host_dns,
            dependencies,
            options.export_mode
        );
        let uses_context = steps.iter().any(|s| {
            matches!(
                s,
                Step::Copy {
                    from: None,
                    inline: None,
                    ..
                }
            )
        });
        Some(cache.root.join(crate::build_cache::key(
            input.as_bytes(),
            uses_context.then_some(options.context.as_path()),
            options.limits,
            policy,
            &cancelled,
        )?))
    } else {
        None
    };
    // Only inline cache validation needs owned source files before replay.
    // Ordinary cached COPY must reject its budgets before creating any work.
    let inline_cache_sources = cache_entry.is_some()
        && steps.iter().any(|step| {
            matches!(
                step,
                Step::Copy {
                    inline: Some(_),
                    ..
                }
            )
        });
    if inline_cache_sources {
        check(&cancelled)?;
        fs::create_dir(&work)?;
        #[cfg(target_os = "linux")]
        if let Some(r) = record.as_deref_mut() {
            r.created(&work, lease.unwrap())?;
        }
        prepare_inline_sources(&steps, &work, &cancelled)?;
    }
    let mut cache_hit = false;
    if let Some(entry) = &cache_entry
        // Whole-stage replay cannot validate an intermediate RUN's input tree.
        // Keep instruction caching, whose guard runs against each input rootfs.
        && !steps.iter().any(|s| matches!(s, Step::Run { absent_secret: Some(_), .. }))
        && stage_cache.as_ref().unwrap().lookup(
            entry,
            options.limits,
            steps
                .iter()
                .filter(|s| matches!(s, Step::Copy { .. }))
                .count(),
            &cancelled,
        )?
    {
        let targets = crate::build_cache::copy_targets(
            entry,
            lease,
            options.limits.layer.max_metadata_bytes,
            steps
                .iter()
                .filter(|step| matches!(step, Step::Copy { .. }))
                .count(),
        )?;
        let mut targets = targets.iter();
        let mut copied = context::Summary::default();
        for (step_index, step) in steps.iter().enumerate() {
            if let Step::Copy {
                from,
                inline,
                sources,
                ..
            } = step
            {
                let stage_root = if inline.is_some() {
                    Some(work.join(format!("inline-{}", step_index)))
                } else {
                    from.as_ref().map(|n| copy_input(n, previous, external).0)
                };
                let summary = context::validate_copy_budget(
                    stage_root.as_deref().unwrap_or(&options.context),
                    &sources.iter().map(String::as_str).collect::<Vec<_>>(),
                    targets.next().ok_or("missing cached COPY targets")?,
                    copy_limits(options.limits, &copied),
                    if from.is_some() || inline.is_some() {
                        None
                    } else {
                        Some(policy)
                    },
                    &cancelled,
                )?;
                copied.bytes_written += summary.bytes_written;
                copied.entries += summary.entries;
                copied.metadata_bytes += summary.metadata_bytes;
            }
        }
        if targets.next().is_some() {
            return Err("extra cached COPY targets".into());
        }
        for suffix in ["blobs", "blobs/sha256"] {
            let m = fs::symlink_metadata(entry.join(suffix))?;
            if !m.is_dir() || m.file_type().is_symlink() {
                return Err("invalid cache blob directory".into());
            }
        }
        let cached = image::load_layout(entry, None, options.limits.image, &cancelled)?;
        if cached.config["config"] != config["config"] {
            return Err("cache config does not match evaluated stage".into());
        }
        metadata = Some(cached);
        base_path = Some(entry.clone());
        steps.clear();
        checkpoints.clear();
        cache_hit = true;
        if options.progress {
            eprintln!("  CACHED (verified local stage); all instructions");
        }
    }
    #[cfg(target_os = "linux")]
    if steps.iter().any(|s| matches!(s, Step::Run { .. })) && unsafe { libc::geteuid() } != 0 {
        return Err("RUN worker requires root".into());
    }
    if !*notice && steps.iter().any(|s| matches!(s, Step::Run { .. })) {
        *notice = true;
        eprintln!(
            "Note: Weld runs trusted Dockerfiles only; RUN commands can access the Pod's devices and process information."
        );
    }
    check(&cancelled)?;
    if !inline_cache_sources {
        fs::create_dir(&work)?;
        #[cfg(target_os = "linux")]
        if let Some(r) = record.as_deref_mut() {
            r.created(&work, lease.unwrap())?;
        }
        prepare_inline_sources(&steps, &work, &cancelled)?;
    }
    let root = work.join("rootfs");
    let spool = work.join("spool");
    let state = work.join("state");
    for p in [&spool, &state] {
        fs::create_dir(p)?;
    }
    let mut base_replay_usage = (0u64, 0usize);
    let mut transferred = false;
    let mut replay_receipt = None;
    if let Some((source, prepared)) = prepared_base {
        let m = metadata
            .as_ref()
            .ok_or("prepared root base metadata missing")?;
        if prepared.manifest != m.selected
            || prepared.replay_usage.0 > options.limits.max_replay_bytes
            || prepared.replay_usage.1 > options.limits.max_replay_entries
        {
            return Err("prepared root image identity or replay limits changed".into());
        }
        prepared.receipt.validate(&source, &m.diff_ids)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if fs::metadata(&source)?.dev() == fs::metadata(&work)?.dev() {
                check(&cancelled)?;
                match fs::rename(&source, &root) {
                    Ok(()) => {
                        prepared.receipt.validate(&root, &m.diff_ids)?;
                        root_budget(&root, options.limits, &cancelled)?;
                        base_replay_usage = prepared.replay_usage;
                        replay_receipt = Some(prepared.receipt);
                        transferred = true;
                        if options.progress {
                            eprintln!(
                                "[weld]   Reusing owned parent filesystem at its last FROM use (no replay)"
                            );
                        }
                    }
                    // Separate bind mounts can share st_dev while refusing rename.
                    Err(error) if error.raw_os_error() == Some(libc::EXDEV) => (),
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    if !transferred {
        create_image_root(&root)?;
    }
    if !transferred
        && export_image
        && options.export_mode == ExportMode::Layered
        && !cache_hit
        && metadata.is_some()
    {
        replay_receipt = Some(rootfs::ReplayReceipt::new(
            &root,
            options.limits.export.max_metadata_bytes,
        )?);
    }
    if !transferred && let (Some(m), Some(p)) = (&metadata, &base_path) {
        let store = BlobStore::open(p)?;
        let mut bytes = 0u64;
        let mut entries = 0usize;
        let preparation =
            crate::progress::Phase::start(options.progress, "  Preparing base layers");
        for (layer_index, (descriptor, diff)) in m.layers.iter().zip(&m.diff_ids).enumerate() {
            check(&cancelled)?;
            let mut limits = options.limits.layer;
            limits.max_uncompressed_bytes = limits
                .max_uncompressed_bytes
                .min(options.limits.max_replay_bytes - bytes);
            limits.max_entries = limits
                .max_entries
                .min(options.limits.max_replay_entries - entries);
            let phase = crate::progress::Phase::start(
                options.progress && options.verbose,
                format!(
                    "  Layer {}/{}: verifying and decompressing",
                    layer_index + 1,
                    m.layers.len()
                ),
            );
            preparation.detail(format!(
                "{} | layer {}: verifying/decompressing",
                crate::progress::count_bar(layer_index, m.layers.len()),
                layer_index + 1
            ));
            check_spool_space(resources, &spool, descriptor)?;
            let mut verified = layer::verify(&store, descriptor, diff, &spool, limits, || {
                preparation.tick();
                phase.tick();
                cancelled()
            })?;
            phase.finish();
            bytes += verified.size();
            entries += verified.physical_header_count();
            check_replay_space(resources, &root, &verified, &cancelled)?;
            let phase = crate::progress::Phase::start(
                options.progress && options.verbose,
                format!(
                    "  Layer {}/{}: applying filesystem entries",
                    layer_index + 1,
                    m.layers.len()
                ),
            );
            preparation.detail(format!(
                "{} | layer {}: applying",
                crate::progress::count_bar(layer_index, m.layers.len()),
                layer_index + 1
            ));
            let applying = || {
                preparation.tick();
                phase.tick();
                cancelled()
            };
            if let Some(receipt) = &mut replay_receipt {
                receipt.apply(&root, &mut verified, applying)?;
            } else {
                rootfs::apply_layer(&root, &mut verified, applying)?;
            }
            phase.finish();
            let phase = crate::progress::Phase::start(
                options.progress && options.verbose,
                "  Checking filesystem budgets",
            );
            preparation.detail(format!(
                "{} | checking filesystem budgets",
                crate::progress::count_bar(layer_index, m.layers.len())
            ));
            root_budget(&root, options.limits, &|| {
                preparation.tick();
                phase.tick();
                cancelled()
            })?;
            phase.finish();
        }
        base_replay_usage = (bytes, entries);
        preparation.detail(crate::progress::count_bar(m.layers.len(), m.layers.len()));
        preparation.finish();
    }
    let baseline = if export_image && options.export_mode == ExportMode::Layered && !cache_hit {
        let phase = crate::progress::Phase::start(
            options.progress,
            "  Capturing verified base filesystem (no replay)",
        );
        let capturing = || {
            phase.tick();
            cancelled()
        };
        let baseline = match (&base_path, &metadata, replay_receipt) {
            (Some(layout), Some(metadata), Some(receipt)) => export::Baseline::capture_replayed(
                &root,
                layout,
                metadata,
                receipt,
                options.limits.export,
                options.limits.image.max_layer_bytes,
                capturing,
            )?,
            (None, None, None) => {
                export::Baseline::scratch(&root, options.limits.export, capturing)?
            }
            _ => return Err("inconsistent layered export base".into()),
        };
        phase.finish();
        Some(baseline)
    } else {
        None
    };
    let mut copied = context::Summary::default();
    let mut copy_targets = Vec::new();
    let mut materialized = metadata.is_some();
    let builder_identity = if cache_entry.is_some() && !cache_hit {
        Some(crate::build_cache::key(
            b"instruction-builder",
            None,
            options.limits,
            policy,
            &cancelled,
        )?)
    } else {
        None
    };
    let mut prior_identity = metadata.as_ref().map(|m| m.selected.digest.to_string());
    let mut last_checkpoint: Option<(PathBuf, Descriptor, Value)> = None;
    let mut start = 0usize;
    for boundary in &checkpoints {
        let started = std::time::Instant::now();
        if options.progress {
            eprintln!(
                "[weld] [stage {} instruction {}] {} START",
                index + 1,
                boundary.ordinal,
                boundary.operation
            );
        }
        let instruction_steps = &steps[start..boundary.end];
        for step in instruction_steps {
            if let Step::Run {
                absent_secret: Some(id),
                ..
            } = step
            {
                validate_absent_secret(&root, id)?;
                eprintln!(
                    "Note: optional secret {id}: no secret supplied; /run/secrets/{id} verified absent."
                );
            }
        }
        let mut fingerprint_summary: Option<context::Summary> = None;
        let entry = if let Some(builder) = &builder_identity {
            let mut selected: Vec<u8> = Vec::new();
            let mut dependency = None;
            let mut available = true;
            for (offset, step) in instruction_steps.iter().enumerate() {
                if let Step::Copy {
                    from,
                    inline,
                    sources,
                    destination,
                    chown,
                    chmod,
                } = step
                {
                    let stage_root = if inline.is_some() {
                        Some(work.join(format!("inline-{}", start + offset)))
                    } else {
                        from.as_ref().map(|n| copy_input(n, previous, external).0)
                    };
                    dependency = from
                        .as_ref()
                        .map(|n| {
                            copy_input(n, previous, external)
                                .1
                                .ok_or("cached COPY source image missing")
                        })
                        .transpose()?;
                    #[cfg(target_os = "linux")]
                    {
                        match context::fingerprint_copy(
                            stage_root.as_deref().unwrap_or(&options.context),
                            &root,
                            &sources.iter().map(String::as_str).collect::<Vec<_>>(),
                            destination,
                            copy_limits(options.limits, &copied),
                            if from.is_some() || inline.is_some() {
                                None
                            } else {
                                Some(policy)
                            },
                            context::CopyOptions {
                                chown: chown.as_deref(),
                                chmod: *chmod,
                            },
                            &cancelled,
                        ) {
                            Ok((fingerprint, summary)) => {
                                selected = fingerprint;
                                fingerprint_summary = Some(summary);
                            }
                            Err(context::Error::FingerprintUnavailable(_)) => available = false,
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
            }
            let inputs = format!(
                "{builder}\n{prior_identity:?}\n{:?}\n{}\n{materialized}\n{:?}\n{:?}\n{instruction_steps:?}\n{dependency:?}\n{:?}",
                options.limits,
                options.host_dns,
                boundary.config,
                boundary.args,
                options.export_mode
            );
            let inputs = serde_json::to_vec(&(inputs, selected))?;
            available.then(|| {
                stage_cache
                    .as_ref()
                    .unwrap()
                    .root
                    .join(crate::build_cache::instruction_key(&inputs))
            })
        } else {
            None
        };
        if let Some(entry) = &entry
            && stage_cache.as_ref().unwrap().lookup(
                entry,
                options.limits,
                instruction_steps
                    .iter()
                    .filter(|s| matches!(s, Step::Copy { .. }))
                    .count(),
                &cancelled,
            )?
        {
            let targets = crate::build_cache::copy_targets(
                entry,
                lease,
                options.limits.layer.max_metadata_bytes,
                usize::from(fingerprint_summary.is_some()),
            )?;
            if let Some(summary) = fingerprint_summary {
                if targets != vec![summary.targets.clone()] {
                    return Err("checkpoint COPY receipt does not match current selection".into());
                }
                copied.bytes_written += summary.bytes_written;
                copied.entries += summary.entries;
                copied.metadata_bytes += summary.metadata_bytes;
                copy_targets.push(summary.targets);
            }
            let manifest = restore_checkpoint(
                entry,
                &boundary.config,
                &work,
                &format!("rootfs-before-{}", boundary.ordinal),
                &spool,
                options.limits,
                resources,
                &cancelled,
            )?;
            materialized |= instruction_steps
                .iter()
                .any(|step| !matches!(step, Step::Directory { path, .. } if path == "/"));
            prior_identity = Some(manifest.digest.to_string());
            last_checkpoint = Some((entry.clone(), manifest, boundary.config.clone()));
            if options.progress {
                eprintln!(
                    "  CACHED instruction {} {} [stage {}] {:.3}s",
                    boundary.ordinal,
                    boundary.operation,
                    index + 1,
                    started.elapsed().as_secs_f64()
                );
            }
            start = boundary.end;
            continue;
        }
        let receipt_start = copy_targets.len();
        let run_label = format!("stage {} instruction {} RUN", index + 1, boundary.ordinal);
        for (index, step) in steps.iter().enumerate().take(boundary.end).skip(start) {
            check(&cancelled)?;
            match step {
                Step::Copy {
                    from,
                    inline,
                    sources,
                    destination,
                    chown,
                    chmod,
                } => {
                    // Untouched scratch has no filesystem reference for named lookup.
                    if !materialized
                        && chown.as_deref().is_some_and(|value| {
                            value.split(':').any(|part| {
                                !part.is_empty() && part != "root" && part.parse::<u32>().is_err()
                            })
                        })
                    {
                        return Err(
                            "COPY named ownership requires a materialized image filesystem".into(),
                        );
                    }
                    let stage_root = if inline.is_some() {
                        Some(work.join(format!("inline-{}", index)))
                    } else {
                        from.as_ref().map(|n| copy_input(n, previous, external).0)
                    };
                    let admission = |bytes, inodes| {
                        resource_check(
                            resources,
                            "COPY prepared allocation",
                            &[crate::build_resources::Requirement {
                                path: root.clone(),
                                bytes,
                                inodes,
                            }],
                        )
                        .map_err(|e| context::Error::Io(io::Error::other(e)))
                    };
                    let summary = context::copy_filtered_checked(
                        stage_root.as_deref().unwrap_or(&options.context),
                        &root,
                        &sources.iter().map(String::as_str).collect::<Vec<_>>(),
                        destination,
                        copy_limits(options.limits, &copied),
                        if from.is_some() || inline.is_some() {
                            None
                        } else {
                            Some(policy)
                        },
                        context::CopyOptions {
                            chown: chown.as_deref(),
                            chmod: *chmod,
                        },
                        resources.map(|_| &admission as &dyn Fn(u64, u64) -> _),
                        &cancelled,
                    )?;
                    copied.bytes_written += summary.bytes_written;
                    copied.entries += summary.entries;
                    copied.metadata_bytes += summary.metadata_bytes;
                    copy_targets.push(summary.targets);
                }
                Step::Directory { path, user } => {
                    directory(&root, path, user.as_deref())?;
                }
                Step::Run {
                    command,
                    workdir,
                    env,
                    user,
                    absent_secret,
                } => {
                    if let Some(id) = absent_secret {
                        validate_absent_secret(&root, id)?;
                    }
                    let run_state = state.join(index.to_string());
                    fs::create_dir(&run_state)?;
                    let dns = if options.host_dns {
                        install_dns(&root, &run_state)?
                    } else {
                        None
                    };
                    let result = worker(
                        &root, &run_state, command, workdir, env, user, options, lease, &run_label,
                        &cancelled,
                    );
                    // Restore even on failed/cancelled RUN; restoration errors are fatal.
                    if let Some(dns) = dns {
                        dns.restore()?;
                    }
                    result?;
                }
            }
            // Preflight inserts an initial root WORKDIR step even for untouched scratch.
            materialized |= !matches!(step, Step::Directory { path, .. } if path == "/");
            root_budget(&root, options.limits, &cancelled)?;
        }
        if builder_identity.is_some() {
            check(&cancelled)?;
            let snapshot = work.join(format!("checkpoint-image-{}", boundary.ordinal));
            let mut checkpoint_config = config.clone();
            checkpoint_config["config"] = boundary.config.clone();
            let phase = crate::progress::Phase::start(
                options.progress,
                "  Exporting instruction checkpoint",
            );
            let exported = export_stage(
                &root,
                &snapshot,
                &checkpoint_config,
                baseline.as_ref(),
                options.limits.export,
                resources,
                None,
                &|| {
                    phase.tick();
                    cancelled()
                },
                || Ok(()),
            )?;
            phase.finish();
            // Layered engine export repairs only its own readlink observations;
            // the live root already has the archived filesystem state.
            let phase = crate::progress::Phase::start(
                options.progress,
                if baseline.is_some() {
                    "  Verifying checkpoint delta (keeping working filesystem)"
                } else {
                    "  Verifying and restoring instruction checkpoint"
                },
            );
            let verifying = || {
                phase.tick();
                cancelled()
            };
            let manifest = if baseline.is_some() {
                verify_fresh_checkpoint(
                    &snapshot,
                    &boundary.config,
                    metadata.as_ref(),
                    base_replay_usage,
                    &spool,
                    options.limits,
                    resources,
                    &verifying,
                )?
                .0
            } else {
                restore_checkpoint(
                    &snapshot,
                    &boundary.config,
                    &work,
                    &format!("rootfs-exported-{}", boundary.ordinal),
                    &spool,
                    options.limits,
                    resources,
                    &verifying,
                )?
            };
            if manifest != exported {
                return Err("checkpoint identity changed during verification".into());
            }
            phase.finish();
            check(&cancelled)?;
            if let Some(entry) = entry {
                let publication = crate::progress::Phase::start(
                    options.progress,
                    "  Publishing instruction cache",
                );
                stage_cache.as_ref().unwrap().publish(
                    &snapshot,
                    &entry,
                    &copy_targets[receipt_start..],
                    options.limits,
                    resources,
                    &|| {
                        publication.tick();
                        cancelled()
                    },
                )?;
                publication.finish();
            }
            // Even an unkeyable COPY must replace the prior filesystem identity.
            prior_identity = Some(manifest.digest.to_string());
            last_checkpoint = Some((snapshot, manifest, boundary.config.clone()));
        }
        if options.progress {
            eprintln!(
                "[weld] [stage {} instruction {}] {} DONE {:.3}s",
                index + 1,
                boundary.ordinal,
                boundary.operation,
                started.elapsed().as_secs_f64()
            );
        }
        start = boundary.end;
    }
    check(&cancelled)?;
    if !export_image {
        if options.progress {
            eprintln!("[weld]   Keeping COPY-only stage filesystem; no intermediate image export");
        }
        return Ok(StageResult {
            work,
            image: None,
            args,
            prepared: None,
        });
    }
    let mut output_reuses_checkpoint = false;
    let mut exported_receipt = None;
    let mut verified_replay_usage = None;
    let output_phase = crate::progress::Phase::start(
        options.progress,
        "  Publishing stage image (export or verified cache reuse)",
    );
    let output_cancelled = || {
        output_phase.tick();
        cancelled()
    };
    let manifest = if cache_hit {
        // Preserve the cached OCI bytes: re-exporting a replayed tree changes
        // access timestamps and would invalidate every dependent stage.
        check_layout_space(
            resources,
            cache_entry.as_ref().unwrap(),
            &output,
            None,
            options.limits,
            &cancelled,
        )?;
        crate::build_cache::publish_created(
            cache_entry.as_ref().unwrap(),
            lease,
            &output,
            None,
            &output_cancelled,
            || {
                #[cfg(target_os = "linux")]
                if let Some(r) = record.as_deref_mut() {
                    r.created(&output, lease.unwrap())?;
                }
                Ok(())
            },
        )?;
        metadata.as_ref().unwrap().selected.clone()
    } else if let Some((snapshot, manifest, checkpoint_config)) = &last_checkpoint
        && *checkpoint_config == config["config"]
    {
        check_layout_space(
            resources,
            snapshot,
            &output,
            None,
            options.limits,
            &cancelled,
        )?;
        crate::build_cache::publish_created(
            snapshot,
            lease,
            &output,
            None,
            &output_cancelled,
            || {
                #[cfg(target_os = "linux")]
                if let Some(r) = record.as_deref_mut() {
                    r.created(&output, lease.unwrap())?;
                }
                Ok(())
            },
        )?;
        output_reuses_checkpoint = true;
        manifest.clone()
    } else {
        export_stage(
            &root,
            &output,
            &config,
            baseline.as_ref(),
            options.limits.export,
            resources,
            prepare_handoff.map(|limit| (&mut exported_receipt, limit)),
            &output_cancelled,
            || {
                #[cfg(target_os = "linux")]
                if let Some(r) = record.as_deref_mut() {
                    r.created(&output, lease.unwrap())?;
                }
                Ok(())
            },
        )?
    };
    output_phase.finish();
    if !cache_hit && (cache_entry.is_some() || !final_stage) {
        // Export traverses directories: COPY --from must consume the exported
        // metadata even with caching disabled or a metadata-only stage suffix.
        let phase = crate::progress::Phase::start(
            options.progress,
            if baseline.is_some() || output_reuses_checkpoint {
                "  Verifying stage checkpoint (keeping working filesystem)"
            } else {
                "  Verifying and restoring exported stage"
            },
        );
        let verification_cancelled = || {
            phase.tick();
            cancelled()
        };
        let verified = if baseline.is_some() {
            let (verified, usage) = verify_fresh_checkpoint(
                &output,
                &config["config"],
                metadata.as_ref(),
                base_replay_usage,
                &spool,
                options.limits,
                resources,
                &verification_cancelled,
            )?;
            verified_replay_usage = Some(usage);
            verified
        } else if output_reuses_checkpoint {
            // The last instruction already restored this exact snapshot. Copying
            // its OCI blobs does not touch rootfs; verify the output without
            // writing and retaining another identical filesystem tree.
            verify_checkpoint(
                &output,
                &config["config"],
                None,
                &spool,
                options.limits,
                resources,
                &verification_cancelled,
            )?
        } else {
            restore_checkpoint(
                &output,
                &config["config"],
                &work,
                "rootfs-final-export",
                &spool,
                options.limits,
                resources,
                &verification_cancelled,
            )?
        };
        if verified != manifest {
            return Err("exported stage identity changed during verification".into());
        }
        phase.finish();
    }
    #[cfg(target_os = "linux")]
    if final_stage && let Some(r) = record {
        // A cache-publication failure must not erase evidence of a valid image.
        r.update(lease.unwrap(), |r| {
            r.phase = crate::build_record::Phase::ImageReady;
            r.manifest = Some(manifest.clone());
        })?;
    }
    if !cache_hit && let Some(entry) = cache_entry {
        stage_cache.as_ref().unwrap().publish(
            &output,
            &entry,
            &copy_targets,
            options.limits,
            resources,
            &cancelled,
        )?;
    }
    let prepared = if let Some(receipt) = exported_receipt {
        Some(PreparedStage {
            receipt,
            manifest: manifest.clone(),
            replay_usage: verified_replay_usage.ok_or("exported root verification missing")?,
        })
    } else {
        None
    };
    Ok(StageResult {
        work: work.clone(),
        image: Some(BuildResult {
            manifest,
            output,
            work,
        }),
        args,
        prepared,
    })
}

struct Dns {
    target: PathBuf,
    backup: Option<PathBuf>,
}
impl Dns {
    fn restore(self) -> Result<()> {
        // A trusted RUN may replace the final leaf. Never follow it on cleanup.
        let parent = self.target.parent().ok_or("DNS parent missing")?;
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err("RUN replaced DNS parent; partial root retained".into());
        }
        match fs::remove_file(&self.target) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        if let Some(backup) = self.backup {
            fs::rename(backup, self.target)?;
        }
        Ok(())
    }
}
fn install_dns(root: &Path, state: &Path) -> Result<Option<Dns>> {
    // /etc is a single checked component, so restoration cannot traverse an
    // unchecked ancestor created by RUN. Symlinked resolv.conf is rejected.
    let etc = root.join("etc");
    match fs::symlink_metadata(&etc) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => (),
        Ok(_) => return Err("host DNS requires a real /etc directory".into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&etc)?;
        }
        Err(e) => return Err(e.into()),
    }
    let target = etc.join("resolv.conf");
    let exists = match fs::symlink_metadata(&target) {
        Ok(m) if m.is_file() => {
            if m.len() != 0 {
                return Ok(None);
            }
            true
        }
        Ok(_) => return Err("host DNS requires a regular or missing resolv.conf".into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let mut data = Vec::new();
    fs::File::open("/etc/resolv.conf")?
        .take(65537)
        .read_to_end(&mut data)?;
    if data.len() > 65536 {
        return Err("host resolv.conf exceeds 64 KiB".into());
    }
    let backup = if exists {
        let p = state.join("resolv.conf.original");
        fs::rename(&target, &p)?;
        Some(p)
    } else {
        None
    };
    let dns = Dns { target, backup };
    if let Err(error) = fs::write(&dns.target, data) {
        dns.restore()?;
        return Err(error.into());
    }
    Ok(Some(dns))
}

#[allow(clippy::too_many_arguments)] // The lease is borrowed independently of build options.
fn worker(
    root: &Path,
    state: &Path,
    command: &str,
    wd: &str,
    env: &[String],
    user: &str,
    options: &BuildOptions,
    lease: Option<&crate::store_lease::StoreLease>,
    log_label: &str,
    c: &impl Fn() -> bool,
) -> Result<()> {
    let timeout = options.limits.run_timeout_seconds;
    #[cfg(target_os = "linux")]
    let mut cmd = crate::lease_process::command(std::env::current_exe()?, lease)?;
    #[cfg(not(target_os = "linux"))]
    let mut cmd = {
        let _ = lease;
        Command::new(std::env::current_exe()?)
    };
    cmd.env("RPWELD_BUILD_WORKER", "1").env(
        "RPWELD_TRACE_VERBOSE",
        if options.verbose { "1" } else { "0" },
    );
    cmd.arg("__trace-worker")
        .arg(root)
        .arg(state)
        .arg(timeout.to_string())
        .arg(command)
        .arg("--clear-env")
        .arg("--workdir")
        .arg(wd)
        // The worker rejects a cwd above rootfs; state is a disjoint sibling.
        .current_dir(state)
        .stdin(Stdio::null());
    if !user.is_empty() {
        cmd.arg("--user").arg(user);
    }
    for e in env {
        cmd.arg("--env").arg(e);
    }
    #[cfg(target_os = "linux")]
    let stop_output = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(target_os = "linux")]
    let sinks = if options.progress {
        use std::os::fd::AsFd;
        Some((
            crate::progress::RunOutput::new(io::stdout().as_fd(), stop_output.clone())?,
            crate::progress::RunOutput::new(io::stderr().as_fd(), stop_output.clone())?,
        ))
    } else {
        None
    };
    if options.progress {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    #[cfg(target_os = "linux")]
    let started = std::time::Instant::now();
    let child = cmd.spawn()?;
    #[cfg(target_os = "linux")]
    let mut child = child;
    #[cfg(target_os = "linux")]
    let output = if let Some((out_sink, err_sink)) = sinks {
        let stdout = child.stdout.take().ok_or("missing RUN stdout pipe")?;
        let stderr = child.stderr.take().ok_or("missing RUN stderr pipe")?;
        let out_label = format!("{log_label} stdout");
        let err_label = format!("{log_label} stderr");
        Some((
            std::thread::spawn(move || {
                crate::progress::forward_output(stdout, out_sink, &out_label)
            }),
            std::thread::spawn(move || {
                crate::progress::forward_output(stderr, err_sink, &err_label)
            }),
        ))
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    {
        use std::sync::atomic::Ordering;
        let deadline = Duration::from_secs(timeout.saturating_add(5));
        let (status, stopped) = crate::lease_process::wait(
            &mut child,
            &|| {
                let cancelled = c();
                if cancelled {
                    stop_output.store(true, Ordering::Release);
                }
                cancelled
            },
            deadline,
        )?;
        let mut output_stopped = false;
        if let Some((stdout, stderr)) = output {
            // The command can exit before its output drains. Continue observing
            // cancellation/deadline instead of joining a blocked external write.
            while !stdout.is_finished() || !stderr.is_finished() {
                if stopped || c() || started.elapsed() >= deadline {
                    stop_output.store(true, Ordering::Release);
                    output_stopped = true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let out = stdout.join().map_err(|_| "RUN stdout reader panicked");
            let err = stderr.join().map_err(|_| "RUN stderr reader panicked");
            if stopped || output_stopped {
                return Err("RUN/output cancelled/timed out; partial root retained".into());
            }
            out??;
            err??;
        }
        if stopped {
            return Err("RUN cancelled/timed out; partial root retained".into());
        }
        if !status.success() {
            return Err(format!("RUN worker failed: {status}").into());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (child, timeout, c, log_label);
        Err("RUN requires Linux".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    fn never_cancel() -> bool {
        false
    }

    fn resource_entry(path: &str, kind: layer::EntryKind, size: u64) -> layer::Entry {
        layer::Entry {
            path: path.as_bytes().to_vec(),
            kind,
            size,
            data_offset: 0,
            link_target: None,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: layer::Timestamp {
                negative: false,
                seconds: 0,
                fraction: Vec::new(),
            },
            atime: None,
            ctime: None,
            uname: Vec::new(),
            gname: Vec::new(),
            xattrs: BTreeMap::new(),
            pax_records: BTreeMap::new(),
        }
    }

    #[test]
    fn resource_root_payload_deduplication_does_not_relax_logical_limits() {
        let temp = tempfile::tempdir().unwrap();
        let mut options = options(temp.path());
        fs::write(options.context.join("file"), vec![0; 8193]).unwrap();
        for name in ["a", "b", "c"] {
            fs::hard_link(options.context.join("file"), options.context.join(name)).unwrap();
        }
        let usage = root_budget(&options.context, options.limits, &never_cancel).unwrap();
        assert_eq!(usage.bytes, 4 * 8193);
        assert_eq!(usage.unique_payload_bytes, 8193);
        assert_eq!(usage.entries, 4);
        options.limits.max_rootfs_bytes = 3 * 8193;
        assert!(
            root_budget(&options.context, options.limits, &never_cancel)
                .err()
                .unwrap()
                .to_string()
                .contains("rootfs budget")
        );
    }

    #[test]
    fn resource_replay_counts_existing_shared_parents_and_hardlinks_without_mutating_metadata() {
        use layer::EntryKind::{Directory, File, Hardlink};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("a/b")).unwrap();
        fs::set_permissions(temp.path().join("a/b"), fs::Permissions::from_mode(0o555)).unwrap();
        let before = fs::metadata(temp.path().join("a/b")).unwrap();
        let entries = [
            resource_entry("a", Directory, 0),
            resource_entry("a/b", Directory, 0),
            resource_entry("a/b/new/file", File, 4097),
            resource_entry("a/b/new/file", File, 4097),
            resource_entry("a/b/new/alias", Hardlink, 0),
            resource_entry("a/b/new/alias2", Hardlink, 0),
        ];
        assert_eq!(
            replay_allocation(temp.path(), &entries, &never_cancel).unwrap(),
            (9 * 4096, 4)
        );
        let after = fs::metadata(temp.path().join("a/b")).unwrap();
        assert_eq!(
            (
                before.atime(),
                before.atime_nsec(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.atime(),
                after.atime_nsec(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        assert!(!temp.path().join("a/b/new").exists());
    }

    #[test]
    fn resource_replay_whiteouts_replacements_and_cancellation() {
        use layer::EntryKind::{Directory, File};
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("a/b")).unwrap();
        for marker in ["a/.wh.b", "a/.wh..wh..opq", ".wh.a"] {
            let entries = [
                resource_entry("a/b/one", File, 0),
                resource_entry("a/b/two", File, 0),
                resource_entry(marker, File, 0),
                resource_entry(marker, File, 0),
            ];
            let parents = if marker == ".wh.a" { 2 } else { 1 };
            assert_eq!(
                replay_allocation(temp.path(), &entries, &never_cancel).unwrap(),
                ((2 + parents) * 4096, 3 + parents)
            );
        }
        let entries = [
            resource_entry("a/b/one", File, 0),
            resource_entry("a-keep/sub", Directory, 0),
            resource_entry("a", File, 0),
            resource_entry("a", Directory, 0),
            resource_entry("a/b/two", File, 0),
        ];
        assert_eq!(
            replay_allocation(temp.path(), &entries, &never_cancel).unwrap(),
            (7 * 4096, 8)
        );
        let calls = std::cell::Cell::new(0);
        let cancelled = || {
            calls.set(calls.get() + 1);
            calls.get() == 5
        };
        assert!(
            replay_allocation(temp.path(), &entries, &cancelled)
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    }

    #[test]
    fn resource_refusal_precedes_work_and_stops_cooperatively_with_its_reason() {
        use std::cell::Cell;
        let ran = Cell::new(false);
        let denied = super::with_resource_checks(
            || Err("export requires 8192 bytes; available 4096".into()),
            || false,
            |_| {
                ran.set(true);
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(!ran.get());
        assert!(denied.contains("available 4096"));
        let checks = Cell::new(0);
        let stopped = Cell::new(false);
        let denied = super::with_resource_checks(
            || {
                checks.set(checks.get() + 1);
                if checks.get() == 1 {
                    Ok(())
                } else {
                    Err("available disk fell below reserve".into())
                }
            },
            || false,
            |cancelled| {
                std::thread::sleep(std::time::Duration::from_millis(1050));
                assert!(cancelled());
                stopped.set(true);
                Err::<(), super::Error>("worker cancelled; descendants stopped".into())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(stopped.get());
        assert!(denied.contains("available disk fell below reserve"));
        assert!(denied.contains("descendants stopped"));
        assert!(!denied.starts_with("build cancelled"));
    }
    #[test]
    fn absent_secret_guard_never_reads_deletes_or_follows_inherited_paths() {
        use std::{fs, os::unix::fs::symlink};
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        fs::create_dir(&root).unwrap();
        super::validate_absent_secret(&root, "HF_TOKEN").unwrap();
        fs::create_dir_all(root.join("run/secrets")).unwrap();
        super::validate_absent_secret(&root, "HF_TOKEN").unwrap();
        let target = root.join("run/secrets/HF_TOKEN");
        fs::write(&target, b"inherited-canary").unwrap();
        assert!(super::validate_absent_secret(&root, "HF_TOKEN").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"inherited-canary");
        fs::remove_file(&target).unwrap();
        let outside = t.path().join("outside-canary");
        fs::write(&outside, b"outside-canary").unwrap();
        for link in [&outside, &t.path().join("missing-canary")] {
            symlink(link, &target).unwrap();
            assert!(super::validate_absent_secret(&root, "HF_TOKEN").is_err());
            assert_eq!(fs::read_link(&target).unwrap(), *link);
            fs::remove_file(&target).unwrap();
        }
        fs::remove_dir(root.join("run/secrets")).unwrap();
        symlink(t.path(), root.join("run/secrets")).unwrap();
        assert!(super::validate_absent_secret(&root, "HF_TOKEN").is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"outside-canary");
    }
    use super::*;
    #[test]
    fn automatic_platform_globals_and_from_validation() {
        let supplied = BTreeMap::new();
        let plan = resolve_plan("FROM --platform=$BUILDPLATFORM scratch AS base\nFROM --platform=${TARGETPLATFORM} base", &supplied, 4096).unwrap();
        assert_eq!(plan.stages[1].base, Base::Stage(0));
        for stage in &plan.stages {
            assert!(
                matches!(&stage.instructions[0].kind, I::From { platform: Some(p), .. } if p == "linux/amd64")
            );
        }
        let globals = global_args(&plan, &supplied, 4096).unwrap();
        assert_eq!(globals.len(), 8);
        for prefix in ["BUILD", "TARGET"] {
            assert_eq!(globals[&format!("{prefix}OS")], "linux");
            assert_eq!(globals[&format!("{prefix}ARCH")], "amd64");
            assert_eq!(globals[&format!("{prefix}VARIANT")], "");
        }
        let supplied = BTreeMap::from([("TARGETPLATFORM".into(), "linux/arm64".into())]);
        assert!(resolve_plan("FROM --platform=$TARGETPLATFORM scratch", &supplied, 4096).is_err());
        assert!(resolve_plan("FROM scratch", &supplied, 4096).is_ok());
        assert!(resolve_plan("FROM scratch", &BTreeMap::new(), 10).is_err());
        let plan =
            resolve_plan("ARG BASE=$TARGETARCH\nFROM $BASE", &BTreeMap::new(), 4096).unwrap();
        assert_eq!(plan.stages[0].base, Base::Image("amd64".into()));
        for platform in ["linux", "amd64", "x86_64", "LINUX/X86-64", "linux/amd64/v1"] {
            assert_eq!(normalize_platform(platform).unwrap(), "linux/amd64");
        }
        for platform in [
            "",
            "linux/arm64",
            "windows/amd64",
            "linux/amd64/v2",
            "linux/amd64/",
            "linux//",
            "linux/amd64/v1/extra",
            "$UNKNOWN",
        ] {
            assert!(
                resolve_plan(
                    &format!("FROM scratch AS base\nFROM --platform={platform} base"),
                    &BTreeMap::new(),
                    4096
                )
                .is_err(),
                "{platform}"
            );
        }
        let supplied = BTreeMap::from([("TARGETPLATFORM".into(), "linux/amd64 ".into())]);
        assert!(resolve_plan("FROM --platform=$TARGETPLATFORM scratch", &supplied, 4096).is_err());
        let supplied = BTreeMap::from([("TARGETARCH".into(), "override".into())]);
        let plan =
            resolve_plan("ARG TARGETARCH=default\nFROM $TARGETARCH", &supplied, 4096).unwrap();
        assert_eq!(plan.stages[0].base, Base::Image("override".into()));
    }

    #[test]
    fn automatic_args_require_stage_declaration_and_preserve_overrides() {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        let source = "ARG TARGETARCH\nFROM scratch AS base\nENV BEFORE=$TARGETARCH\nARG TARGETARCH\nARG BUILDVARIANT\nRUN echo test\nENV AFTER=$TARGETARCH\nFROM base\nENV CHILD=$TARGETARCH\nFROM scratch\nENV UNRELATED=$TARGETARCH";
        for override_value in [None, Some("custom"), Some("")] {
            o.args.clear();
            if let Some(v) = override_value {
                o.args.insert("TARGETARCH".into(), v.into());
            }
            let plan = resolve_plan(source, &o.args, 4096).unwrap();
            let (cfg, steps, args) =
                preflight_stage(&plan, 0, &o, json!({"config":{}}), BTreeMap::new()).unwrap();
            let expected = override_value.unwrap_or("amd64");
            assert_eq!(
                cfg["config"]["Env"],
                json!([format!("AFTER={expected}"), "BEFORE="])
            );
            assert!(steps.iter().any(|s| matches!(s, Step::Run { env, .. } if env.contains(&format!("TARGETARCH={expected}")) && env.contains(&"BUILDVARIANT=".into()) && !env.iter().any(|v| v.starts_with("BUILDOS=")))));
            let (child, _, _) = preflight_stage(&plan, 1, &o, cfg, args).unwrap();
            assert!(
                child["config"]["Env"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(format!("CHILD={expected}")))
            );
            let (other, _, _) =
                preflight_stage(&plan, 2, &o, json!({"config":{}}), BTreeMap::new()).unwrap();
            assert_eq!(other["config"]["Env"], json!(["UNRELATED="]));
        }
        o.args.clear();
        let (cfg, _) = preflight("ARG TARGETARCH=global\nFROM scratch\nARG TARGETARCH=stage\nENV VALUE=$TARGETARCH\nENV TARGETARCH=env\nRUN echo test", &o, json!({"config":{}})).unwrap();
        assert_eq!(
            cfg["config"]["Env"],
            json!(["TARGETARCH=env", "VALUE=stage"])
        );
        o.args.insert("TARGETARCH".into(), "cli".into());
        let (cfg, steps) = preflight("ARG TARGETARCH=global\nFROM scratch\nARG TARGETARCH=stage\nENV VALUE=$TARGETARCH\nENV TARGETARCH=env\nRUN echo test", &o, json!({"config":{}})).unwrap();
        assert_eq!(cfg["config"]["Env"], json!(["TARGETARCH=env", "VALUE=cli"]));
        assert!(steps.iter().any(|s| matches!(s, Step::Run { env, .. } if env.contains(&"TARGETARCH=env".into()) && !env.contains(&"TARGETARCH=cli".into()))));
    }
    fn preflight(
        source: &str,
        options: &BuildOptions,
        config: Value,
    ) -> Result<(Value, Vec<Step>)> {
        let plan = build_plan::parse(source)?;
        let (config, steps, _) = preflight_stage(&plan, 0, options, config, BTreeMap::new())?;
        Ok((config, steps))
    }
    fn options(temp: &Path) -> BuildOptions {
        let context = temp.join("context");
        fs::create_dir(&context).unwrap();
        BuildOptions {
            dockerfile: None,
            work: temp.join("work"),
            output: temp.join("output"),
            context,
            bases: BTreeMap::new(),
            args: BTreeMap::new(),
            host_dns: false,
            verbose: false,
            progress: true,
            export_mode: ExportMode::Flattened,
            managed_cache: None,
            target: None,
            cache: None,
            no_cache: false,
            limits: Limits {
                image: image::Limits {
                    max_metadata_bytes: 1024 * 1024,
                    max_total_metadata_bytes: 4 * 1024 * 1024,
                    max_descriptors: 100,
                    max_layer_bytes: 64 * 1024 * 1024,
                    max_total_layer_bytes: 128 * 1024 * 1024,
                },
                layer: layer::Limits {
                    max_blob_bytes: 64 * 1024 * 1024,
                    max_uncompressed_bytes: 128 * 1024 * 1024,
                    max_entries: 100_000,
                    max_metadata_bytes: 32 * 1024 * 1024,
                    max_gzip_header_bytes: 65536,
                },
                export: export::Limits {
                    max_layer_bytes: 128 * 1024 * 1024,
                    max_entries: 100_000,
                    max_metadata_bytes: 32 * 1024 * 1024,
                },
                max_replay_bytes: 128 * 1024 * 1024,
                max_replay_entries: 100_000,
                max_rootfs_bytes: 128 * 1024 * 1024,
                max_rootfs_entries: 100_000,
                max_plan_bytes: 1024 * 1024,
                run_timeout_seconds: 30,
            },
        }
    }
    #[test]
    fn heredoc_run_keeps_shell_user_environment_and_body() {
        let t = tempfile::tempdir().unwrap();
        let o = options(t.path());
        let (_, steps) = preflight("FROM scratch\nARG X=value\nSHELL [\"/bin/bash\",\"-eu\",\"-c\"]\nUSER 1234:2345\nRUN <<'EOF'\nprintf '%s' \"$X\"\nEOF\nUSER root\nRUN <<EOF\necho done\nEOF\n", &o, json!({"config":{}})).unwrap();
        let runs: Vec<_> = steps
            .iter()
            .filter_map(|s| {
                if let Step::Run {
                    command, user, env, ..
                } = s
                {
                    Some((command, user, env))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(runs[0].1, "1234:2345");
        assert!(runs[0].0.starts_with("exec '/bin/bash' '-eu' '-c'"));
        assert!(runs[0].0.contains("$X"));
        assert!(runs[0].2.contains(&"X=value".into()));
        assert_eq!(runs[1].1, "root");
    }

    #[test]
    fn heredoc_expansion_limits_and_materialization_cancellation() {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        let source = "FROM scratch\nARG X=123456789\nCOPY <<EOF /out\n$X\nEOF\n";
        o.limits.max_rootfs_bytes = 9;
        assert!(preflight(source, &o, json!({"config":{}})).is_err());
        o.limits.max_rootfs_bytes = 1024;
        o.limits.max_plan_bytes = 5;
        assert!(preflight(source, &o, json!({"config":{}})).is_err());
        o.limits.max_plan_bytes = 1024;
        let (_, steps) = preflight(source, &o, json!({"config":{}})).unwrap();
        fs::create_dir(&o.work).unwrap();
        assert!(prepare_inline_sources(&steps, &o.work, &|| true).is_err());
        assert_eq!(fs::read_dir(&o.work).unwrap().count(), 0);
        assert!(
            preflight(
                "FROM scratch\nCOPY <<EOF /x\n${X:-default}\nEOF\n",
                &o,
                json!({"config":{}})
            )
            .unwrap_err()
            .to_string()
            .contains("unsupported expansion")
        );
    }
    #[test]
    fn run_worker_argument_budget_checks_encoded_boundary_before_mutation() {
        let t = tempfile::tempdir().unwrap();
        let o = options(t.path());
        let overhead = exec_command(&shell_argv(&["/bin/sh".into(), "-c".into()], "")).len();
        for (extra, accepted) in [(0, true), (1, false)] {
            let body = format!(
                "{}\n",
                "x".repeat(build_plan::MAX_LINE_BYTES - overhead - 1 + extra)
            );
            let source = format!("FROM scratch\nRUN <<EOF\n{body}EOF\n");
            let result = preflight(&source, &o, json!({"config":{}}));
            assert_eq!(result.is_ok(), accepted);
            if let Ok((_, steps)) = result {
                assert!(steps.iter().any(|s| matches!(s, Step::Run { command, .. } if command.len() == build_plan::MAX_LINE_BYTES)));
            }
        }
        // Each literal quote costs multiple bytes in the worker argv encoding.
        let quoted = "'".repeat(20_000);
        let source = format!("FROM scratch\nRUN <<EOF\n{quoted}\nEOF\n");
        let never_cancel: fn() -> bool = || false;
        assert!(
            build(&source, &o, never_cancel)
                .unwrap_err()
                .to_string()
                .contains("64 KiB")
        );
        assert!(!o.work.exists());
        assert!(!o.output.exists());
        let json_run = serde_json::to_string(&vec!["echo", &quoted]).unwrap();
        assert!(
            preflight(
                &format!("FROM scratch\nRUN {json_run}\n"),
                &o,
                json!({"config":{}})
            )
            .unwrap_err()
            .to_string()
            .contains("64 KiB")
        );
    }
    #[test]
    fn runtime_metadata_inheritance_validation_and_budget() {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        let inherited = json!({"config": {
            "StopSignal":"SIGTERM", "User":"missing",
            "Healthcheck":{"Test":["CMD-SHELL","missing"],"Interval":1234567,"Extension":"preserved"}
        }});
        let (cfg, steps) = preflight("FROM scratch", &o, inherited.clone()).unwrap();
        assert_eq!(
            cfg["config"]["Healthcheck"],
            inherited["config"]["Healthcheck"]
        );
        assert_eq!(cfg["config"]["StopSignal"], "SIGTERM");
        assert_eq!(steps.len(), 1); // Only the inherited working directory, no healthcheck work.
        for cfg in [
            json!({"StopSignal":12}),
            json!({"StopSignal":"BOGUS"}),
            json!({"Healthcheck":[]}),
            json!({"Healthcheck":{"Test":[42]}}),
            json!({"Healthcheck":{"Test":["UNKNOWN"]}}),
            json!({"Healthcheck":{"Timeout":-1}}),
            json!({"Healthcheck":{"Interval":9223372036854775808u64}}),
            json!({"Healthcheck":{"Retries":2147483648i64}}),
        ] {
            assert!(preflight("FROM scratch", &o, json!({"config":cfg})).is_err());
        }
        o.limits.max_plan_bytes = 128;
        assert!(
            preflight(
                &format!("FROM scratch\nHEALTHCHECK CMD {}", "x".repeat(200)),
                &o,
                json!({"config":{}})
            )
            .is_err()
        );
    }

    #[test]
    fn shell_run_uses_selected_argv_and_exec_form_stays_literal() {
        let t = tempfile::tempdir().unwrap();
        let o = options(t.path());
        let (_, steps) = preflight(
            "FROM scratch\nRUN echo 'one' $V\nSHELL [\"/new shell\",\"--flag\",\"-c\"]\nRUN echo 'two' $V\nRUN [\"echo\",\"$V\"]",
            &o,
            json!({"config":{"Shell":["/base shell", "-c"]}}),
        ).unwrap();
        let commands: Vec<_> = steps
            .iter()
            .filter_map(|step| match step {
                Step::Run { command, .. } => Some(command.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            commands,
            vec![
                "exec '/base shell' '-c' 'echo '\\''one'\\'' $V'",
                "exec '/new shell' '--flag' '-c' 'echo '\\''two'\\'' $V'",
                "exec 'echo' '$V'",
            ]
        );
        assert!(preflight("FROM scratch", &o, json!({"config":{"Shell":[""]}})).is_err());
        assert!(preflight("FROM scratch", &o, json!({"config":{"Labels":{"bad":42}}})).is_err());
    }
    #[test]
    fn scratch_export_and_arg_scope() {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        o.args.insert("VERSION".into(), "override".into());
        let source = "ARG VERSION=global\nFROM scratch\nARG VERSION\nENV A=$VERSION B=old\nENV B=new C=$B\nWORKDIR /app/$A\nCMD [\"hello\"]\nENTRYPOINT [\"/entry\"]\nEXPOSE 80 53/udp\n";
        let result = build(source, &o, || false).unwrap();
        let m = image::load_layout(&result.output, None, o.limits.image, || false).unwrap();
        assert_eq!(m.selected, result.manifest);
        assert_eq!(m.config["config"]["WorkingDir"], "/app/override");
        assert_eq!(
            m.config["config"]["Env"],
            json!(["A=override", "B=new", "C=old"])
        );
        assert_eq!(m.config["config"]["Cmd"], json!(["hello"]));
        assert_eq!(
            m.config["config"]["ExposedPorts"],
            json!({"80/tcp":{}, "53/udp":{}})
        );
        assert!(o.work.join("rootfs/app/override").is_dir());
        assert!(!o.work.join("rootfs/dev").exists());
    }
    #[test]
    fn preflight_and_cancellation_do_not_mutate() {
        let t = tempfile::tempdir().unwrap();
        let o = options(t.path());
        for source in [
            "FROM scratch\nWORKDIR /made\nCOPY --badflag a b\n",
            "FROM scratch\nWORKDIR /made\nENV A=${UNSET:-bad}\n",
            "FROM scratch\nWORKDIR /made\nWORKDIR ../bad\n",
        ] {
            assert!(build(source, &o, || false).is_err());
            assert!(!o.work.exists());
            assert!(!o.output.exists());
        }
        assert!(build("FROM scratch", &o, || true).is_err());
        assert!(!o.work.exists());
    }
    #[test]
    fn copy_entry_and_metadata_budgets_are_cumulative() {
        for budget in ["entries", "metadata"] {
            let t = tempfile::tempdir().unwrap();
            let mut o = options(t.path());
            fs::write(o.context.join("a"), "data").unwrap();
            if budget == "entries" {
                o.limits.layer.max_entries = 1;
            } else {
                // One entry fits (512 + source + destination), two do not.
                o.limits.layer.max_metadata_bytes = 600;
            }
            let error = build("FROM scratch\nCOPY a /a\nCOPY a /a\n", &o, || false)
                .unwrap_err()
                .to_string();
            assert!(error.contains("Limit"), "{error}");
            assert_eq!(fs::read(o.work.join("rootfs/a")).unwrap(), b"data");
            assert!(!o.output.exists());
        }
    }

    #[test]
    fn cached_many_empty_copies_fit_small_metadata_budget() {
        for (budget, count) in [(1024, 3000), (1536, 4095)] {
            let t = tempfile::tempdir().unwrap();
            let mut o = options(t.path());
            o.limits.layer.max_metadata_bytes = budget;
            o.cache = Some(t.path().join("cache"));
            fs::create_dir(o.cache.as_ref().unwrap()).unwrap();
            let source = format!("FROM scratch\n{}", "COPY missing* /out/\n".repeat(count));
            if budget == 1024 {
                // Checkpoints must verify replay before publication, including cold builds.
                assert_eq!(
                    build(&source, &o, || false).unwrap_err().to_string(),
                    "layer limit exceeded: metadata bytes"
                );
                assert!(!o.output.exists());
                assert_eq!(fs::read_dir(o.cache.as_ref().unwrap()).unwrap().count(), 0);
                continue;
            }
            let first = build(&source, &o, || false).unwrap();
            assert!(!o.work.join("rootfs/out").exists());
            let entry = fs::read_dir(o.cache.as_ref().unwrap())
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| crate::build_cache::copy_targets(p, None, budget, count).is_ok())
                .unwrap();
            let receipt_size = fs::metadata(entry.join("weld-copy-targets.json"))
                .unwrap()
                .len();
            assert_eq!(receipt_size, 3 * count as u64 + 1);
            assert!(receipt_size > 6 * budget); // Both cases fail the old receipt cap.
            let receipt = crate::build_cache::copy_targets(&entry, None, budget, count).unwrap();
            assert_eq!(receipt.len(), count);
            assert!(receipt.iter().all(Vec::is_empty));
            o.work = t.path().join("work-warm");
            o.output = t.path().join("output-warm");
            let warm = build(&source, &o, || false);
            assert_eq!(first.manifest, warm.unwrap().manifest);
            assert!(!o.work.join("rootfs/out").exists());
            assert!(fs::read_dir(o.cache.as_ref().unwrap()).unwrap().count() > 1);
        }
    }

    #[test]
    fn cached_wildcards_keep_empty_and_repeated_targets_and_invalidate() {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        let source =
            "FROM scratch\nCOPY missing* /absent/\nCOPY ignored* /ignored/\nCOPY ?.txt /file\n";
        fs::write(o.context.join(".dockerignore"), "ignored*\n").unwrap();
        fs::write(o.context.join("ignored.txt"), "ignored").unwrap();
        // Reverse creation order must not change the sorted wildcard overwrite order.
        fs::write(o.context.join("b.txt"), "B").unwrap();
        fs::write(o.context.join("a.txt"), "A").unwrap();
        let future = std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        for entry in fs::read_dir(&o.context).unwrap() {
            fs::File::open(entry.unwrap().path())
                .unwrap()
                .set_times(
                    fs::FileTimes::new()
                        .set_accessed(future)
                        .set_modified(future),
                )
                .unwrap();
        }
        fs::File::open(&o.context)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_accessed(future)
                    .set_modified(future),
            )
            .unwrap();
        o.cache = Some(t.path().join("cache"));
        fs::create_dir(o.cache.as_ref().unwrap()).unwrap();
        let first = build(source, &o, || false).unwrap();
        assert_eq!(fs::read(o.work.join("rootfs/file")).unwrap(), b"B");
        assert!(!o.work.join("rootfs/absent").exists());
        assert!(!o.work.join("rootfs/ignored").exists());
        let entry = fs::read_dir(o.cache.as_ref().unwrap())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                crate::build_cache::copy_targets(p, None, o.limits.layer.max_metadata_bytes, 3)
                    .is_ok()
            })
            .unwrap();
        let targets =
            crate::build_cache::copy_targets(&entry, None, o.limits.layer.max_metadata_bytes, 3)
                .unwrap();
        assert_eq!(targets, vec![vec![], vec![], vec![b"file".to_vec(); 2]]);
        o.work = t.path().join("work-hit");
        o.output = t.path().join("output-hit");
        assert_eq!(
            first.manifest,
            build(source, &o, || false).unwrap().manifest
        );
        assert_eq!(fs::read(o.work.join("rootfs/file")).unwrap(), b"B");
        // A formerly empty selection must not reuse its completed stage.
        fs::write(o.context.join("missing-now"), "new").unwrap();
        o.work = t.path().join("work-new-match");
        o.output = t.path().join("output-new-match");
        assert_ne!(
            first.manifest,
            build(source, &o, || false).unwrap().manifest
        );
        assert_eq!(
            fs::read(o.work.join("rootfs/absent/missing-now")).unwrap(),
            b"new"
        );
        assert!(fs::read_dir(o.cache.as_ref().unwrap()).unwrap().count() > 2);
    }

    #[test]
    fn cached_copy_rechecks_ignored_traversal_budgets() {
        for budget in ["entries", "metadata"] {
            let t = tempfile::tempdir().unwrap();
            let mut o = options(t.path());
            let source = "FROM scratch\nCOPY . /a/\nCOPY . /b/\n";
            fs::write(o.context.join("Dockerfile"), source).unwrap();
            fs::write(
                o.context.join(".dockerignore"),
                "Dockerfile\n.dockerignore\nignored\n!never\n",
            )
            .unwrap();
            fs::write(o.context.join("keep"), "keep").unwrap();
            fs::create_dir(o.context.join("ignored")).unwrap();
            // Relatime may update atime when it equals mtime, even in the future.
            let future = std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
            for name in ["", "Dockerfile", ".dockerignore", "keep"] {
                fs::File::open(o.context.join(name))
                    .unwrap()
                    .set_times(
                        fs::FileTimes::new()
                            .set_accessed(future + Duration::from_secs(1))
                            .set_modified(future),
                    )
                    .unwrap();
            }
            o.cache = Some(t.path().join("cache"));
            fs::create_dir(o.cache.as_ref().unwrap()).unwrap();
            if budget == "entries" {
                o.limits.layer.max_entries = 20;
            } else {
                o.limits.layer.max_metadata_bytes = 10_000;
            }
            let first = build(source, &o, || false).unwrap();
            o.work = t.path().join("work-hit");
            o.output = t.path().join("output-hit");
            assert_eq!(
                first.manifest,
                build(source, &o, || false).unwrap().manifest
            );
            let policy = context::load_policy(&o.context, None, &|| false).unwrap();
            let key =
                crate::build_cache::key(b"test", Some(&o.context), o.limits, &policy, &|| false)
                    .unwrap();
            for n in 0..6 {
                fs::write(o.context.join(format!("ignored/{n}")), "ignored").unwrap();
            }
            assert_eq!(
                key,
                crate::build_cache::key(b"test", Some(&o.context), o.limits, &policy, &|| false)
                    .unwrap()
            );
            for no_cache in [false, true] {
                o.no_cache = no_cache;
                o.work = t.path().join(format!("work-{no_cache}"));
                o.output = t.path().join(format!("output-{no_cache}"));
                let error = build(source, &o, || false).unwrap_err().to_string();
                assert!(error.contains(&format!("Limit(\"{budget}\")")), "{error}");
                if !no_cache {
                    assert!(!o.work.exists(), "cache validation must precede replay");
                }
            }
            for n in 0..2 {
                fs::remove_file(o.context.join(format!("ignored/{n}"))).unwrap();
            }
            o.no_cache = false;
            o.work = t.path().join("work-within-budget");
            o.output = t.path().join("output-within-budget");
            assert_eq!(
                first.manifest,
                build(source, &o, || false).unwrap().manifest
            );
            assert!(!o.output.join("weld-copy-targets.json").exists());
        }
    }

    #[test]
    fn later_copy_filesystem_failure_can_follow_earlier_mutation() {
        let t = tempfile::tempdir().unwrap();
        let o = options(t.path());
        fs::write(o.context.join("a"), "data").unwrap();
        fs::create_dir(o.context.join("dir")).unwrap();
        assert!(build("FROM scratch\nCOPY a /a\nCOPY dir /a\n", &o, || false).is_err());
        assert_eq!(fs::read(o.work.join("rootfs/a")).unwrap(), b"data");
        assert!(!o.output.exists());
    }
    #[test]
    fn inherited_semantics_and_literal_expansion() {
        let t = tempfile::tempdir().unwrap();
        let o = options(t.path());
        for config in [
            json!({"User":42}),
            json!({"OnBuild":["RUN true"]}),
            json!({"Shell":[42]}),
            json!({"Cmd":[1]}),
            json!({"WorkingDir":"relative"}),
            json!({"Env":["bad"]}),
        ] {
            assert!(preflight("FROM scratch", &o, json!({"config":config})).is_err());
        }
        let (cfg, steps) = preflight("ARG GLOBAL=hidden\nFROM scratch\nARG LOCAL=value\nENV Q='$LOCAL' R=\"$LOCAL\"\nWORKDIR $HOME\nRUN [\"echo\",\"$LOCAL\",\"it's\"]\nENTRYPOINT [\"/new\"]", &o, json!({"config":{"Env":["HOME=/home"],"Cmd":["old"]}})).unwrap();
        assert_eq!(cfg["config"]["Cmd"], Value::Null);
        assert_eq!(
            cfg["config"]["Env"],
            json!(["HOME=/home", "Q=$LOCAL", "R=value"])
        );
        match steps.last().unwrap() {
            Step::Run {
                command,
                env,
                workdir,
                ..
            } => {
                assert_eq!(command, "exec 'echo' '$LOCAL' 'it'\\''s'");
                assert_eq!(workdir, "/home");
                assert!(env.contains(&"LOCAL=value".into()));
                assert!(!env.iter().any(|s| s.starts_with("GLOBAL=")));
            }
            _ => panic!("expected RUN"),
        }
    }
    #[test]
    fn workdir_never_follows_host_symlinks() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let outside = t.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join("link")).unwrap();
        assert!(directory(&root, "/link/escaped", Some("0:0")).is_err());
        assert!(!outside.join("escaped").exists());
    }
    #[test]
    fn user_snapshots_follow_instruction_order_without_account_lookup() {
        let t = tempfile::tempdir().unwrap();
        let o = options(t.path());
        let (cfg, steps) = preflight(
            "FROM scratch\nARG WHO=first\nUSER $WHO\nWORKDIR /one\nRUN first\nENV WHO=second\nUSER ${WHO}:123\nSHELL [\"/custom\",\"-c\"]\nRUN second\nUSER absent-final\n",
            &o,
            json!({"config":{"User":"inherited","WorkingDir":"/inherited"}}),
        ).unwrap();
        assert_eq!(cfg["config"]["User"], "absent-final");
        assert!(matches!(&steps[0], Step::Directory { path, user: None } if path == "/inherited"));
        assert!(
            matches!(&steps[1], Step::Directory { path, user: Some(user) } if path == "/one" && user == "first")
        );
        let runs: Vec<_> = steps
            .iter()
            .filter_map(|step| match step {
                Step::Run {
                    user,
                    workdir,
                    env,
                    command,
                    ..
                } => Some((user.as_str(), workdir.as_str(), env, command.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(runs[0].0, "first");
        assert_eq!(runs[1].0, "second:123");
        assert_eq!(runs[0].1, "/one");
        assert!(runs[0].2.contains(&"WHO=first".into()));
        assert!(runs[1].2.contains(&"WHO=second".into()));
        assert_eq!(runs[0].3, "exec '/bin/sh' '-c' 'first'");
        assert_eq!(runs[1].3, "exec '/custom' '-c' 'second'");
    }
    #[test]
    fn temporary_dns_restores_empty_file_and_rejects_links() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let state = t.path().join("state");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&state).unwrap();
        fs::create_dir(root.join("etc")).unwrap();
        let resolv = root.join("etc/resolv.conf");
        fs::write(&resolv, "").unwrap();
        fs::set_permissions(&resolv, fs::Permissions::from_mode(0o640)).unwrap();
        install_dns(&root, &state)
            .unwrap()
            .unwrap()
            .restore()
            .unwrap();
        assert_eq!(fs::read(&resolv).unwrap(), b"");
        assert_eq!(
            fs::metadata(&resolv).unwrap().permissions().mode() & 0o777,
            0o640
        );
        fs::remove_file(&resolv).unwrap();
        symlink("/etc/resolv.conf", &resolv).unwrap();
        assert!(install_dns(&root, &state).is_err());
    }
    #[test]
    #[ignore = "requires the existing root-owned Alpine corpus; run explicitly in WSL"]
    fn alpine_replay_and_export() {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        o.bases.insert(
            "alpine".into(),
            LocalBase {
                layout: "/var/tmp/rpweld-replay.krmojg/layout".into(),
                reference: None,
            },
        );
        let result = build(
            "FROM alpine\nENV BUILT=yes\nWORKDIR /app\nCMD [\"/bin/sh\"]",
            &o,
            || false,
        )
        .unwrap();
        assert!(o.work.join("rootfs/bin/busybox").is_file());
        let m = image::load_layout(&result.output, None, o.limits.image, || false).unwrap();
        assert!(
            array(&m.config["config"], "Env")
                .unwrap()
                .contains(&"BUILT=yes".into())
        );
    }
}
