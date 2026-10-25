//! Minimal, trusted/stable Linux amd64 builds from local OCI bindings or scratch.
//! Supports dependency-selected stages: FROM, RUN, local/stage COPY, ARG, ENV, WORKDIR, JSON
//! CMD/ENTRYPOINT, EXPOSE.
//! Local/stage COPY is supported; other COPY flags, custom shells, USER/OnBuild and complex
//! expansion fail closed. RUN exec
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
    build_plan::{self, Base, InstructionKind as I, Protocol, Run},
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

/// Exact literal FROM name -> local OCI layout and optional ref annotation.
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
    pub target: Option<String>,
    pub cache: Option<PathBuf>,
    pub no_cache: bool,
}

/// Successful flattened OCI publication and retained engine work directory.
#[derive(Debug)]
pub struct BuildResult {
    pub manifest: Descriptor,
    pub output: PathBuf,
    pub work: PathBuf,
}

enum Step {
    Directory(String),
    Copy {
        from: Option<usize>,
        sources: Vec<String>,
        destination: String,
    },
    Run {
        command: String,
        workdir: String,
        env: Vec<String>,
    },
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
    let mut chars = raw.chars().peekable();
    let mut out = String::new();
    let mut quote = None;
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' if quote.is_none() => quote = Some(c),
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
                    return Err("only $NAME and ${NAME} expansion supported".into());
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
        || value.bytes().any(|b| b"\0*?[$\\".contains(&b))
        || value.split('/').any(|p| p == "..")
        || value.split('/').count() > 128
    {
        return Err("COPY requires literal context-relative sources and bounded image destinations; no glob, parent, or unresolved variable syntax".into());
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

fn preflight_stage(
    plan: &build_plan::BuildPlan,
    index: usize,
    options: &BuildOptions,
    mut config: Value,
    inherited_args: BTreeMap<String, String>,
) -> Result<(Value, Vec<Step>, BTreeMap<String, String>)> {
    let cap = options.limits.max_plan_bytes;
    if config.get("config").is_none_or(Value::is_null) {
        config["config"] = json!({});
    }
    let cfg = &mut config["config"];
    if !cfg.is_object() {
        return Err("invalid base config object".into());
    }
    match cfg.get("User") {
        None | Some(Value::Null) => (),
        Some(Value::String(s)) if s.is_empty() => (),
        _ => return Err("base User unsupported".into()),
    }
    if !array(cfg, "OnBuild")?.is_empty() {
        return Err("base OnBuild unsupported".into());
    }
    let shell = array(cfg, "Shell")?;
    if !shell.is_empty() && shell != ["/bin/sh", "-c"] {
        return Err("custom base Shell unsupported".into());
    }
    array(cfg, "Cmd")?;
    array(cfg, "Entrypoint")?;
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
    let mut globals = BTreeMap::new();
    for i in &plan.global_args {
        if let I::Arg { name, default } = &i.kind {
            let default = default
                .as_deref()
                .map(|s| expand(s, &globals, cap))
                .transpose()?;
            if let Some(v) = options.args.get(name).cloned().or(default) {
                globals.insert(name.clone(), v);
                map_bytes(&globals, cap)?;
            }
        }
    }
    let mut args = inherited_args;
    let mut steps = vec![Step::Directory(wd.clone())];
    let mut charge = supplied_bytes + wd.len() + map_bytes(&globals, cap)?;
    let mut cmd_set = false;
    for i in &plan.stages[index].instructions {
        let mut vars = args.clone();
        vars.extend(env.clone()); // ENV shadows ARG, including empty values.
        match &i.kind {
            I::From { .. } => (),
            I::Copy { from, paths } => {
                let mut values = copy_words(paths, &vars, cap)?;
                let dest = values.pop().ok_or("COPY destination missing")?;
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
                charge = charge
                    .checked_add(destination.len())
                    .and_then(|n| values.iter().try_fold(n, |n, s| n.checked_add(s.len())))
                    .ok_or("plan budget overflow")?;
                steps.push(Step::Copy {
                    from: *from,
                    sources: values,
                    destination,
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
                    .or_else(|| args.get(name).cloned())
                    .or_else(|| globals.get(name).cloned());
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
            I::Workdir(word) => {
                wd = path(&wd, &expand(&word.raw, &vars, cap)?)?;
                steps.push(Step::Directory(wd.clone()));
            }
            I::Cmd(argv) => {
                cfg["Cmd"] = json!(argv);
                cmd_set = true;
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
                    Run::Shell(s) => s.clone(),
                    Run::Exec(argv) => format!(
                        "exec {}",
                        argv.iter()
                            .map(|s| format!("'{}'", s.replace('\'', "'\\''")))
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                };
                let entries: Vec<_> = vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
                charge = charge
                    .checked_add(
                        command.len() + wd.len() + entries.iter().map(String::len).sum::<usize>(),
                    )
                    .ok_or("plan budget overflow")?;
                steps.push(Step::Run {
                    command,
                    workdir: wd.clone(),
                    env: entries,
                });
            }
        }
        charge = charge
            .checked_add(
                wd.len()
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
fn directory(root: &Path, image_path: &str) -> Result<PathBuf> {
    let mut target = root.to_path_buf();
    for part in image_path.split('/').filter(|p| !p.is_empty()) {
        if matches!(part, "." | "..") {
            return Err("invalid directory component".into());
        }
        target.push(part);
        match fs::symlink_metadata(&target) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => (),
            Ok(_) => return Err("WORKDIR/DNS path traverses symlink or nondirectory".into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(&target)?,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(target)
}

fn root_budget(root: &Path, limits: Limits, c: &impl Fn() -> bool) -> Result<()> {
    fn walk(
        p: &Path,
        bytes: &mut u64,
        entries: &mut usize,
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
                *entries = entries.checked_add(1).ok_or("rootfs entry overflow")?;
                *bytes = bytes.checked_add(m.len()).ok_or("rootfs byte overflow")?;
                if *entries > l.max_rootfs_entries || *bytes > l.max_rootfs_bytes {
                    return Err("rootfs budget exceeded".into());
                }
                if m.is_dir() {
                    walk(&p, bytes, entries, depth + 1, l, c)?;
                }
            }
            Ok(())
        })();
        directory.set_times(fs::FileTimes::new().set_accessed(accessed))?;
        result
    }
    walk(root, &mut 0, &mut 0, 0, limits, c)
}

/// Parse/static-preflight completely before creating directories. Spawns the
/// current executable's `__trace-worker` and `__lease-guard` dispatches.
/// Embedders must implement both, before threads and signal handlers.
/// Cancellation is cooperative for I/O; RUN cancellation signals its dedicated
/// worker through the lease guard, waiting for descendant-safe cleanup.
struct StageResult {
    result: BuildResult,
    args: BTreeMap<String, String>,
}

/// Select the target and only its transitive FROM/COPY dependencies.
pub fn selected_stages(plan: &build_plan::BuildPlan, target: Option<&str>) -> Result<Vec<usize>> {
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
                from: Some(from), ..
            } = i.kind
            {
                pending.push(from);
            }
        }
    }
    Ok(selected.into_iter().collect())
}

/// Compatibility entry point for truly unmanaged paths only.
pub fn build(
    source: &str,
    options: &BuildOptions,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    build_inner(source, options, None, cancelled)
}

/// Caller keeps this lease through use of returned managed paths, tagging and push.
pub fn build_with_lease(
    source: &str,
    options: &BuildOptions,
    lease: &crate::store_lease::StoreLease,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    build_inner(source, options, Some(lease), cancelled)
}

fn build_inner(
    source: &str,
    options: &BuildOptions,
    lease: Option<&crate::store_lease::StoreLease>,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err("build requires Linux amd64".into());
    }
    check(&cancelled)?;
    for path in [&options.work, &options.output, &options.context]
        .into_iter()
        .chain(options.bases.values().map(|b| &b.layout))
        .chain(options.cache.iter())
        .chain(options.dockerfile.iter())
    {
        crate::store_access::validate_path(path, lease)?;
    }
    let plan = build_plan::parse(source)?;
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
    if let Some(cache) = &options.cache {
        let cache = fs::canonicalize(cache)?;
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
    let intermediate = if selected.len() > 1 {
        Some(
            tempfile::Builder::new()
                .prefix(".weld-stages-")
                .tempdir_in(work.parent().unwrap())?
                .keep(),
        )
    } else {
        None
    };
    let mut previous = BTreeMap::new();
    let mut notice = false;
    for n in selected {
        let mut stage_options = options.clone();
        if n != target {
            let parent = intermediate.as_ref().unwrap();
            stage_options.work = parent.join(format!("stage-{n}-work"));
            stage_options.output = parent.join(format!("stage-{n}-image"));
        }
        eprintln!(
            "Stage {}: {}",
            n + 1,
            plan.stages[n].name.as_deref().unwrap_or("unnamed")
        );
        let result = build_stage(
            &plan,
            n,
            &stage_options,
            &previous,
            &mut notice,
            &policy,
            lease,
            &cancelled,
        )?;
        previous.insert(n, result);
    }
    Ok(previous.remove(&target).unwrap().result)
}

#[allow(clippy::too_many_arguments)] // Keep the operation lease explicit at each call boundary.
fn build_stage(
    plan: &build_plan::BuildPlan,
    index: usize,
    options: &BuildOptions,
    previous: &BTreeMap<usize, StageResult>,
    notice: &mut bool,
    policy: &crate::dockerignore::Policy,
    lease: Option<&crate::store_lease::StoreLease>,
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
            I::Workdir(w) => {
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
            layout: previous[&n].result.output.clone(),
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
    let (config, mut steps, args) =
        preflight_stage(plan, index, options, config, inherited.clone())?;
    check_copy_sources(&steps, options, policy, &cancelled)?;
    let cache_entry = if let Some(cache) = options.cache.as_ref().filter(|_| !options.no_cache) {
        let dependencies: Vec<_> = plan.stages[index]
            .instructions
            .iter()
            .filter_map(|i| match i.kind {
                I::Copy { from: Some(n), .. } => {
                    Some(previous[&n].result.manifest.digest.to_string())
                }
                _ => None,
            })
            .collect();
        let input = format!(
            "{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{}\n{:?}",
            plan.global_args,
            plan.stages[index],
            options.args,
            options.limits,
            // Later ARG instructions can overwrite values consumed by earlier steps.
            inherited,
            metadata.as_ref().map(|m| &m.selected.digest),
            options.host_dns,
            dependencies
        );
        let uses_context = steps
            .iter()
            .any(|s| matches!(s, Step::Copy { from: None, .. }));
        Some(cache.join(crate::build_cache::key(
            input.as_bytes(),
            uses_context.then_some(options.context.as_path()),
            options.limits,
            policy,
            &cancelled,
        )?))
    } else {
        None
    };
    let mut cache_hit = false;
    if let Some(entry) = &cache_entry
        && crate::build_cache::lookup(entry, lease)?
    {
        let targets = crate::build_cache::copy_targets(
            entry,
            lease,
            options.limits.layer.max_metadata_bytes,
        )?;
        let mut targets = targets.iter();
        let mut copied = context::Summary::default();
        for step in &steps {
            if let Step::Copy { from, sources, .. } = step {
                let stage_root = from.map(|n| previous[&n].result.work.join("rootfs"));
                let summary = context::validate_copy_budget(
                    stage_root.as_deref().unwrap_or(&options.context),
                    &sources.iter().map(String::as_str).collect::<Vec<_>>(),
                    targets.next().ok_or("missing cached COPY targets")?,
                    copy_limits(options.limits, &copied),
                    if from.is_some() { None } else { Some(policy) },
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
        cache_hit = true;
        eprintln!("  CACHED (verified local stage)");
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
    fs::create_dir(&work)?;
    let root = work.join("rootfs");
    let spool = work.join("spool");
    let state = work.join("state");
    for p in [&root, &spool, &state] {
        fs::create_dir(p)?;
    }
    if let (Some(m), Some(p)) = (&metadata, &base_path) {
        let store = BlobStore::open(p)?;
        let mut bytes = 0u64;
        let mut entries = 0usize;
        for (descriptor, diff) in m.layers.iter().zip(&m.diff_ids) {
            check(&cancelled)?;
            let mut limits = options.limits.layer;
            limits.max_uncompressed_bytes = limits
                .max_uncompressed_bytes
                .min(options.limits.max_replay_bytes - bytes);
            limits.max_entries = limits
                .max_entries
                .min(options.limits.max_replay_entries - entries);
            let mut verified = layer::verify(&store, descriptor, diff, &spool, limits, &cancelled)?;
            bytes += verified.size();
            entries += verified.entries().len();
            rootfs::apply_layer(&root, &mut verified, &cancelled)?;
            root_budget(&root, options.limits, &cancelled)?;
        }
    }
    let mut copied = context::Summary::default();
    let mut copy_targets = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        check(&cancelled)?;
        match step {
            Step::Copy {
                from,
                sources,
                destination,
            } => {
                let stage_root = from.map(|n| previous[&n].result.work.join("rootfs"));
                let summary = context::copy_filtered(
                    stage_root.as_deref().unwrap_or(&options.context),
                    &root,
                    &sources.iter().map(String::as_str).collect::<Vec<_>>(),
                    destination,
                    copy_limits(options.limits, &copied),
                    if from.is_some() { None } else { Some(policy) },
                    &cancelled,
                )?;
                copied.bytes_written += summary.bytes_written;
                copied.entries += summary.entries;
                copied.metadata_bytes += summary.metadata_bytes;
                copy_targets.push(summary.targets);
            }
            Step::Directory(p) => {
                directory(&root, p)?;
            }
            Step::Run {
                command,
                workdir,
                env,
            } => {
                let run_state = state.join(index.to_string());
                fs::create_dir(&run_state)?;
                let dns = if options.host_dns {
                    install_dns(&root, &run_state)?
                } else {
                    None
                };
                let result = worker(
                    &root, &run_state, command, workdir, env, options, lease, &cancelled,
                );
                // Restore even on failed/cancelled RUN; restoration errors are fatal.
                if let Some(dns) = dns {
                    dns.restore()?;
                }
                result?;
            }
        }
        root_budget(&root, options.limits, &cancelled)?;
    }
    check(&cancelled)?;
    let manifest = if cache_hit {
        // Preserve the cached OCI bytes: re-exporting a replayed tree changes
        // access timestamps and would invalidate every dependent stage.
        crate::build_cache::publish(
            cache_entry.as_ref().unwrap(),
            lease,
            &output,
            None,
            &cancelled,
        )?;
        metadata.as_ref().unwrap().selected.clone()
    } else {
        export::export_layout(&root, &output, &config, options.limits.export, &cancelled)?
    };
    if !cache_hit && let Some(entry) = cache_entry {
        crate::build_cache::publish(&output, lease, &entry, Some(&copy_targets), &cancelled)?;
    }
    Ok(StageResult {
        result: BuildResult {
            manifest,
            output,
            work,
        },
        args,
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
    options: &BuildOptions,
    lease: Option<&crate::store_lease::StoreLease>,
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
    for e in env {
        cmd.arg("--env").arg(e);
    }
    let child = cmd.spawn()?;
    #[cfg(target_os = "linux")]
    {
        let mut child = child;
        let (status, stopped) = crate::lease_process::wait(
            &mut child,
            c,
            Duration::from_secs(timeout.saturating_add(5)),
        )?;
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
        let _ = (child, timeout, c);
        Err("RUN requires Linux".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
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
            // Keep emitted timestamps stable even on relatime mounts.
            let future = std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
            for name in ["", "Dockerfile", ".dockerignore", "keep"] {
                fs::File::open(o.context.join(name))
                    .unwrap()
                    .set_times(
                        fs::FileTimes::new()
                            .set_accessed(future)
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
            json!({"User":"root"}),
            json!({"OnBuild":["RUN true"]}),
            json!({"Shell":["bash","-c"]}),
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
        assert!(directory(&root, "/link/escaped").is_err());
        assert!(!outside.join("escaped").exists());
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
