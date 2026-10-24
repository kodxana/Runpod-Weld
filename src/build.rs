//! Minimal, trusted/stable Linux amd64 builds from local OCI bindings or scratch.
//! Supports one stage: FROM, RUN, ARG, ENV, WORKDIR, JSON CMD/ENTRYPOINT, EXPOSE.
//! COPY, custom shells, USER/OnBuild and complex expansion fail closed. RUN exec
//! form uses `/bin/sh -c 'exec ...'` with every argv element literally quoted.
//! This is not a sandbox. Caller owns stable ancestors and trusted image/commands;
//! no concurrent writers, mounts or external hardlinks are allowed. WORKDIR
//! rejects symlink components (including absolute image symlinks), never follows
//! them on the host. No synthetic /dev or /proc files are created.
//! Budgets are explicit; rootfs budgets are checked between operations, not disk
//! quotas or RUN memory limits. Caller must provision/enforce RUN resources.
//! Errors leave partial owned work/output directories for manual inspection;
//! nothing recursively deletes user trees. Never reuse a failed build directory.

use crate::{
    build_plan::{self, Base, InstructionKind as I, Protocol, Run},
    export, image, layer,
    oci::{BlobStore, Descriptor},
    rootfs,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

/// Errors include underlying parser, image, filesystem, worker and export errors.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

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
pub struct BuildOptions {
    pub work: PathBuf,
    pub output: PathBuf,
    pub context: PathBuf,
    pub bases: BTreeMap<String, LocalBase>,
    pub args: BTreeMap<String, String>,
    pub limits: Limits,
    /// Opt in to temporary host /etc/resolv.conf only when the image's file is
    /// missing/empty. Original file metadata is restored by rename before export.
    pub host_dns: bool,
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

fn preflight(
    source: &str,
    options: &BuildOptions,
    mut config: Value,
) -> Result<(Value, Vec<Step>)> {
    let plan = build_plan::parse(source)?;
    if plan.stages.len() != 1 {
        return Err("multistage builds unsupported".into());
    }
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
    let mut args = BTreeMap::new();
    let mut steps = vec![Step::Directory(wd.clone())];
    let mut charge = supplied_bytes + wd.len() + map_bytes(&globals, cap)?;
    let mut cmd_set = false;
    for i in &plan.stages[0].instructions {
        let mut vars = args.clone();
        vars.extend(env.clone()); // ENV shadows ARG, including empty values.
        match &i.kind {
            I::From { .. } => (),
            I::Copy { .. } => return Err(format!("line {}: COPY unsupported", i.line).into()),
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
    Ok((config, steps))
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
    }
    walk(root, &mut 0, &mut 0, 0, limits, c)
}

/// Parse/static-preflight completely before creating directories. Spawns the
/// current executable's `__trace-worker` dispatch (caller must implement it).
/// Cancellation is cooperative for I/O; RUN cancellation signals its dedicated
/// worker, waits for bounded cleanup, then kills/reaps it if necessary.
pub fn build(
    source: &str,
    options: &BuildOptions,
    cancelled: impl Fn() -> bool,
) -> Result<BuildResult> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err("build requires Linux amd64".into());
    }
    check(&cancelled)?;
    let plan = build_plan::parse(source)?;
    if plan.stages.len() != 1 {
        return Err("multistage builds unsupported".into());
    }
    // Syntax-only pass: inherited ENV must not be guessed before loading config.
    for instruction in plan
        .global_args
        .iter()
        .chain(plan.stages[0].instructions.iter())
    {
        let empty = BTreeMap::new();
        match &instruction.kind {
            I::Copy { .. } => return Err("COPY unsupported".into()),
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
    let binding = match &plan.stages[0].base {
        Base::Image(name) if name == "scratch" => None,
        Base::Image(name) => Some(
            options
                .bases
                .get(name)
                .ok_or_else(|| format!("no local base binding for {name}"))?,
        ),
        Base::Stage(_) => return Err("stage base unsupported".into()),
    };
    let base_path = binding.map(|b| fs::canonicalize(&b.layout)).transpose()?;
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
    let metadata = match (binding, &base_path) {
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
    let (config, steps) = preflight(source, options, config)?;
    #[cfg(target_os = "linux")]
    if steps.iter().any(|s| matches!(s, Step::Run { .. })) && unsafe { libc::geteuid() } != 0 {
        return Err("RUN worker requires root".into());
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
    for (index, step) in steps.iter().enumerate() {
        check(&cancelled)?;
        match step {
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
                    &root,
                    &run_state,
                    command,
                    workdir,
                    env,
                    options.limits.run_timeout_seconds,
                    &cancelled,
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
    let manifest =
        export::export_layout(&root, &output, &config, options.limits.export, &cancelled)?;
    Ok(BuildResult {
        manifest,
        output,
        work,
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

fn worker(
    root: &Path,
    state: &Path,
    command: &str,
    wd: &str,
    env: &[String],
    timeout: u64,
    c: &impl Fn() -> bool,
) -> Result<()> {
    let mut cmd = Command::new(std::env::current_exe()?);
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
    let mut child = cmd.spawn()?;
    let start = std::time::Instant::now();
    let mut stopping = None;
    loop {
        if let Some(status) = child.try_wait()? {
            if stopping.is_some() {
                return Err("RUN cancelled/timed out; partial root retained".into());
            }
            return if status.success() {
                Ok(())
            } else {
                Err(format!("RUN worker failed: {status}").into())
            };
        }
        if stopping.is_none() && (c() || start.elapsed() > Duration::from_secs(timeout + 5)) {
            #[cfg(target_os = "linux")]
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
            stopping = Some(std::time::Instant::now());
        }
        if stopping.is_some_and(|s| s.elapsed() > Duration::from_secs(5)) {
            child.kill()?;
            child.wait()?;
            return Err("RUN cleanup deadline exceeded; partial root retained".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn options(temp: &Path) -> BuildOptions {
        let context = temp.join("context");
        fs::create_dir(&context).unwrap();
        BuildOptions {
            work: temp.join("work"),
            output: temp.join("output"),
            context,
            bases: BTreeMap::new(),
            args: BTreeMap::new(),
            host_dns: false,
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
            "FROM scratch\nWORKDIR /made\nCOPY a b\n",
            "FROM scratch\nFROM scratch\n",
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
