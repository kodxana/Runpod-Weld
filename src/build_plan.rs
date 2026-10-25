//! Bounded, fail-closed Dockerfile subset for Weld; parsing performs no work.
//!
//! Expansion contract: this module NEVER expands variables, globs, tildes or
//! shell syntax. `Word::value` only removes lexical quotes/backslash escapes;
//! `Word::raw` retains their spelling for a future Docker-style evaluator.
//! That evaluator must implement instruction-specific expansion (including
//! quote/escape handling) or reject it, never feed COPY/ENV to a shell.
//! Shell RUN/CMD/ENTRYPOINT delegate their payload to the stage shell. JSON
//! arrays are literal argv. COPY JSON strings still require Docker-style path
//! expansion by the evaluator (never shell expansion). ARG scope/defaults and
//! ENV inheritance also belong to the evaluator. Accept the entire `parse`
//! result before doing any work. Base image reference grammar and availability
//! are validated by the evaluator before dependency selection or image lookup.
//!
//! Deliberate limits: default backslash escape only, no parser directives,
//! complex heredocs, dynamic COPY --from, flags except
//! FROM --platform, COPY --from/--chmod/--chown and HEALTHCHECK options, legacy ENV/LABEL,
//! or other instructions.
//! Empty continuation lines, repeated trailing escapes and non-ASCII syntax
//! whitespace are rejected rather than guessed. This is not full Dockerfile.
//! WORKDIR paths containing spaces must be quoted. `<<` is supported only for
//! one bare RUN or one inline COPY source; other occurrences fail closed.

use std::fmt;

pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_LINES: usize = 32 * 1024;
pub const MAX_INSTRUCTIONS: usize = 4096;
pub const MAX_TOKENS: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}
impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

fn error<T>(line: usize, message: impl Into<String>) -> Result<T> {
    Err(ParseError {
        line,
        message: message.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPlan {
    /// Only ARG is permitted before the first stage.
    pub global_args: Vec<Instruction>,
    pub stages: Vec<Stage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub name: Option<String>,
    pub base: Base,
    /// FROM is the first instruction, preserving its source location/payload.
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base {
    /// Reference or global ARG template; resolved by build::resolve_plan, never shell.
    Image(String),
    Stage(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopySource {
    Stage(usize),
    Image(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub line: usize,
    pub end_line: usize,
    /// Logical payload after continuation folding, before lexical decoding.
    pub raw_payload: String,
    pub kind: InstructionKind,
    pub heredoc: Option<Heredoc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heredoc {
    pub delimiter: String,
    pub expand: bool,
    pub strip_tabs: bool,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub raw: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arguments {
    Words(Vec<Word>),
    Json(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Run {
    Shell(String),
    Exec(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstructionKind {
    From {
        base: Base,
        alias: Option<String>,
        /// Raw global ARG template, validated before any image lookup.
        platform: Option<String>,
    },
    Run(Run),
    /// Last argument is the destination; preceding arguments are sources.
    Copy {
        from: Option<CopySource>,
        paths: Arguments,
        chown: Option<String>,
        chmod: Option<String>,
    },
    Workdir(Word),
    User(Word),
    StopSignal(Word),
    Healthcheck(Healthcheck),
    /// Each word is a modern key=value assignment; order is preserved.
    Env(Vec<Word>),
    /// Default is raw text, not shell-unquoted or expanded.
    Arg {
        name: String,
        default: Option<String>,
    },
    Cmd(Vec<String>),
    Entrypoint(Vec<String>),
    ShellCmd(String),
    ShellEntrypoint(String),
    Shell(Vec<String>),
    Label(Vec<Word>),
    Expose(Vec<Port>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Docker image metadata; zero options are omitted and left to the runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Healthcheck {
    pub test: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub interval: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub timeout: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub start_period: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub start_interval: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub retries: i32,
}

fn is_zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

/// Match moby/sys/signal ParseSignal on Linux/amd64, preserving original spelling.
pub(crate) fn validate_stop_signal(value: &str) -> std::result::Result<(), String> {
    if value.parse::<i64>().is_ok_and(|n| n != 0) {
        return Ok(());
    }
    let upper = value.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    if [
        "ABRT", "ALRM", "BUS", "CHLD", "CLD", "CONT", "FPE", "HUP", "ILL", "INT", "IO", "IOT",
        "KILL", "PIPE", "POLL", "PROF", "PWR", "QUIT", "SEGV", "STKFLT", "STOP", "SYS", "TERM",
        "TRAP", "TSTP", "TTIN", "TTOU", "URG", "USR1", "USR2", "VTALRM", "WINCH", "XCPU", "XFSZ",
        "RTMIN", "RTMAX",
    ]
    .contains(&name)
        || (1..=15).any(|n| name == format!("RTMIN+{n}"))
        || (1..=14).any(|n| name == format!("RTMAX-{n}"))
    {
        return Ok(());
    }
    Err("invalid STOPSIGNAL: expected a Linux signal name or nonzero signed 64-bit integer".into())
}

fn health_duration(value: &str) -> Option<i64> {
    if value.is_empty() {
        return Some(0);
    }
    let mut rest = value.strip_prefix('+').unwrap_or(value);
    if rest.is_empty() {
        return None;
    }
    if rest == "0" {
        return Some(0);
    }
    let mut total = 0i64;
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        let number = &rest[..end];
        rest = &rest[end..];
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if whole.is_empty() && fraction.is_empty() || !fraction.bytes().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        let (unit, scale) = [
            ("ns", 1i64),
            ("us", 1_000),
            ("µs", 1_000),
            ("μs", 1_000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ]
        .into_iter()
        .find(|(unit, _)| rest.starts_with(unit))?;
        rest = &rest[unit.len()..];
        let whole = if whole.is_empty() {
            0
        } else {
            whole.parse::<i64>().ok()?
        };
        // Decimal arithmetic avoids floating point rounding at the i64 boundary.
        let fraction = fraction
            .bytes()
            .rev()
            .fold(0i64, |n, c| ((c - b'0') as i64 * scale + n) / 10);
        total = total.checked_add(whole.checked_mul(scale)?.checked_add(fraction)?)?;
    }
    (total == 0 || total >= 1_000_000).then_some(total)
}

fn healthcheck(mut payload: &str, line: usize, tokens: &mut usize) -> Result<Healthcheck> {
    let mut health = Healthcheck::default();
    let mut seen = std::collections::BTreeSet::new();
    while payload.starts_with("--") {
        let end = payload.find([' ', '\t']).unwrap_or(payload.len());
        let flag = &payload[..end];
        let (name, value) = flag.split_once('=').ok_or_else(|| ParseError {
            line,
            message: "HEALTHCHECK flags require --name=value".into(),
        })?;
        if !seen.insert(name) {
            return error(line, "duplicate HEALTHCHECK flag");
        }
        charge(tokens, 1, line)?;
        if name == "--retries" {
            health.retries = if value.is_empty() {
                0
            } else {
                value
                    .parse::<i32>()
                    .ok()
                    .filter(|n| *n >= 0)
                    .ok_or_else(|| ParseError {
                        line,
                        message: "HEALTHCHECK retries must be 0..2147483647".into(),
                    })?
            };
        } else {
            let dest = match name {
                "--interval" => &mut health.interval,
                "--timeout" => &mut health.timeout,
                "--start-period" => &mut health.start_period,
                "--start-interval" => &mut health.start_interval,
                _ => return error(line, "unsupported HEALTHCHECK flag"),
            };
            *dest = health_duration(value).ok_or_else(|| ParseError {
                line, message: format!("invalid HEALTHCHECK {name}: expected nonnegative duration, zero or >=1ms, within signed 64-bit nanoseconds"),
            })?;
        }
        payload = payload[end..].trim_start_matches([' ', '\t']);
    }
    let end = payload.find([' ', '\t']).unwrap_or(payload.len());
    let command = payload[end..].trim_start_matches([' ', '\t']);
    match payload[..end].to_ascii_uppercase().as_str() {
        "NONE" if command.is_empty() && seen.is_empty() => health.test = vec!["NONE".into()],
        "NONE" => {
            return error(
                line,
                "HEALTHCHECK NONE takes no arguments or flags in this subset",
            );
        }
        "CMD" if !command.is_empty() => {
            if command.starts_with('[') {
                health.test = vec!["CMD".into()];
                let values = argv(command, line, tokens, false)?;
                if values.is_empty() {
                    return error(line, "HEALTHCHECK CMD requires a command");
                }
                health.test.extend(values);
            } else {
                charge(tokens, 1, line)?;
                health.test = vec!["CMD-SHELL".into(), command.into()];
            }
        }
        _ => return error(line, "expected HEALTHCHECK CMD command or HEALTHCHECK NONE"),
    }
    Ok(health)
}

/// Parse and validate the complete source, returning no partial plan on error.
pub fn parse(source: &str) -> Result<BuildPlan> {
    if source.len() > MAX_SOURCE_BYTES {
        return error(1, "source byte limit exceeded");
    }
    let mut plan = BuildPlan {
        global_args: Vec::new(),
        stages: Vec::new(),
    };
    let mut logical = String::new();
    let mut start = 1;
    let mut pending = false;
    let mut instructions = 0;
    let mut tokens = 0;
    let mut lines = source.split_terminator('\n').enumerate();
    while let Some((index, physical)) = lines.next() {
        let line = index + 1;
        if line > MAX_LINES {
            return error(line, "physical line limit exceeded");
        }
        let physical = physical.strip_suffix('\r').unwrap_or(physical);
        if physical.len() > MAX_LINE_BYTES {
            return error(line, "line byte limit exceeded");
        }
        if physical.chars().any(|c| c.is_control() && c != '\t') {
            return error(line, "control character in source");
        }
        let text = physical.trim_start_matches([' ', '\t']);
        if let Some(comment) = text.strip_prefix('#') {
            // Reject directive-shaped comments anywhere, even during continuation.
            if let Some((key, _)) = comment.trim().split_once('=')
                && matches!(
                    key.trim().to_ascii_lowercase().as_str(),
                    "syntax" | "escape" | "check"
                )
            {
                return error(line, "parser directives are unsupported");
            }
            continue;
        }
        if text.trim().is_empty() {
            if pending {
                return error(line, "empty continuation line is unsupported");
            }
            continue;
        }
        if !pending {
            start = line;
        }
        // Only the first physical line loses indentation. Continuation
        // indentation can separate arguments or be part of a quoted value.
        let text = if pending { physical } else { text };
        let text = text.trim_end_matches([' ', '\t']);
        let continued = text.ends_with('\\');
        if text.ends_with("\\\\") {
            return error(
                line,
                "repeated trailing escapes are ambiguous in this subset",
            );
        }
        let part = if continued {
            &text[..text.len() - 1]
        } else {
            text
        };
        if logical.len() + part.len() > MAX_LINE_BYTES {
            return error(start, "logical instruction byte limit exceeded");
        }
        // Docker continuation removes the newline, it does not insert a space.
        logical.push_str(part);
        pending = continued;
        if pending {
            continue;
        }
        instructions += 1;
        if instructions > MAX_INSTRUCTIONS {
            return error(start, "instruction limit exceeded");
        }
        let mut instruction = parse_instruction(&logical, start, line, &plan, &mut tokens)?;
        if let Some(doc) = &mut instruction.heredoc {
            instruction.end_line = read_heredoc(doc, &mut lines, start)?;
            if matches!(instruction.kind, InstructionKind::Run(_)) && doc.body.starts_with("#!") {
                return error(start, "shebang RUN heredocs are unsupported");
            }
        }
        match &instruction.kind {
            InstructionKind::From { base, alias, .. } => {
                plan.stages.push(Stage {
                    name: alias.clone(),
                    base: base.clone(),
                    instructions: vec![instruction],
                });
            }
            InstructionKind::Arg { .. } if plan.stages.is_empty() => {
                plan.global_args.push(instruction)
            }
            _ => match plan.stages.last_mut() {
                Some(stage) => stage.instructions.push(instruction),
                None => return error(start, "only ARG is allowed before FROM"),
            },
        }
        logical.clear();
    }
    if pending {
        return error(start, "unfinished continuation");
    }
    if plan.stages.is_empty() {
        return error(1, "at least one FROM is required");
    }
    for stage in &plan.stages {
        for instruction in &stage.instructions {
            if let InstructionKind::Copy {
                from: Some(CopySource::Image(name)),
                ..
            } = &instruction.kind
                && stage_index(name, &plan).is_some()
            {
                return error(
                    instruction.line,
                    "COPY forward stage references are unsupported",
                );
            }
        }
    }
    Ok(plan)
}

fn charge(tokens: &mut usize, count: usize, line: usize) -> Result<()> {
    *tokens += count;
    if *tokens > MAX_TOKENS {
        return error(line, "token limit exceeded");
    }
    Ok(())
}

fn identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn alias_valid(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

fn stage_index(value: &str, plan: &BuildPlan) -> Option<usize> {
    if value.bytes().all(|c| c.is_ascii_digit()) {
        value
            .parse::<usize>()
            .ok()
            .filter(|i| *i < plan.stages.len())
    } else {
        plan.stages.iter().position(|s| {
            s.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(value))
        })
    }
}

fn parse_instruction(
    text: &str,
    line: usize,
    end_line: usize,
    plan: &BuildPlan,
    tokens: &mut usize,
) -> Result<Instruction> {
    let split = text.find([' ', '\t']).unwrap_or(text.len());
    let name = text[..split].to_ascii_uppercase();
    let payload = text[split..].trim_start_matches([' ', '\t']);
    if payload.is_empty() {
        return error(line, format!("{name} requires a payload"));
    }
    let heredoc = heredoc_header(&name, payload, line)?;
    if payload
        .chars()
        .any(|c| c.is_whitespace() && !matches!(c, ' ' | '\t'))
    {
        return error(line, "non-ASCII syntax whitespace is unsupported");
    }
    if payload.starts_with("--") && !matches!(name.as_str(), "COPY" | "FROM" | "HEALTHCHECK") {
        return error(line, "instruction flags are unsupported");
    }
    charge(tokens, 1, line)?;
    let kind = match name.as_str() {
        "FROM" => {
            let words = words(payload, line, tokens)?;
            let platform = words[0]
                .value
                .strip_prefix("--platform=")
                .map(str::to_owned);
            if platform.as_deref() == Some("") {
                return error(line, "FROM --platform requires a value");
            }
            if words.iter().any(|w| w.raw != w.value) {
                return error(line, "quoted FROM syntax is unsupported");
            }
            let words = &words[usize::from(platform.is_some())..];
            if !matches!(words.len(), 1 | 3)
                || (words.len() == 3 && !words[1].value.eq_ignore_ascii_case("AS"))
            {
                return error(line, "expected FROM [--platform=value] reference [AS name]");
            }
            let reference = &words[0].value;
            if reference.is_empty()
                || !reference
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._/:@+-${}".contains(&c))
                || (!reference.contains('$') && !reference.as_bytes()[0].is_ascii_alphanumeric())
            {
                return error(
                    line,
                    "FROM requires an image reference or backward stage name with optional ARG expansion",
                );
            }
            let alias = words.get(2).map(|w| w.value.clone());
            if let Some(alias) = &alias
                && (!alias_valid(alias)
                    || plan.stages.iter().any(|s| {
                        s.name
                            .as_deref()
                            .is_some_and(|n| n.eq_ignore_ascii_case(alias))
                    }))
            {
                return error(line, "invalid or duplicate stage name");
            }
            // FROM numeric strings are image references, not stage indices.
            let base = plan
                .stages
                .iter()
                .position(|s| {
                    s.name
                        .as_deref()
                        .is_some_and(|n| n.eq_ignore_ascii_case(reference))
                })
                .map(Base::Stage)
                .unwrap_or_else(|| Base::Image(reference.clone()));
            InstructionKind::From {
                base,
                alias,
                platform,
            }
        }
        "RUN" => InstructionKind::Run(if payload.starts_with('[') {
            Run::Exec(argv(payload, line, tokens, true)?)
        } else {
            Run::Shell(payload.to_owned())
        }),
        "COPY" => {
            let mut from = None;
            let mut chown = None;
            let mut chmod = None;
            let mut paths = payload;
            while paths.starts_with("--") {
                let split = paths.find([' ', '\t']).ok_or_else(|| ParseError {
                    line,
                    message: "COPY requires paths".into(),
                })?;
                let flag = &paths[..split];
                if let Some(reference) = flag.strip_prefix("--from=") {
                    if from.is_some() || reference.contains('$') {
                        return error(line, "duplicate or dynamic COPY --from unsupported");
                    }
                    from = Some(if let Some(index) = stage_index(reference, plan) {
                        if index + 1 >= plan.stages.len() {
                            return error(line, "COPY cannot reference its current stage");
                        }
                        CopySource::Stage(index)
                    } else {
                        if reference.is_empty() || reference.bytes().all(|b| b.is_ascii_digit()) {
                            return error(line, "COPY stage index is out of range");
                        }
                        crate::registry::reference(reference, true)
                            .map_err(|message| ParseError { line, message })?;
                        CopySource::Image(reference.to_owned())
                    });
                } else if let Some(value) = flag.strip_prefix("--chown=") {
                    if value.is_empty() || chown.replace(value.to_owned()).is_some() {
                        return error(line, "empty or duplicate COPY --chown");
                    }
                } else if let Some(value) = flag.strip_prefix("--chmod=") {
                    if value.is_empty() || chmod.replace(value.to_owned()).is_some() {
                        return error(line, "empty or duplicate COPY --chmod");
                    }
                } else {
                    return error(line, "unsupported COPY flag");
                }
                charge(tokens, 1, line)?;
                paths = paths[split..].trim_start_matches([' ', '\t']);
            }
            let paths = if paths.starts_with('[') {
                let values = argv(paths, line, tokens, false)?;
                if values.len() < 2 || values.iter().any(String::is_empty) {
                    return error(line, "COPY requires nonempty source(s) and destination");
                }
                Arguments::Json(values)
            } else {
                let values = words(paths, line, tokens)?;
                if values.len() < 2
                    || values
                        .iter()
                        .any(|w| w.value.is_empty() || w.raw.starts_with("--"))
                {
                    return error(
                        line,
                        "COPY requires nonempty source(s) and destination without flags",
                    );
                }
                Arguments::Words(values)
            };
            InstructionKind::Copy {
                from,
                paths,
                chown,
                chmod,
            }
        }
        "HEALTHCHECK" => InstructionKind::Healthcheck(healthcheck(payload, line, tokens)?),
        "WORKDIR" | "USER" | "STOPSIGNAL" => {
            let mut values = words(payload, line, tokens)?;
            if values.len() != 1 || values[0].value.is_empty() {
                return error(line, format!("{name} requires one nonempty token"));
            }
            let word = values.remove(0);
            if name == "STOPSIGNAL" {
                if !word.raw.contains('$') {
                    validate_stop_signal(&word.value)
                        .map_err(|message| ParseError { line, message })?;
                }
                InstructionKind::StopSignal(word)
            } else if name == "USER" {
                // Expansion is evaluated with the stage ARG/ENV scope later.
                if !word.raw.contains('$') {
                    crate::user::validate_user_spec(&word.value)
                        .map_err(|message| ParseError { line, message })?;
                }
                InstructionKind::User(word)
            } else {
                InstructionKind::Workdir(word)
            }
        }
        "ENV" | "LABEL" => {
            let values = words(payload, line, tokens)?;
            for word in &values {
                let Some((key, _)) = word.raw.split_once('=') else {
                    return error(line, format!("{name} requires key=value assignments"));
                };
                if name == "ENV" && !identifier(key) || key.is_empty() {
                    return error(line, format!("invalid {name} key"));
                }
            }
            if name == "ENV" {
                InstructionKind::Env(values)
            } else {
                InstructionKind::Label(values)
            }
        }
        "ARG" => {
            let declarations = words(payload, line, tokens)?;
            if declarations.len() != 1 {
                return error(
                    line,
                    "only one ARG declaration per instruction is supported",
                );
            }
            let (name, default) = match payload.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (payload, None),
            };
            if !identifier(name) {
                return error(line, "ARG requires a name with optional =default");
            }
            // Preserve quoted defaults for the evaluator; never merge declarations.
            InstructionKind::Arg {
                name: name.into(),
                default,
            }
        }
        "CMD" if payload.starts_with('[') => {
            InstructionKind::Cmd(argv(payload, line, tokens, false)?)
        }
        "CMD" => InstructionKind::ShellCmd(payload.to_owned()),
        "ENTRYPOINT" if payload.starts_with('[') => {
            InstructionKind::Entrypoint(argv(payload, line, tokens, false)?)
        }
        "ENTRYPOINT" => InstructionKind::ShellEntrypoint(payload.to_owned()),
        "SHELL" => InstructionKind::Shell(argv(payload, line, tokens, true)?),
        "EXPOSE" => {
            let values = words(payload, line, tokens)?;
            let mut ports = Vec::new();
            for word in values {
                if word.raw != word.value {
                    return error(line, "EXPOSE requires literal port tokens");
                }
                let (number, protocol) = word.value.split_once('/').unwrap_or((&word.value, "tcp"));
                let protocol = match protocol {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    _ => return error(line, "unsupported EXPOSE protocol"),
                };
                if !number.bytes().all(|c| c.is_ascii_digit()) {
                    return error(line, "invalid EXPOSE port");
                }
                let number = number
                    .parse::<u16>()
                    .ok()
                    .filter(|n| *n != 0)
                    .ok_or_else(|| ParseError {
                        line,
                        message: "EXPOSE port must be 1..65535".into(),
                    })?;
                ports.push(Port { number, protocol });
            }
            InstructionKind::Expose(ports)
        }
        _ => return error(line, format!("unsupported instruction {name}")),
    };
    Ok(Instruction {
        line,
        end_line,
        raw_payload: payload.into(),
        kind,
        heredoc,
    })
}

/// Deliberately narrow grammar shared with the policy scanner. Other possible
/// heredocs fail closed rather than exposing their bodies as instructions.
pub(crate) fn heredoc_header(name: &str, payload: &str, line: usize) -> Result<Option<Heredoc>> {
    if !payload.contains("<<") {
        return Ok(None);
    }
    let mut tokens = 0;
    let values = words(payload, line, &mut tokens)?;
    let sources: Vec<_> = values.iter().filter(|w| !w.raw.starts_with("--")).collect();
    let valid = match name {
        "RUN" => values.len() == 1 && sources.len() == 1,
        "COPY" => sources.len() == 2 && !values.iter().any(|w| w.raw.starts_with("--from")),
        _ => false,
    };
    let unsupported = "unsupported heredoc: use bare RUN <<word or COPY [--chmod/--chown] <<word destination; multiple, command-bearing, fd-prefixed and mixed-source heredocs are unsupported";
    if !valid
        || !sources[0].raw.starts_with("<<")
        || sources.iter().skip(1).any(|w| w.raw.contains("<<"))
    {
        return error(line, unsupported);
    }
    let raw = &sources[0].raw[2..];
    let (strip_tabs, raw) = raw.strip_prefix('-').map_or((false, raw), |s| (true, s));
    let delimiter = words(raw, line, &mut tokens)?;
    if delimiter.len() != 1 || !identifier(&delimiter[0].value) {
        return error(
            line,
            "heredoc delimiter must be an optionally quoted ASCII identifier",
        );
    }
    Ok(Some(Heredoc {
        delimiter: delimiter[0].value.clone(),
        expand: raw == delimiter[0].value,
        strip_tabs,
        body: String::new(),
    }))
}

pub(crate) fn read_heredoc<'a>(
    doc: &mut Heredoc,
    lines: &mut impl Iterator<Item = (usize, &'a str)>,
    start: usize,
) -> Result<usize> {
    for (index, physical) in lines {
        let line = index + 1;
        let delimiter_line = physical.strip_suffix('\r').unwrap_or(physical);
        if line > MAX_LINES || physical.len() > MAX_LINE_BYTES {
            return error(line, "heredoc physical line budget exceeded");
        }
        if delimiter_line.chars().any(|c| c.is_control() && c != '\t') {
            return error(line, "control character in heredoc");
        }
        let text = if doc.strip_tabs {
            physical.trim_start_matches('\t')
        } else {
            physical
        };
        if (if doc.strip_tabs {
            delimiter_line.trim_start_matches('\t')
        } else {
            delimiter_line
        }) == doc.delimiter
        {
            return Ok(line);
        }
        if doc.body.len() + text.len() + 1 > MAX_SOURCE_BYTES {
            return error(line, "heredoc body budget exceeded");
        }
        doc.body.push_str(text);
        doc.body.push('\n');
    }
    error(start, format!("unterminated heredoc {}", doc.delimiter))
}

fn argv(text: &str, line: usize, tokens: &mut usize, executable: bool) -> Result<Vec<String>> {
    let values: Vec<String> = serde_json::from_str(text).map_err(|e| ParseError {
        line,
        message: format!("expected JSON string array: {e}"),
    })?;
    charge(tokens, values.len(), line)?;
    if values.iter().any(|v| v.contains('\0')) {
        return error(line, "NUL in JSON argument");
    }
    if executable && values.first().is_none_or(String::is_empty) {
        return error(line, "RUN requires a nonempty executable");
    }
    Ok(values)
}

fn words(text: &str, line: usize, tokens: &mut usize) -> Result<Vec<Word>> {
    let mut result = Vec::new();
    let mut iter = text.char_indices().peekable();
    while let Some(&(start, c)) = iter.peek() {
        if matches!(c, ' ' | '\t') {
            iter.next();
            continue;
        }
        let mut value = String::new();
        let mut quote = None;
        let mut end = start;
        while let Some(&(index, c)) = iter.peek() {
            if quote.is_none() && matches!(c, ' ' | '\t') {
                break;
            }
            iter.next();
            end = index + c.len_utf8();
            if c == '\\' && quote != Some('\'') {
                let Some((next_index, next)) = iter.next() else {
                    return error(line, "dangling token escape");
                };
                end = next_index + next.len_utf8();
                // Double quotes preserve backslashes before non-special chars.
                if quote == Some('"') && !matches!(next, '"' | '\\' | '$') {
                    value.push('\\');
                }
                value.push(next);
            } else if Some(c) == quote {
                quote = None;
            } else if quote.is_none() && matches!(c, '\'' | '"') {
                quote = Some(c);
            } else {
                value.push(c);
            }
        }
        if quote.is_some() {
            return error(line, "unterminated quote");
        }
        charge(tokens, 1, line)?;
        result.push(Word {
            raw: text[start..end].into(),
            value,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_platform_retains_template_and_rejects_ambiguous_flags() {
        let plan = parse(
            "FROM --platform=${BUILDPLATFORM} scratch AS base\nFROM --platform=linux/amd64 base",
        )
        .unwrap();
        assert!(matches!(&plan.stages[0].instructions[0].kind,
            InstructionKind::From { platform: Some(value), .. } if value == "${BUILDPLATFORM}"));
        assert_eq!(plan.stages[1].base, Base::Stage(0));
        for source in [
            "FROM --platform= scratch",
            "FROM --platform linux/amd64 scratch",
            "FROM --platform=linux/amd64",
            "FROM --unknown=linux/amd64 scratch",
            "FROM --platform=linux/amd64 --platform=linux/amd64 scratch",
        ] {
            assert!(parse(source).is_err(), "{source}");
        }
    }

    #[test]
    fn continuation_indentation_preserves_shell_and_quoted_values() {
        let plan = parse(
            "FROM alpine\nRUN echo a\\\n    b\nENV X=\"a\\\n    b\"\nCOPY \"a\\\n    b\" /out\n",
        )
        .unwrap();
        let instructions = &plan.stages[0].instructions;
        assert_eq!(
            instructions[1].kind,
            InstructionKind::Run(Run::Shell("echo a    b".into()))
        );
        assert_eq!(instructions[2].raw_payload, "X=\"a    b\"");
        let InstructionKind::Env(words) = &instructions[2].kind else {
            panic!()
        };
        assert_eq!(words[0].value, "X=a    b");
        let InstructionKind::Copy {
            paths: Arguments::Words(words),
            ..
        } = &instructions[3].kind
        else {
            panic!()
        };
        assert_eq!(words[0].value, "a    b");
    }

    #[test]
    fn arg_rejects_multiple_declarations_but_preserves_quoted_default() {
        for text in ["A=one B=two", "A B", "A=one B", "A=one\\\n    B=two"] {
            assert!(parse(&format!("FROM alpine\nARG {text}\n")).is_err());
        }
        let plan = parse("FROM alpine\nARG A=\"one B=two\"\nARG EMPTY=\n").unwrap();
        assert_eq!(
            plan.stages[0].instructions[1].kind,
            InstructionKind::Arg {
                name: "A".into(),
                default: Some("\"one B=two\"".into())
            }
        );
        assert_eq!(
            plan.stages[0].instructions[2].kind,
            InstructionKind::Arg {
                name: "EMPTY".into(),
                default: Some(String::new())
            }
        );
    }

    #[test]
    fn practical_two_stage_plan() {
        let plan = parse(
            r#"ARG VERSION=1
FROM python:3.12-slim AS build
WORKDIR /opt/ComfyUI
ENV PATH="/opt/venv/bin:$PATH" NAME='Comfy UI'
RUN python -m venv /opt/venv && \
    pip install torch
RUN ["python", "-c", "print('ok')"]
COPY ["requirements.txt", "/opt/ComfyUI/"]
FROM python:3.12-slim AS runtime
COPY --from=build /opt/venv /opt/venv
COPY --from=0 ["/opt/ComfyUI", "/app"]
ARG MODE=production
EXPOSE 8188 9000/udp
ENTRYPOINT ["python"]
CMD ["/app/main.py", "--listen", "0.0.0.0"]
"#,
        )
        .unwrap();
        assert_eq!(plan.global_args.len(), 1);
        assert_eq!(plan.stages.len(), 2);
        assert!(matches!(
            plan.stages[1].instructions[1].kind,
            InstructionKind::Copy {
                from: Some(CopySource::Stage(0)),
                ..
            }
        ));
        let InstructionKind::Env(env) = &plan.stages[0].instructions[2].kind else {
            panic!()
        };
        assert_eq!(env[0].raw, "PATH=\"/opt/venv/bin:$PATH\"");
        assert_eq!(env[1].value, "NAME=Comfy UI");
        assert_eq!(plan.stages[0].instructions[3].end_line, 6);
    }

    #[test]
    fn folding_comments_and_inline_hash() {
        let plan =
            parse("FROM alpine\r\nRUN echo ab\\\r\n# comment\\\r\ncd # literal\r\nUSER root\r\n");
        let plan = plan.unwrap();
        assert_eq!(plan.stages[0].instructions[2].line, 5);
        assert!(matches!(
            plan.stages[0].instructions[2].kind,
            InstructionKind::User(_)
        ));
        let plan = parse("FROM alpine\nRUN echo ab\\\n# comment\ncd # literal\n").unwrap();
        assert_eq!(
            plan.stages[0].instructions[1].kind,
            InstructionKind::Run(Run::Shell("echo abcd # literal".into()))
        );
        assert!(matches!(
            parse("FROM alpine\nUS\\\nER root").unwrap().stages[0].instructions[1].kind,
            InstructionKind::User(_)
        ));
    }

    #[test]
    fn copy_image_references_and_stage_precedence() {
        let plan = parse("FROM scratch AS alpine\nFROM scratch\nCOPY --from=AlPiNe /a /a\nCOPY --from=0 /b /b\nCOPY --from=example.invalid/team/image:tag /c /c\nCOPY --from=other /d /d\n").unwrap();
        for i in [1, 2] {
            assert!(matches!(
                plan.stages[1].instructions[i].kind,
                InstructionKind::Copy {
                    from: Some(CopySource::Stage(0)),
                    ..
                }
            ));
        }
        assert!(matches!(&plan.stages[1].instructions[3].kind,
            InstructionKind::Copy { from: Some(CopySource::Image(name)), .. } if name == "example.invalid/team/image:tag"));
        assert!(matches!(&plan.stages[1].instructions[4].kind,
            InstructionKind::Copy { from: Some(CopySource::Image(name)), .. } if name == "other"));
        let pinned = format!(
            "FROM scratch\nCOPY --from=alpine@sha256:{} /a /a\n",
            "a".repeat(64)
        );
        assert!(parse(&pinned).is_ok());
        for reference in [
            "",
            "$IMAGE",
            "${IMAGE}",
            "999999999999999999999999999",
            "4",
            "https://host/repo",
            "alpine@sha256:bad",
        ] {
            assert!(parse(&format!("FROM scratch\nCOPY --from={reference} /a /a\n")).is_err());
        }
    }

    #[test]
    fn rejects_unsupported_and_ambiguous_syntax() {
        for source in [
            "FROM",
            "FROM ''",
            "FROM --platform=linux/amd64 --platform=linux/amd64 alpine",
            "# escape=`\nFROM alpine",
            "# syntax=docker/dockerfile:1\nFROM alpine",
            "RUN hi",
            "FROM alpine\nUSER root:group:extra",
            "FROM alpine\nADD a b",
            "FROM alpine\nRUN --mount=type=cache echo hi",
            "FROM alpine\nRUN <<EOF cat\nhi\nEOF",
            "FROM alpine\nRUN [bad]",
            "FROM alpine\nRUN []",
            "FROM alpine\nRUN [1]",
            "FROM alpine\nCOPY --chown=root --chown=root a b",
            "FROM alpine\nCOPY --from=next a b\nFROM alpine AS next",
            "FROM alpine AS current\nCOPY --from=current a b",
            "FROM alpine\nCOPY --from=0 a b",
            "FROM alpine\nCOPY a",
            "FROM alpine\nCOPY [\"\",\"b\"]",
            "FROM alpine\nCOPY 'a b",
            "FROM alpine\nENV legacy value",
            "FROM alpine\nENV =bad",
            "FROM alpine\nARG bad name=x",
            "FROM alpine\nSHELL echo hi",
            "FROM alpine\nEXPOSE 65536",
            "FROM alpine\nEXPOSE 80/sctp",
            "FROM alpine\nRUN hi\\",
            "FROM alpine\nRUN hi\\\n\nUSER root",
            "FROM alpine AS build\nFROM alpine AS BUILD",
            "FROM alpine\nWORKDIR \"\"",
        ] {
            assert!(parse(source).is_err(), "accepted {source:?}");
        }
    }

    #[test]
    fn retains_literal_arguments_and_backward_base() {
        let plan = parse("FROM alpine AS build\nFROM build\nCOPY '$HOME/a b' c\\ d /out\nRUN [\"echo\",\"$HOME\"]\nCMD []\nARG EMPTY=\n").unwrap();
        assert_eq!(plan.stages[1].base, Base::Stage(0));
        let InstructionKind::Copy {
            paths: Arguments::Words(words),
            ..
        } = &plan.stages[1].instructions[1].kind
        else {
            panic!()
        };
        assert_eq!(
            words[0],
            Word {
                raw: "'$HOME/a b'".into(),
                value: "$HOME/a b".into()
            }
        );
        assert_eq!(words[1].value, "c d");
        assert_eq!(
            plan.stages[1].instructions[2].kind,
            InstructionKind::Run(Run::Exec(vec!["echo".into(), "$HOME".into()]))
        );
    }

    #[test]
    fn bounds_are_enforced() {
        assert!(parse(&" ".repeat(MAX_SOURCE_BYTES + 1)).is_err());
        assert!(parse(&format!("FROM alpine\nRUN {}", "x".repeat(MAX_LINE_BYTES))).is_err());
        assert!(
            parse(&format!(
                "FROM alpine\n{}",
                "RUN true\n".repeat(MAX_INSTRUCTIONS)
            ))
            .is_err()
        );
        assert!(parse(&"\n".repeat(MAX_LINES + 1)).is_err());
        let source = format!(
            "FROM alpine\n{}",
            format!("COPY {} /out\n", "a ".repeat(4000)).repeat(5)
        );
        assert!(parse(&source).unwrap_err().message.contains("token limit"));
    }
}
