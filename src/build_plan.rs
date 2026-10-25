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
//! heredocs, USER, external COPY images, dynamic COPY --from, flags except
//! COPY --from/--chmod/--chown, legacy ENV/LABEL, or other instructions.
//! Empty continuation lines, repeated trailing escapes and non-ASCII syntax
//! whitespace are rejected rather than guessed. This is not full Dockerfile.
//! WORKDIR paths containing spaces must be quoted. Any `<<` payload is rejected,
//! including quoted literals, to keep heredoc handling unambiguous.

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
pub struct Instruction {
    pub line: usize,
    pub end_line: usize,
    /// Logical payload after continuation folding, before lexical decoding.
    pub raw_payload: String,
    pub kind: InstructionKind,
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
    },
    Run(Run),
    /// Last argument is the destination; preceding arguments are sources.
    Copy {
        from: Option<usize>,
        paths: Arguments,
        chown: Option<String>,
        chmod: Option<String>,
    },
    Workdir(Word),
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
    for (index, physical) in source.split_terminator('\n').enumerate() {
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
        let instruction = parse_instruction(&logical, start, line, &plan, &mut tokens)?;
        match &instruction.kind {
            InstructionKind::From { base, alias } => {
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
    if name == "USER" {
        return error(
            line,
            "USER is explicitly unsupported by the initial builder",
        );
    }
    if payload.is_empty() {
        return error(line, format!("{name} requires a payload"));
    }
    if payload.contains("<<") {
        return error(line, "heredoc markers are unsupported");
    }
    if payload
        .chars()
        .any(|c| c.is_whitespace() && !matches!(c, ' ' | '\t'))
    {
        return error(line, "non-ASCII syntax whitespace is unsupported");
    }
    if payload.starts_with("--") && name != "COPY" {
        return error(line, "instruction flags are unsupported");
    }
    charge(tokens, 1, line)?;
    let kind = match name.as_str() {
        "FROM" => {
            let words = words(payload, line, tokens)?;
            if !matches!(words.len(), 1 | 3)
                || (words.len() == 3 && !words[1].value.eq_ignore_ascii_case("AS"))
            {
                return error(line, "expected FROM reference [AS name]");
            }
            if words.iter().any(|w| w.raw != w.value) {
                return error(line, "quoted FROM syntax is unsupported");
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
            InstructionKind::From { base, alias }
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
                    let index = stage_index(reference, plan).ok_or_else(|| ParseError {
                        line,
                        message: "COPY --from must reference an earlier stage".into(),
                    })?;
                    // Current stage already exists in the plan but cannot copy itself.
                    if index + 1 >= plan.stages.len() {
                        return error(line, "COPY cannot reference its current stage");
                    }
                    from = Some(index);
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
        "WORKDIR" => {
            let mut values = words(payload, line, tokens)?;
            if values.len() != 1 || values[0].value.is_empty() {
                return error(line, "WORKDIR requires one nonempty path token");
            }
            InstructionKind::Workdir(values.remove(0))
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
    })
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
            InstructionKind::Copy { from: Some(0), .. }
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
        let err = plan.unwrap_err();
        assert_eq!(err.line, 5);
        assert!(err.message.contains("USER"));
        let plan = parse("FROM alpine\nRUN echo ab\\\n# comment\ncd # literal\n").unwrap();
        assert_eq!(
            plan.stages[0].instructions[1].kind,
            InstructionKind::Run(Run::Shell("echo abcd # literal".into()))
        );
        assert!(
            parse("FROM alpine\nUS\\\nER root")
                .unwrap_err()
                .message
                .contains("USER")
        );
    }

    #[test]
    fn rejects_unsupported_and_ambiguous_syntax() {
        for source in [
            "FROM",
            "FROM ''",
            "FROM --platform=linux/amd64 alpine",
            "# escape=`\nFROM alpine",
            "# syntax=docker/dockerfile:1\nFROM alpine",
            "RUN hi",
            "FROM alpine\nUSER root",
            "FROM alpine\nADD a b",
            "FROM alpine\nRUN --mount=type=cache echo hi",
            "FROM alpine\nRUN <<EOF\nhi\nEOF",
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
