//! Partial lexical policy checks, not a Dockerfile parser or a working builder.
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool_version: &'static str,
    pub profile: &'static str,
    pub builder_ready: bool,
    pub checks: &'static str,
    pub scan_complete: bool,
    pub policy_status: &'static str,
    pub diagnostics: Vec<Diagnostic>,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub line: usize,
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Instruction {
    pub line: usize,
    pub end_line: usize,
    pub name: String,
}

impl Report {
    fn diagnostic(
        &mut self,
        line: usize,
        severity: &'static str,
        code: &'static str,
        message: &str,
        instruction: Option<&str>,
    ) {
        self.diagnostics.push(Diagnostic {
            line,
            severity,
            code,
            message: message.into(),
            instruction: instruction.map(str::to_owned),
        });
    }
}

/// Scan a caller-size-limited source. Passing means only no known policy issues.
pub fn scan(source: &str) -> Report {
    let mut report = Report {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION"),
        profile: "initial-planned",
        builder_ready: false,
        checks: "partial lexical checks only; image account lookup and full Dockerfile validation are not performed",
        scan_complete: true,
        policy_status: "no_known_policy_issues",
        diagnostics: Vec::new(),
        instructions: Vec::new(),
    };
    let mut escape = '\\';
    let mut directives = true;
    let mut escape_seen = false;
    let mut logical = String::new();
    let mut start = 0;
    let mut last = 0;
    let mut continued = false;
    let mut from_seen = false;
    for (index, physical) in source.lines().enumerate() {
        let line = index + 1;
        last = line;
        let text = physical.trim();
        if let Some(comment) = text.strip_prefix('#') {
            let comment = comment.trim();
            if directives && let Some((key, value)) = comment.split_once('=') {
                match key.trim().to_ascii_lowercase().as_str() {
                    "escape" => {
                        if escape_seen || !matches!(value.trim(), "\\" | "`") {
                            report.diagnostic(
                                line,
                                "error",
                                "invalid_escape_directive",
                                "Escape must be a single backslash or backtick, specified once.",
                                None,
                            );
                        } else {
                            escape = value.trim().chars().next().unwrap();
                        }
                        escape_seen = true;
                        continue;
                    }
                    "syntax" => {
                        report.diagnostic(line, "review", "external_frontend",
                            "External syntax frontends are outside the initial planned profile; their syntax is not validated.", None);
                        continue;
                    }
                    "check" => {
                        report.diagnostic(
                            line,
                            "review",
                            "check_directive",
                            "Frontend check directives are not implemented by this scanner.",
                            None,
                        );
                        continue;
                    }
                    _ => {}
                }
            }
            directives = false;
            continue;
        }
        directives = false;
        if text.is_empty() {
            continue;
        }
        if !continued {
            start = line;
        }
        let trailing = text.chars().rev().take_while(|&ch| ch == escape).count();
        continued = trailing == 1;
        logical.push_str(if continued {
            &text[..text.len() - escape.len_utf8()]
        } else {
            text
        });
        if continued {
            continue;
        }
        let (name, arguments) = split_instruction(&logical);
        let name = name.to_ascii_uppercase();
        report.instructions.push(Instruction {
            line: start,
            end_line: line,
            name: name.clone(),
        });
        if name == "FROM" {
            if from_seen {
                report.diagnostic(
                    start,
                    "review",
                    "multiple_stages",
                    "Multi-stage build behavior is not implemented or validated.",
                    Some(&name),
                );
            }
            from_seen = true;
        }
        if !from_seen && name != "ARG" && name != "FROM" {
            report.diagnostic(
                start,
                "error",
                "instruction_before_from",
                "Only global ARG instructions may precede the first FROM.",
                Some(&name),
            );
        }
        inspect(&mut report, start, &name, arguments);
        // shortcut: stop at any possible heredoc; use a real parser before accepting heredocs.
        if matches!(name.as_str(), "RUN" | "COPY" | "ADD" | "ONBUILD") && arguments.contains("<<") {
            report.diagnostic(start, "review", "heredoc_scan_stopped",
                "Possible heredoc is outside scanner support. Scanning stopped here; remaining lines were not inspected (including any USER instructions).", Some(&name));
            report.scan_complete = false;
            break;
        }
        logical.clear();
    }
    if continued && report.scan_complete {
        report.diagnostic(
            start,
            "error",
            "unterminated_continuation",
            "Instruction ends with a continuation but has no final line.",
            None,
        );
        let (name, arguments) = split_instruction(&logical);
        let name = name.to_ascii_uppercase();
        report.instructions.push(Instruction {
            line: start,
            end_line: last,
            name: name.clone(),
        });
        inspect(&mut report, start, &name, arguments);
        report.scan_complete = false;
    }
    if !from_seen && report.scan_complete {
        report.diagnostic(
            1,
            "error",
            "missing_from",
            "Dockerfile has no FROM instruction.",
            None,
        );
    }
    report.policy_status = if report.diagnostics.iter().any(|d| d.severity == "error") {
        "excluded_or_invalid"
    } else if !report.diagnostics.is_empty() || !report.scan_complete {
        "review_required"
    } else {
        "no_known_policy_issues"
    };
    report
}

fn split_instruction(text: &str) -> (&str, &str) {
    let boundary = text.find(char::is_whitespace).unwrap_or(text.len());
    (&text[..boundary], text[boundary..].trim())
}

fn inspect(report: &mut Report, line: usize, name: &str, arguments: &str) {
    if name == "USER" {
        match crate::build_plan::parse(&format!("FROM scratch\nUSER {arguments}")) {
            Err(error) => report.diagnostic(line, "error", "invalid_user", &error.message, Some(name)),
            Ok(_) if arguments.contains('$') => report.diagnostic(line, "review", "user_expansion",
                "USER supports basic ARG/ENV expansion; the evaluated identity requires build-time validation. Named accounts are resolved from the current image filesystem when needed.", Some(name)),
            Ok(_) => (),
        }
        return;
    }
    if ![
        "FROM",
        "RUN",
        "COPY",
        "ADD",
        "ARG",
        "ENV",
        "WORKDIR",
        "LABEL",
        "CMD",
        "ENTRYPOINT",
        "EXPOSE",
        "VOLUME",
        "STOPSIGNAL",
        "SHELL",
        "HEALTHCHECK",
        "ONBUILD",
    ]
    .contains(&name)
    {
        report.diagnostic(
            line,
            "error",
            "unknown_instruction",
            "Unknown or excluded instruction in the initial planned profile.",
            Some(name),
        );
        return;
    }
    if arguments.is_empty() {
        report.diagnostic(
            line,
            "error",
            "missing_arguments",
            "Instruction requires arguments.",
            Some(name),
        );
        return;
    }
    if name == "ONBUILD" {
        report.diagnostic(line, "review", "onbuild_partial",
            "ONBUILD trigger semantics and inherited triggers require review; only the nested instruction is checked.", Some(name));
        let (nested, rest) = split_instruction(arguments);
        let nested = nested.to_ascii_uppercase();
        if nested == "ONBUILD" {
            report.diagnostic(
                line,
                "error",
                "nested_onbuild",
                "ONBUILD cannot contain ONBUILD.",
                Some(name),
            );
        } else {
            inspect(report, line, &nested, rest);
        }
        return;
    }
    if name == "FROM" && arguments.starts_with("--") {
        match crate::build_plan::parse(&format!("FROM {arguments}")) {
            Err(e) => report.diagnostic(
                line,
                "error",
                "invalid_from_platform",
                &e.message,
                Some(name),
            ),
            Ok(plan) => {
                if let crate::build_plan::InstructionKind::From {
                    platform: Some(value),
                    ..
                } = &plan.stages[0].instructions[0].kind
                {
                    if value.contains('$') {
                        report.diagnostic(line, "review", "platform_expansion", "FROM platform uses global ARG expansion and requires build-time validation; only linux/amd64 is supported.", Some(name));
                    } else if let Err(e) = crate::build::normalize_platform(value) {
                        report.diagnostic(
                            line,
                            "error",
                            "invalid_from_platform",
                            &e.to_string(),
                            Some(name),
                        );
                    }
                }
            }
        }
    } else if arguments.starts_with("--") {
        report.diagnostic(line, "review", "instruction_flags",
            "This scanner does not validate instruction flags. The builder supports static COPY --from stages/images and --chmod/--chown within its documented profile; dynamic --from remains unsupported. Other flags require separate compatibility review.", Some(name));
    }
    let mut json_args = None;
    if ["RUN", "CMD", "ENTRYPOINT", "COPY", "ADD", "VOLUME", "SHELL"].contains(&name)
        && arguments.starts_with('[')
    {
        match serde_json::from_str::<Vec<String>>(arguments) {
            Ok(values) if !values.is_empty() => json_args = Some(values),
            _ => report.diagnostic(line, "error", "invalid_json_form",
                "JSON form must be a nonempty array of strings; full instruction arity is not checked.", Some(name)),
        }
    } else if name == "SHELL" {
        report.diagnostic(
            line,
            "error",
            "shell_requires_json",
            "SHELL requires a JSON array of strings.",
            Some(name),
        );
    }
    if name == "ADD" {
        let words: Vec<&str> = match &json_args {
            Some(values) => values.iter().map(String::as_str).collect(),
            None => arguments.split_whitespace().collect(),
        };
        if words.iter().any(|word| {
            let word = word.trim_matches(['\'', '"']).to_ascii_lowercase();
            word.contains("://") || word.starts_with("git@")
        }) {
            report.diagnostic(line, "review", "remote_add",
                "Remote ADD sources are outside the initial planned profile; downloads and Git sources are not implemented.", Some(name));
        }
    }
    if name == "FROM"
        && arguments
            .split_whitespace()
            .any(|word| word.eq_ignore_ascii_case("AS"))
    {
        report.diagnostic(
            line,
            "review",
            "stage_alias",
            "Named stages and multi-stage resolution are not validated by this scanner.",
            Some(name),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_platform_checks_static_values_and_defers_globals() {
        assert!(
            scan("FROM --platform=linux/x86_64 scratch")
                .diagnostics
                .is_empty()
        );
        assert!(has(
            &scan("FROM --platform=linux/arm64 scratch"),
            "invalid_from_platform",
            1
        ));
        assert!(has(
            &scan("FROM --platform= scratch"),
            "invalid_from_platform",
            1
        ));
        assert!(has(
            &scan("FROM --platform=$BUILDPLATFORM scratch"),
            "platform_expansion",
            1
        ));
    }

    fn has(report: &Report, code: &str, line: usize) -> bool {
        report
            .diagnostics
            .iter()
            .any(|d| d.code == code && d.line == line)
    }

    #[test]
    fn explicit_users_are_supported_with_physical_lines() {
        let report = scan("# comment\r\nFROM alpine\r\n\r\nuser root\r\nUSER app\r\n");
        assert!(report.diagnostics.is_empty());
        assert_eq!(report.instructions[1].line, 4);
        assert_eq!(report.instructions[2].line, 5);
        assert!(!report.builder_ready);
        assert_eq!(report.policy_status, "no_known_policy_issues");
    }

    #[test]
    fn continuations_and_shell_text_are_not_instructions() {
        let report = scan(
            "FROM alpine\nRUN echo USER \\\n  && echo 'USER root'\n# USER app\nUSER \\\n root\n",
        );
        assert_eq!(report.instructions.len(), 3);
        assert_eq!(report.instructions[2].line, 5);
        assert!(report.diagnostics.is_empty());
        assert_eq!(report.instructions[1].end_line, 3);
    }

    #[test]
    fn backtick_directive_and_external_frontend() {
        let report = scan(
            "# syntax=docker/dockerfile:1\n# escape=`\nFROM alpine\nRUN echo `\nUSER root\nUSER app\n",
        );
        assert!(has(&report, "external_frontend", 1));
        assert!(
            !report
                .instructions
                .iter()
                .any(|i| i.name == "USER" && i.line == 5)
        );
        assert_eq!(report.instructions.last().unwrap().line, 6);
        assert!(has(
            &scan("# escape=x\nFROM alpine"),
            "invalid_escape_directive",
            1
        ));
    }

    #[test]
    fn late_directives_are_comments_and_continued_comments_are_skipped() {
        let report = scan("\n# escape=`\nFROM alpine\nRUN echo `\nUSER root\n");
        assert_eq!(report.instructions.last().unwrap().line, 5);
        let report = scan("FROM alpine\nRUN echo \\\n# USER fake\n USER text\nUSER app");
        assert_eq!(report.instructions.len(), 3);
        assert!(
            !report
                .instructions
                .iter()
                .any(|i| i.name == "USER" && i.line == 4)
        );
        assert_eq!(report.instructions.last().unwrap().line, 5);
    }

    #[test]
    fn invalid_and_empty_sources() {
        assert!(has(&scan("# empty\n"), "missing_from", 1));
        assert!(has(&scan("RUN echo hi"), "instruction_before_from", 1));
        assert!(has(
            &scan("FROM alpine\nBOGUS thing"),
            "unknown_instruction",
            2
        ));
        assert!(has(
            &scan("FROM alpine\nCMD [\"hi\",]"),
            "invalid_json_form",
            2
        ));
        assert!(has(
            &scan("FROM alpine\nUSER \\"),
            "unterminated_continuation",
            2
        ));
        assert!(has(&scan("FROM alpine\nUSER \\"), "invalid_user", 2));
    }

    #[test]
    fn advanced_features_require_review() {
        for instruction in [
            "RUN --mount=type=cache echo hi",
            "RUN --network=host true",
            "RUN --security=insecure true",
            "COPY --from=base /a /b",
            "COPY --link a b",
            "COPY --parents a b",
        ] {
            assert!(has(
                &scan(&format!("FROM alpine\n{instruction}")),
                "instruction_flags",
                2
            ));
        }
        assert!(has(
            &scan("FROM alpine\nADD [\"https://example.org/a\", \"/a\"]"),
            "remote_add",
            2
        ));
        assert!(has(
            &scan("FROM alpine\nONBUILD USER root"),
            "onbuild_partial",
            2
        ));
    }

    #[test]
    fn heredoc_body_is_never_reported_as_instructions() {
        let report = scan("FROM alpine\nRUN <<EOF\nUSER root\nEOF\nUSER app\n");
        assert!(!report.scan_complete);
        assert_eq!(report.policy_status, "review_required");
        assert_eq!(report.instructions.len(), 2);
        assert!(has(&report, "heredoc_scan_stopped", 2));
        assert!(!report.instructions.iter().any(|i| i.name == "USER"));
    }

    #[test]
    fn user_validation_matches_parser_and_defers_expansion() {
        for spec in ["app", "123", "app:team", "123:456", "app:456", "123:team"] {
            assert!(
                scan(&format!("FROM scratch\nUSER {spec}"))
                    .diagnostics
                    .is_empty()
            );
        }
        for spec in [
            "",
            "app:",
            ":team",
            "app:team:extra",
            "app team",
            "2147483648",
        ] {
            assert!(has(
                &scan(&format!("FROM scratch\nUSER {spec}")),
                "invalid_user",
                2
            ));
        }
        assert!(has(
            &scan("FROM scratch\nARG WHO=app\nUSER $WHO"),
            "user_expansion",
            3
        ));
    }

    #[test]
    fn plain_profile_is_not_builder_readiness() {
        let report = scan("ARG BASE=alpine\nFROM alpine\nRUN echo USER\nCMD [\"sh\"]");
        assert_eq!(report.policy_status, "no_known_policy_issues");
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["builder_ready"], false);
        assert_eq!(json["schema_version"], 1);
    }
}
