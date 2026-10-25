use rpweld::{build_plan, dockerfile};

#[test]
fn scanner_understands_only_validated_backward_stages() {
    let source = "FROM alpine AS base\nFROM base AS final\nCOPY --from=base /a /b\n";
    assert!(dockerfile::scan(source).diagnostics.is_empty());
    for source in [
        "FROM alpine AS base\nCOPY --from=base /a /b",
        "FROM alpine\nCOPY --from=later /a /b\nFROM alpine AS later",
        "FROM alpine AS base\nFROM alpine\nCOPY --from=$STAGE /a /b",
        "FROM alpine AS base\nFROM alpine\nCOPY --from=base --link /a /b",
        "FROM alpine AS base\nFROM alpine\nCOPY --from=external /a /b",
        "FROM alpine AS base\nFROM alpine AS base",
        "ARG BASE=alpine\nFROM $BASE AS base\nFROM base",
        "FROM later AS base\nFROM alpine AS later",
    ] {
        assert!(!dockerfile::scan(source).diagnostics.is_empty(), "{source}");
    }
    let pinned = dockerfile::scan(include_str!("fixtures/optional-secret/Dockerfile.nemotron"));
    assert_eq!(pinned.diagnostics.len(), 1, "{:?}", pinned.diagnostics);
    assert_eq!(pinned.diagnostics[0].code, "optional_absent_secret");
}

#[test]
fn optional_absent_secret_parse() {
    build_plan::parse("# syntax=docker/dockerfile:1\nFROM scratch\nRUN --mount=type=secret,id=HF_TOKEN,required=false test ! -e /run/secrets/HF_TOKEN\nCMD []\n").unwrap();
}

#[test]
fn pinned_nemotron_dockerfile_parses_before_target_selection() {
    let source = include_str!("fixtures/optional-secret/Dockerfile.nemotron");
    let plan = build_plan::parse(source).unwrap();
    assert_eq!(plan.stages.len(), 3);
    assert_eq!(plan.stages[0].name.as_deref(), Some("runtime-base"));
    let run = &plan.stages[1].instructions[2];
    assert_eq!(run.absent_secret.as_deref(), Some("HF_TOKEN"));
    assert!(
        matches!(&run.kind, build_plan::InstructionKind::Run(build_plan::Run::Shell(command)) if command.starts_with("python3 scripts/bake_models.py"))
    );
    let report = dockerfile::scan(source);
    assert!(report.scan_complete);
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.severity == "error" || d.code == "external_frontend")
    );
}

#[test]
fn secret_exec_and_heredoc_preserve_payloads() {
    for command in ["[\"sh\",\"-c\",\"true\"]", "<<EOF\necho true\nEOF"] {
        let source = format!(
            "FROM scratch\nRUN --mount=required=false,id=other-token,type=secret {command}\n"
        );
        let plan = build_plan::parse(&source).unwrap();
        assert_eq!(
            plan.stages[0].instructions[1].absent_secret.as_deref(),
            Some("other-token")
        );
        assert!(dockerfile::scan(&source).scan_complete);
    }
    for source in [
        "FROM scratch\n# syntax=docker/dockerfile:1",
        "# syntax=docker/dockerfile:1\n# syntax=docker/dockerfile:1\nFROM scratch",
    ] {
        assert!(build_plan::parse(source).is_err());
    }
}

#[test]
fn empty_cmd_is_valid_in_scanner() {
    let report = dockerfile::scan("# syntax=docker/dockerfile:1\r\nFROM scratch\r\nCMD []\r\n");
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.code == "invalid_json_form" || d.code == "external_frontend")
    );
}

#[test]
fn invalid_secret_profiles_rejected() {
    for flag in [
        "--mount=type=cache,id=HF_TOKEN,required=false",
        "--mount=type=secret,id=HF_TOKEN,required=true",
        "--mount=type=secret,id=HF_TOKEN",
        "--mount=type=secret,id=../HF_TOKEN,required=false",
        "--mount=type=secret,id=/HF_TOKEN,required=false",
        "--mount=type=secret,id=HF.TOKEN,required=false",
        "--mount=type=secret,id=,required=false",
        "--mount=type=secret,id=HF_TOKEN,required=false,target=/tmp/token",
        "--mount=type=secret,id=HF_TOKEN,required=false,env=HF_TOKEN",
        "--mount=type=secret,id=HF_TOKEN,required=false,from=base",
        "--mount=type=secret,id=HF_TOKEN,required=false,",
        "--mount=type=secret,id=HF_TOKEN,id=OTHER,required=false",
        "--mount=type=secret,id=HF_TOKEN,required=false --mount=type=secret,id=X,required=false",
        "--mount type=secret,id=HF_TOKEN,required=false",
    ] {
        assert!(
            build_plan::parse(&format!("FROM scratch\nRUN {flag} true\n")).is_err(),
            "{flag}"
        );
    }
    for directive in [
        "docker/dockerfile:1.7",
        "docker/dockerfile:latest",
        "custom/frontend:1",
        "docker/dockerfile:1 ",
    ] {
        assert!(build_plan::parse(&format!("# syntax={directive}\nFROM scratch\n")).is_err());
    }
}
