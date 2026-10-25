use rpweld::{
    build_plan::{self, InstructionKind},
    dockerfile,
};
use serde_json::json;

#[test]
fn healthcheck_encoding_and_bounds() {
    let plan = build_plan::parse("FROM scratch\nHEALTHCHECK --interval=1h2m3.004s --timeout=+1.5ms --start-period=0 --start-interval=1000µs --retries=+3 CMD echo $VALUE || exit 1\n").unwrap();
    let InstructionKind::Healthcheck(health) = &plan.stages[0].instructions[1].kind else {
        panic!()
    };
    assert_eq!(
        serde_json::to_value(health).unwrap(),
        json!({
            "Test": ["CMD-SHELL", "echo $VALUE || exit 1"], "Interval":3723004000000i64,
            "Timeout":1500000, "StartInterval":1000000, "Retries":3
        })
    );
    for (duration, expected) in [
        ("9223372036854775807ns", i64::MAX),
        ("2562047h47m16.854775807s", i64::MAX),
        (".001s", 1000000),
        ("1.s", 1000000000),
        ("0.9ns", 0),
        ("", 0),
        ("0", 0),
    ] {
        let plan = build_plan::parse(&format!(
            "FROM scratch\nHEALTHCHECK --interval={duration} CMD [\"true\",\"$X\"]"
        ))
        .unwrap();
        let InstructionKind::Healthcheck(h) = &plan.stages[0].instructions[1].kind else {
            panic!()
        };
        assert_eq!(h.interval, expected, "{duration}");
        assert_eq!(h.test, ["CMD", "true", "$X"]);
    }
    let plan = build_plan::parse("FROM scratch\nHEALTHCHECK none").unwrap();
    let InstructionKind::Healthcheck(h) = &plan.stages[0].instructions[1].kind else {
        panic!()
    };
    assert_eq!(serde_json::to_value(h).unwrap(), json!({"Test":["NONE"]}));
}

#[test]
fn invalid_metadata_has_physical_lines_and_scanner_diagnostics() {
    for instruction in [
        "HEALTHCHECK",
        "HEALTHCHECK CMD",
        "HEALTHCHECK CMD []",
        "HEALTHCHECK CMD [\"x\",]",
        "HEALTHCHECK CMD [1]",
        "HEALTHCHECK CMD [\"\\u0000\"]",
        "HEALTHCHECK NONE extra",
        "HEALTHCHECK --timeout=1s NONE",
        "HEALTHCHECK --unknown=1 CMD true",
        "HEALTHCHECK --interval 1s CMD true",
        "HEALTHCHECK --interval=1s --interval=2s CMD true",
        "HEALTHCHECK --retries=-1 CMD true",
        "HEALTHCHECK --retries=2147483648 CMD true",
        "HEALTHCHECK --interval=$X CMD true",
        "HEALTHCHECK --interval=9223372036854775808ns CMD true",
        "HEALTHCHECK --interval=2562047h47m16.854775808s CMD true",
        "HEALTHCHECK --interval=999us CMD true",
        "HEALTHCHECK --interval=-1s CMD true",
        "HEALTHCHECK --interval=+ CMD true",
        "HEALTHCHECK --interval=1.2.3s CMD true",
        "HEALTHCHECK --interval=1d CMD true",
        "HEALTHCHECK --interval=10 CMD true",
        "HEALTHCHECK CMD-SHELL true",
        "STOPSIGNAL",
        "STOPSIGNAL 0",
        "STOPSIGNAL SIGBOGUS",
        "STOPSIGNAL TERM KILL",
        "STOPSIGNAL 9223372036854775808",
        "STOPSIGNAL SIGRTMIN+16",
        "STOPSIGNAL SIGRTMAX-15",
        "STOPSIGNAL --bad=TERM",
    ] {
        let source = format!("# comment\nFROM scratch\n{instruction}\n");
        assert_eq!(
            build_plan::parse(&source).unwrap_err().line,
            3,
            "{instruction}"
        );
        let report = dockerfile::scan(&source);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.line == 3 && d.code == "invalid_runtime_metadata"),
            "{instruction}"
        );
    }
    assert_eq!(
        build_plan::parse("FROM scratch\nHEALTHCHECK --interval=1s \\\n --timeout=999us CMD true")
            .unwrap_err()
            .line,
        2
    );
}

#[test]
fn signal_syntax_and_expansion_deferral() {
    for signal in [
        "TERM",
        "sigterm",
        "SIGIOT",
        "SIGRTMIN+15",
        "RTMAX-14",
        "15",
        "+15",
        "-1",
        "9223372036854775807",
        "\"SIGTERM\"",
    ] {
        let source = format!("FROM scratch\nSTOPSIGNAL {signal}");
        build_plan::parse(&source).unwrap();
        assert!(dockerfile::scan(&source).diagnostics.is_empty());
    }
    let report = dockerfile::scan("FROM scratch\nSTOPSIGNAL ${SIGNAL}");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == "stopsignal_expansion")
    );
    assert!(
        dockerfile::scan("FROM scratch\nHEALTHCHECK --interval=1s CMD echo $X")
            .diagnostics
            .is_empty()
    );
}
