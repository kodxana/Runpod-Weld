use rpweld::{build_plan, dockerfile};

#[test]
fn bodies_preserve_bytes_and_physical_locations() {
    let source = "FROM scratch\r\nCOPY <<-E'O'F /out\r\n\t'$X'\r\n\t\r\n\tEOF\r\nUSER 1234\r\nRUN <<END\n# body comment\necho hi\\\nnext\nEND\n";
    let plan = build_plan::parse(source).unwrap();
    let instructions = &plan.stages[0].instructions;
    let doc = instructions[1].heredoc.as_ref().unwrap();
    assert!(!doc.expand);
    assert_eq!(doc.body, "'$X'\r\n\r\n");
    assert_eq!((instructions[1].line, instructions[1].end_line), (2, 5));
    assert_eq!(instructions[2].line, 6);
    assert_eq!(
        instructions[3].heredoc.as_ref().unwrap().body,
        "# body comment\necho hi\\\nnext\n"
    );
    let report = dockerfile::scan(source);
    assert!(report.scan_complete);
    assert_eq!(report.instructions.len(), 4);
    assert_eq!(report.instructions[2].line, 6);
    assert_eq!(
        build_plan::parse("FROM scratch\nCOPY <<EOF /x\nx\nEOF\nBOGUS x\n")
            .unwrap_err()
            .line,
        5
    );
    let error = build_plan::parse("FROM scratch\n\nCOPY <<EOF /x\nx\n").unwrap_err();
    assert_eq!(error.line, 3);
    assert!(error.message.contains("unterminated heredoc"));
}

#[test]
fn unsupported_profiles_fail_closed() {
    for header in [
        "RUN <<EOF cat",
        "RUN cat <<EOF",
        "RUN 3<<EOF",
        "RUN <<EOF <<OTHER",
        "COPY <<EOF local /x/",
        "COPY <<EOF <<OTHER /x/",
        "COPY --from=base <<EOF /x",
        "ADD <<EOF /x",
        "RUN <<../EOF",
        "RUN <<'E O F'",
        "RUN echo '<<literal'",
    ] {
        assert!(
            build_plan::parse(&format!("FROM scratch\n{header}\nx\nEOF\n")).is_err(),
            "{header}"
        );
        assert!(
            !dockerfile::scan(&format!("FROM scratch\n{header}\nx\nEOF\nUSER root")).scan_complete,
            "{header}"
        );
    }
    assert!(
        build_plan::parse("FROM scratch\nRUN <<EOF\n#!/bin/sh\necho hi\nEOF\n")
            .unwrap_err()
            .message
            .contains("shebang")
    );
    assert!(
        build_plan::parse(&format!(
            "FROM scratch\nCOPY <<EOF /x\n{}\nEOF",
            "x".repeat(build_plan::MAX_LINE_BYTES + 1)
        ))
        .is_err()
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{fs, os::unix::fs::MetadataExt, path::PathBuf, process::Command};

    struct Project {
        temp: tempfile::TempDir,
        context: PathBuf,
        serial: usize,
    }
    impl Project {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let context = temp.path().join("context");
            fs::create_dir(&context).unwrap();
            // Inline sources must not be filtered through the local context.
            fs::write(context.join(".dockerignore"), "*\n").unwrap();
            Self {
                temp,
                context,
                serial: 0,
            }
        }
        fn build(&mut self, source: &str, extra: &[&str]) -> (bool, String, PathBuf) {
            self.serial += 1;
            fs::write(self.context.join("Dockerfile"), source).unwrap();
            let work = self.temp.path().join(format!("work-{}", self.serial));
            let output = self.temp.path().join(format!("image-{}", self.serial));
            let result = Command::new(env!("CARGO_BIN_EXE_rpweld"))
                .env("RPWELD_HOME", self.temp.path().join("store"))
                .args(["build", "-t", "heredoc:test", "--work-dir"])
                .arg(&work)
                .arg("--output")
                .arg(output)
                .args(extra)
                .arg(&self.context)
                .output()
                .unwrap();
            (
                result.status.success(),
                String::from_utf8_lossy(&result.stderr).into_owned(),
                work.join("rootfs"),
            )
        }
    }

    #[test]
    fn inline_copy_expansion_metadata_and_cache_invalidation() {
        let mut p = Project::new();
        let source = "FROM scratch\nARG X=argument\nENV X=environment\nCOPY --chmod=0751 --chown=1234:2345 <<EOF /expanded\n'$X' \"${X}\" \\$X\nEOF\nCOPY <<'EOF' /literal\n$X\nEOF\nCOPY <<EOF /crlf\r\nbytes\r\nEOF\r\n";
        for serial in 0..3 {
            let extra: &[&str] = if serial == 2 { &["--no-cache"] } else { &[] };
            let (ok, log, root) = p.build(source, extra);
            assert!(ok, "{log}");
            assert_eq!(
                fs::read(root.join("expanded")).unwrap(),
                b"'environment' \"environment\" $X\n"
            );
            assert_eq!(fs::read(root.join("literal")).unwrap(), b"$X\n");
            assert_eq!(fs::read(root.join("crlf")).unwrap(), b"bytes\r\n");
            let m = fs::metadata(root.join("expanded")).unwrap();
            assert_eq!(
                (m.mode() & 0o7777, m.uid(), m.gid(), m.mtime()),
                (0o751, 1234, 2345, 0)
            );
            let m = fs::metadata(root.join("literal")).unwrap();
            assert_eq!(
                (m.mode() & 0o7777, m.uid(), m.gid(), m.mtime()),
                (0o644, 0, 0, 0)
            );
            if serial == 1 {
                assert!(log.contains("CACHED"), "{log}");
            }
        }
        let (ok, log, root) = p.build(&source.replace("bytes\r\n", "changed\r\n"), &[]);
        assert!(ok, "{log}");
        assert!(log.contains("CACHED instruction 4 COPY"), "{log}");
        assert_eq!(fs::read(root.join("crlf")).unwrap(), b"changed\r\n");
        let (ok, log, root) = p.build(&source.replace("X=environment", "X=updated"), &[]);
        assert!(ok, "{log}");
        assert_eq!(
            fs::read(root.join("expanded")).unwrap(),
            b"'updated' \"updated\" $X\n"
        );
    }

    #[test]
    fn cached_inline_prefix_charges_bytes_before_next_copy() {
        let mut p = Project::new();
        let source = "FROM scratch\nCOPY <<EOF /out\n12345\nEOF\n";
        let (ok, log, _) = p.build(source, &["--max-rootfs-bytes", "10"]);
        assert!(ok, "{log}");
        let source = format!("{source}COPY <<EOF /out\n67890\nEOF\n");
        for extra in [
            vec!["--max-rootfs-bytes", "10"],
            vec!["--max-rootfs-bytes", "10", "--no-cache"],
        ] {
            let (ok, log, _) = p.build(&source, &extra);
            assert!(!ok, "{log}");
            if extra.len() == 2 {
                assert!(log.contains("CACHED instruction 2 COPY"), "{log}");
            }
        }
    }
}
