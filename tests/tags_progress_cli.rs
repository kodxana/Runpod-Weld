#[cfg(target_os = "linux")]
use std::fs;
use std::process::Command;

fn cli(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
    cmd.env("HOME", home).env("RPWELD_HOME", home.join("store"));
    cmd
}

#[test]
fn all_options_are_validated_before_reading_source() {
    let home = tempfile::tempdir().unwrap();
    for options in [
        vec!["-t", "valid", "--tag=INVALID"],
        vec!["--progress=invalid"],
    ] {
        let result = cli(home.path())
            .args(["build", "-f", "absent"])
            .args(options)
            .arg(".")
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("absent"));
        assert!(!home.path().join("store").exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn multiple_tags_progress_cache_and_failure_preservation() {
    let home = tempfile::tempdir().unwrap();
    let context = home.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY payload /payload\nENV TOKEN=do-not-print-this\n",
    )
    .unwrap();
    fs::write(context.join("payload"), "one").unwrap();
    let run = |mode: &str, push: bool| {
        let mut cmd = cli(home.path());
        cmd.args([
            "build",
            "-t",
            "localhost:1/test/a",
            "--tag=localhost:1/test/b:v2",
            "--tag",
            "localhost:1/test/a:latest",
            "--progress",
            mode,
        ]);
        if push {
            cmd.arg("--push");
        }
        cmd.arg(&context).output().unwrap()
    };
    let cold = run("plain", false);
    assert!(
        cold.status.success(),
        "{}",
        String::from_utf8_lossy(&cold.stderr)
    );
    let logs = String::from_utf8_lossy(&cold.stderr);
    assert!(
        logs.contains("[stage 1 instruction 2] COPY START"),
        "{logs}"
    );
    assert!(logs.contains("COPY DONE ") && logs.contains("Stage 1/1: DONE "));
    assert!(!logs.contains("do-not-print-this") && !logs.contains('\r'));
    let records = || {
        let mut records: Vec<_> = fs::read_dir(home.path().join("store"))
            .unwrap()
            .map(|p| p.unwrap().path())
            .filter(|p| {
                p.extension().is_some_and(|ext| ext == "json")
                    && p.file_name().unwrap().to_string_lossy().starts_with("tag-")
            })
            .map(|p| fs::read(p).unwrap())
            .collect();
        records.sort();
        records
    };
    let tags = records();
    assert_eq!(tags.len(), 2);
    let a: serde_json::Value = serde_json::from_slice(&tags[0]).unwrap();
    let b: serde_json::Value = serde_json::from_slice(&tags[1]).unwrap();
    assert_eq!(a["image"], b["image"]);
    let cache_entries = || {
        let mut entries: Vec<_> = fs::read_dir(home.path().join("store/cache-v1"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        entries
    };
    let before_quiet = cache_entries();
    let quiet = run("quiet", false);
    assert!(quiet.status.success());
    assert_eq!(
        cache_entries(),
        before_quiet,
        "presentation must not add cache identities"
    );
    assert!(
        quiet.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    let warm = run("auto", false);
    assert!(warm.status.success());
    assert!(String::from_utf8_lossy(&warm.stderr).contains("CACHED (verified local stage"));
    // An offline failure for the first destination must not prevent the second attempt.
    let failed_push = run("quiet", true);
    assert!(!failed_push.status.success());
    let out = String::from_utf8_lossy(&failed_push.stdout);
    assert!(
        out.contains("Push failed for localhost:1/test/a:latest"),
        "{out}"
    );
    assert!(
        out.contains("Push failed for localhost:1/test/b:v2"),
        "{out}"
    );
    let saved = records();
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY missing /payload\n",
    )
    .unwrap();
    let failed = run("quiet", false);
    assert!(!failed.status.success());
    let error = String::from_utf8_lossy(&failed.stderr);
    assert!(
        error.contains("rpweld:") && !error.contains("Stage "),
        "{error}"
    );
    assert_eq!(records(), saved);
}
#[cfg(target_os = "linux")]
#[test]
fn selected_stages_keep_dockerfile_numbers_and_metadata_gaps() {
    let home = tempfile::tempdir().unwrap();
    let context = home.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(context.join("payload"), "test").unwrap();
    fs::write(context.join("Dockerfile"), "ARG UNUSED=private\nFROM scratch AS skipped\nRUN must-not-run\nFROM scratch AS selected\nENV TOKEN=private\nCOPY payload /payload\nFROM scratch AS later\nRUN must-not-run\n").unwrap();
    let result = cli(home.path())
        .args(["build", "--target", "selected", "--progress=plain"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let log = String::from_utf8_lossy(&result.stderr);
    assert!(log.contains("Stage 2/3: START") && log.contains("[stage 2 instruction 1] FROM START"));
    assert!(log.contains("[stage 2 instruction 3] COPY START"));
    assert!(!log.contains("Stage 1/") && !log.contains("Stage 3/") && !log.contains("private"));
}
