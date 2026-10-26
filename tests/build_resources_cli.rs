#![cfg(target_os = "linux")]
use std::{fs, os::unix::process::CommandExt, process::Command};

fn command(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
    cmd.env("HOME", home).env("RPWELD_HOME", home.join("store"));
    cmd
}

#[test]
fn automatic_and_explicit_origins_are_reported_even_when_progress_is_quiet() {
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(context.join("Dockerfile"), "FROM scratch\n").unwrap();
    let result = command(temp.path())
        .args([
            "build",
            "-t",
            "test/resources",
            "--progress",
            "quiet",
            "--max-rootfs-bytes",
            "1234",
            "--max-layer-bytes",
            "1048576",
            "--max-entries",
            "32",
            "--metadata-budget",
            "1048576",
        ])
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let out = String::from_utf8_lossy(&result.stdout);
    for value in [
        "rootfs=1234 (explicit)",
        "layer/replay=1048576 (explicit)",
        "entries=32 (explicit)",
        "logical metadata=1048576 (explicit)",
        "quota unknown",
        "Logical metadata is not RSS",
    ] {
        assert!(out.contains(value), "{out}");
    }
    let result = command(temp.path())
        .args(["build", "-t", "test/resources", "--progress", "quiet"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.lines()
            .find(|s| s.starts_with("Build resources:"))
            .unwrap()
            .matches("(auto)")
            .count()
            == 4
    );
}

#[test]
fn fd_preflight_refuses_before_creating_store_work_or_auth_state() {
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    // An unresolved registry base demonstrates refusal precedes transport, too.
    fs::write(context.join("Dockerfile"), "FROM example.invalid/base\n").unwrap();
    let mut cmd = command(temp.path());
    unsafe {
        cmd.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 200,
                rlim_max: 200,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let result = cmd
        .args(["build", "-t", "test/refusal"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(
        error.contains("build preflight")
            && error.contains("available 200")
            && error.contains("RLIMIT_NOFILE hard"),
        "{error}"
    );
    assert!(!temp.path().join("store").exists());
    assert!(!temp.path().join(".config").exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn entry_flags_are_positive_unique_and_validated_before_source_or_state() {
    for flags in [
        vec!["--max-entries", "0"],
        vec!["--max-entries", "18446744073709551616"],
        vec!["--max-entries", "1", "--max-entries", "2"],
    ] {
        let temp = tempfile::tempdir().unwrap();
        let result = command(temp.path())
            .args(["build", "-t", "test/refusal", "-f", "absent"])
            .args(flags)
            .arg(".")
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("--max-entries"));
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }
}
