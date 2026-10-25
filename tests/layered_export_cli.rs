#![cfg(target_os = "linux")]

use std::{path::PathBuf, process::Command};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/layered-export")
        .join(name)
}

#[test]
fn export_mode_rejects_unknown_values_before_opening_sources() {
    let help = Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .args(["build", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--export-mode"));
    let result = Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .args([
            "build",
            "--export-mode",
            "unknown",
            "-f",
            "does-not-exist",
            ".",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("export-mode"), "{error}");
    assert!(!error.contains("unknown build option"), "{error}");
}

#[test]
#[ignore = "requires Linux root, Python3 and GNU tar with xattr support"]
fn independent_replay_oracle_self_test() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let result = Command::new("python3")
        .arg(fixture("oracle.py"))
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
}

#[test]
#[ignore = "run only after stable handoff; Linux root, RPWELD_TEST_LAYOUT and RPWELD_LAYERED_EVIDENCE required"]
fn layered_export_preserves_base_and_delivered_filesystem() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let mut command = Command::new("python3");
    command
        .arg(fixture("acceptance.py"))
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_rpweld"))
        .arg("--layout")
        .arg(std::env::var_os("RPWELD_TEST_LAYOUT").expect("offline Alpine OCI required"))
        .arg("--evidence")
        .arg(
            std::env::var_os("RPWELD_LAYERED_EVIDENCE")
                .expect("new native Linux evidence path required"),
        );
    if std::env::var_os("RPWELD_LAYERED_DOCKER").is_some() {
        command.arg("--docker");
    }
    let status = command.status().unwrap();
    assert!(status.success());
}
