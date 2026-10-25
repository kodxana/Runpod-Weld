//! Public API boundary checks; real process paths are in store_lease_integration.py.
#![cfg(target_os = "linux")]
use rpweld::{store_access, store_lease::StoreLease};
use std::{fs, os::unix::fs::symlink};

#[test]
fn managed_aliases_missing_outputs_and_cross_store_are_checked() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let lease = StoreLease::shared(a.path(), &|| false).unwrap();
    let _other = StoreLease::shared(b.path(), &|| false).unwrap();
    let output = a.path().join("new/partial/image");
    assert!(store_access::validate_path(&output, None).is_err());
    store_access::validate_path(&output, Some(&lease)).unwrap();
    assert!(store_access::validate_path(b.path(), Some(&lease)).is_err());
    let outside = tempfile::tempdir().unwrap();
    symlink(a.path(), outside.path().join("alias")).unwrap();
    assert!(store_access::validate_path(&outside.path().join("alias/new"), None).is_err());
    store_access::validate_path(&outside.path().join("alias/new"), Some(&lease)).unwrap();
    fs::write(outside.path().join("Dockerfile"), "FROM scratch").unwrap();
    store_access::validate_path(&outside.path().join("Dockerfile"), None).unwrap();
    assert!(rpweld::registry::tagged_image(b.path(), &lease, "example/x:latest").is_err());
    assert!(
        rpweld::registry::save_tag(b.path(), &lease, "example/x:latest", outside.path()).is_err()
    );
}

#[test]
fn hidden_parser_rejects_invalid_descriptors_and_syntax() {
    for args in [
        vec![],
        vec!["0", "--", "/bin/true"],
        vec!["2", "--", "/bin/true"],
        vec!["-3", "--", "/bin/true"],
        vec!["+3", "--", "/bin/true"],
        vec!["999999999999", "--", "/bin/true"],
        vec!["3", "missing-separator"],
        vec!["3", "--"],
        vec!["3", "--", ""],
    ] {
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .arg("__lease-guard")
            .args(args)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(125));
    }
}

#[test]
fn explicit_managed_paths_acquire_current_store_and_reject_other_stores() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("store");
    fs::create_dir(&store).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(context.join("Dockerfile"), "FROM scratch\n").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .env("HOME", temp.path())
        .env("RPWELD_HOME", &store)
        .args(["build", "--work-dir"])
        .arg(store.join("explicit-work"))
        .arg("--output")
        .arg(store.join("explicit-image"))
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(store.join("store.lock").is_file());
    assert!(
        StoreLease::try_exclusive_existing(&store)
            .unwrap()
            .is_some()
    );

    let other = tempfile::tempdir().unwrap();
    let _lease = StoreLease::shared(other.path(), &|| false).unwrap();
    fs::write(context.join("Dockerfile"), "FROM local\n").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .env("HOME", temp.path())
        .env("RPWELD_HOME", &store)
        .args(["build", "--work-dir"])
        .arg(temp.path().join("rejected-work"))
        .arg("--output")
        .arg(temp.path().join("rejected-image"))
        .arg("--base")
        .arg(format!("local={}", other.path().display()))
        .arg(&context)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cross-store"));
    assert!(!temp.path().join("rejected-work").exists());
}

#[test]
fn managed_dockerfile_is_rejected_across_stores_before_reading() {
    let home = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let _lease = StoreLease::shared(other.path(), &|| false).unwrap();
    // Invalid content would produce a parser error if opened before validation.
    let dockerfile = other.path().join("Dockerfile");
    fs::write(&dockerfile, [255]).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .env("HOME", home.path())
        .env("RPWELD_HOME", home.path().join("store"))
        .args(["build", "-f"])
        .arg(&dockerfile)
        .arg(home.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cross-store"));
}

#[test]
fn malformed_marker_never_downgrades_a_store_to_unmanaged() {
    let store = tempfile::tempdir().unwrap();
    symlink("missing-lock-target", store.path().join("store.lock")).unwrap();
    assert!(store_access::validate_path(&store.path().join("image"), None).is_err());
    let other = tempfile::tempdir().unwrap();
    let lease = StoreLease::shared(other.path(), &|| false).unwrap();
    assert!(store_access::validate_path(&store.path().join("image"), Some(&lease)).is_err());
    assert!(StoreLease::shared(store.path(), &|| false).is_err());
}
