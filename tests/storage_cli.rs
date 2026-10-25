#![cfg(target_os = "linux")]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{PermissionsExt, symlink},
    },
    path::Path,
    process::{Command, Output},
};

fn run(home: &Path, explicit: bool, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rpweld"));
    command.env("HOME", home).env_remove("RPWELD_HOME");
    if explicit {
        command.env("RPWELD_HOME", home.join("store"));
    }
    command.args(args).output().unwrap()
}
fn report(home: &Path, args: &[&str]) -> Value {
    let result = run(home, true, args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}
fn tag(store: &Path, reference: &str, image: &Path) {
    let path = store.join(format!(
        "tag-{:x}.json",
        Sha256::digest(reference.as_bytes())
    ));
    fs::write(
        &path,
        serde_json::to_vec(&json!({"reference": reference, "image": image})).unwrap(),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn assert_safe_text(output: Output) -> String {
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        !text
            .bytes()
            .any(|b| b.is_ascii_control() && !matches!(b, b'\n' | b'\t'))
    );
    text
}

#[test]
fn non_utf8_store_paths_and_nested_issues_are_lossless() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp
        .path()
        .join(std::ffi::OsString::from_vec(b"home-\xff".to_vec()));
    let store = home.join("store");
    for exists in [false, true] {
        if exists {
            fs::create_dir_all(store.join("build-old")).unwrap();
            fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
            for name in [
                b"bad-\xff".as_slice(),
                b"bad-\xfe",
                "bad-\u{fffd}".as_bytes(),
            ] {
                symlink(
                    "missing",
                    store
                        .join("build-old")
                        .join(std::ffi::OsString::from_vec(name.to_vec())),
                )
                .unwrap();
            }
        }
        for args in [
            vec!["images"],
            vec!["cache", "ls"],
            vec!["cache", "du"],
            vec!["builds", "ls"],
        ] {
            let mut json_args = args.clone();
            json_args.push("--json");
            let value = report(&home, &json_args);
            assert_eq!(
                value["store"],
                json!({"unix_bytes": store.as_os_str().as_bytes()})
            );
            assert_eq!(value["status"], if exists { "present" } else { "missing" });
            if exists {
                let paths: Vec<_> = value["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v["path"].clone())
                    .collect();
                assert!(paths.contains(&json!({"unix_bytes": b"build-old/bad-\xff".as_slice()})));
                assert!(paths.contains(&json!({"unix_bytes": b"build-old/bad-\xfe".as_slice()})));
                assert!(paths.contains(&json!("build-old/bad-\u{fffd}")));
            } else {
                assert!(!home.exists());
            }
            assert_safe_text(run(&home, true, &args));
        }
    }
    let build = report(&home, &["builds", "inspect", "build-old", "--json"]);
    assert_eq!(build["data"]["build"]["path"], "build-old");
}

#[test]
fn missing_stores_are_empty_without_creating_anything() {
    let temp = tempfile::tempdir().unwrap();
    for explicit in [false, true] {
        for args in [
            vec!["images", "--json"],
            vec!["cache", "ls", "--json"],
            vec!["cache", "du", "--json"],
            vec!["builds", "ls", "--json"],
        ] {
            let output = run(temp.path(), explicit, &args);
            assert!(output.status.success(), "{:?}", output);
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["schema_version"], 1);
            assert_eq!(value["status"], "missing");
            assert_eq!(value["best_effort"], true);
            assert_eq!(value["partial"], false);
            assert!(value["issues"].as_array().unwrap().is_empty());
            assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        }
        for args in [
            vec!["image", "inspect", "alpine", "--json"],
            vec!["builds", "inspect", "build-missing", "--json"],
        ] {
            let output = run(temp.path(), explicit, &args);
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("not found"));
            assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        }
    }
}

#[test]
fn seeded_inventory_preserves_unknowns_and_never_reads_external_or_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("store");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let external = temp.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("secret"), "EXTERNAL_CANARY").unwrap();
    tag(&store, "docker.io/library/alpine:latest", &external);
    tag(
        &store,
        "docker.io/library/alpine:Case",
        &store.join("unknown-output"),
    );
    fs::write(store.join("auth.json"), "AUTH_CANARY").unwrap();
    fs::write(
        store.join(format!("tag-{}.json", "a".repeat(64))),
        "{MALFORMED_CANARY",
    )
    .unwrap();
    fs::create_dir(store.join("build-old")).unwrap();
    fs::write(store.join("build-old/payload"), b"12345").unwrap();
    symlink(&external, store.join("build-old/escape")).unwrap();
    let hostile = "build-\x1b[31m\n\x7f\u{202e}";
    fs::create_dir(store.join(hostile)).unwrap();
    let image = report(temp.path(), &["image", "inspect", "alpine", "--json"]);
    assert_eq!(image["data"]["tag"]["ownership"], "external");
    assert_eq!(image["data"]["tag"]["target_status"], "unknown");
    let internal = report(temp.path(), &["image", "inspect", "alpine:Case", "--json"]);
    assert_eq!(internal["data"]["tag"]["ownership"], "unknown");
    assert!(
        !run(temp.path(), true, &["image", "inspect", "alpine:case"])
            .status
            .success()
    );
    let images = report(temp.path(), &["images", "--json"]);
    assert_eq!(images["partial"], true);
    assert!(
        images["data"]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["status"] == "invalid")
    );
    let build = report(temp.path(), &["builds", "inspect", "build-old", "--json"]);
    assert_eq!(build["data"]["build"]["status"], "legacy_unknown");
    assert_eq!(build["data"]["build"]["ownership"], "unknown");
    assert_eq!(build["data"]["build"]["protected"], true);
    let usage = report(temp.path(), &["cache", "du", "--json"]);
    assert_eq!(usage["data"]["usage"]["logical_bytes"], 0);
    for args in [
        vec!["images"],
        vec!["builds", "ls"],
        vec!["cache", "ls"],
        vec!["cache", "du"],
    ] {
        let output = run(temp.path(), true, &args);
        let text = assert_safe_text(output);
        assert!(!text.contains(['\x1b', '\u{202e}']));
        assert!(!text.contains("CANARY"));
    }
    assert_eq!(
        fs::read(external.join("secret")).unwrap(),
        b"EXTERNAL_CANARY"
    );
    assert_eq!(fs::read(store.join("auth.json")).unwrap(), b"AUTH_CANARY");
}

#[test]
fn invalid_flags_and_mutations_are_rejected_before_store_access() {
    let temp = tempfile::tempdir().unwrap();
    for args in [
        vec!["images", "--json", "--json"],
        vec!["images", "extra"],
        vec!["image", "inspect"],
        vec!["image", "inspect", "alpine", "--authfile", "secret"],
        vec!["cache", "ls", "--dry-run"],
        vec!["cache", "prune"],
        vec!["image", "rm", "alpine"],
        vec!["builds", "rm", "build-old"],
        vec!["builds", "inspect", "../build-old"],
        vec!["builds", "inspect", "build-old/../build-other"],
        vec!["cache", "du", "--json", "extra"],
    ] {
        let output = run(temp.path(), true, &args);
        assert!(!output.status.success(), "{args:?}");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }
    let help = run(temp.path(), true, &["--help"]);
    let help = String::from_utf8(help.stdout).unwrap();
    for command in [
        "images [--json]",
        "image inspect TAG",
        "cache ls",
        "cache du",
        "builds ls",
        "builds inspect BUILD_ID",
    ] {
        assert!(help.contains(command));
    }
}
