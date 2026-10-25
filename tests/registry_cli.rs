#![cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
};

fn cli(home: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rpweld"));
    c.env("HOME", home).env("RPWELD_HOME", home.join("store"));
    c
}

#[test]
fn managed_scratch_tag_survives_failed_push_and_retag_is_atomic() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir(&home).unwrap();
    let context = tmp.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY payload /payload\nCMD [\"/payload\"]\n",
    )
    .unwrap();
    fs::write(context.join("payload"), "v1").unwrap();
    let r = cli(&home)
        .args(["build", "-t", "localhost:1/test/demo:v1", "--push"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stdout).contains("Tagged localhost:1/test/demo:v1"));
    let tags: Vec<_> = fs::read_dir(home.join("store"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    assert_eq!(tags.len(), 1);
    let before = fs::read(&tags[0]).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert!(
        std::path::Path::new(v["image"].as_str().unwrap())
            .join("index.json")
            .is_file()
    );
    // A failed build may not replace an existing tag.
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY absent /payload\n",
    )
    .unwrap();
    let r = cli(&home)
        .args(["build", "-t", "localhost:1/test/demo:v1"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert_eq!(fs::read(&tags[0]).unwrap(), before);
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY payload /payload\n",
    )
    .unwrap();
    let r = cli(&home)
        .args(["build", "-t", "localhost:1/test/demo:v1"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    assert_ne!(fs::read(&tags[0]).unwrap(), before);
    assert_eq!(
        fs::metadata(&tags[0]).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn credential_files_cannot_be_copied_or_follow_links() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir(&home).unwrap();
    let context = tmp.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(context.join("Dockerfile"), "FROM scratch\nCOPY . /\n").unwrap();
    let auth = context.join("auth.json");
    fs::write(&auth, "{\"auths\":{}}").unwrap();
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).unwrap();
    let r = cli(&home)
        .args(["build", "-t", "test", "--authfile"])
        .arg(&auth)
        .arg(&context)
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("outside the build context"));
    let r = cli(&home)
        .args(["build", "--authfile"])
        .arg(&auth)
        .arg("--output")
        .arg(tmp.path().join("out"))
        .arg("--work-dir")
        .arg(tmp.path().join("work"))
        .arg(&context)
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("outside the build context"));
    let alias = tmp.path().join("alias.json");
    symlink(&auth, &alias).unwrap();
    let r = cli(&home)
        .args(["logout", "example.com", "--authfile"])
        .arg(&alias)
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert_eq!(fs::read_to_string(&auth).unwrap(), "{\"auths\":{}}");
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o644)).unwrap();
    let r = cli(&home)
        .args(["logout", "example.com", "--authfile"])
        .arg(&auth)
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("0600"));
}

#[test]
fn certificate_directories_inside_context_are_rejected_before_build_or_pull() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir(&home).unwrap();
    let context = tmp.path().join("context");
    let certs = context.join("certs");
    fs::create_dir_all(&certs).unwrap();
    fs::write(certs.join("client.key"), "private-key-canary").unwrap();
    let alias = tmp.path().join("cert-alias");
    symlink(&certs, &alias).unwrap();
    let context_alias = tmp.path().join("context-alias");
    symlink(&context, &context_alias).unwrap();
    for base in ["scratch", "localhost:1/test/base:latest"] {
        fs::write(
            context.join("Dockerfile"),
            format!("FROM {base}\nCOPY . /\n"),
        )
        .unwrap();
        for cert_dir in [&certs, &alias, &context] {
            for managed in [false, true] {
                let output = tmp.path().join("out");
                let work = tmp.path().join("work");
                let mut cmd = cli(&home);
                cmd.args(["build", "--cert-dir"]).arg(cert_dir);
                if managed {
                    cmd.args(["-t", "test"]);
                } else {
                    cmd.arg("--output")
                        .arg(&output)
                        .arg("--work-dir")
                        .arg(&work);
                }
                let r = cmd.arg(&context_alias).output().unwrap();
                assert!(!r.status.success());
                let error = String::from_utf8_lossy(&r.stderr);
                assert!(
                    error.contains("certificate directory must be outside"),
                    "{error}"
                );
                assert!(!output.exists());
                assert!(!work.exists());
                assert!(!home.join("store").exists());
                assert!(!String::from_utf8_lossy(&r.stdout).contains("Pulling"));
            }
        }
    }
}

#[test]
fn outside_certificate_directory_preserves_explicit_scratch_builds() {
    let tmp = tempfile::tempdir().unwrap();
    let context = tmp.path().join("context");
    // A sibling with the same prefix must not be mistaken for a descendant.
    let certs = tmp.path().join("context-certs");
    fs::create_dir(&context).unwrap();
    fs::create_dir(&certs).unwrap();
    fs::write(certs.join("ca.crt"), "unused by scratch build").unwrap();
    fs::write(context.join("Dockerfile"), "FROM scratch\nCOPY . /\n").unwrap();
    let alias = tmp.path().join("cert-alias");
    symlink(&certs, &alias).unwrap();
    let r = cli(tmp.path())
        .args(["build", "--cert-dir"])
        .arg(&alias)
        .arg("--output")
        .arg(tmp.path().join("out"))
        .arg("--work-dir")
        .arg(tmp.path().join("work"))
        .arg(&context)
        .output()
        .unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    assert!(tmp.path().join("out/index.json").is_file());
}

#[test]
fn auth_arguments_reject_passwords_and_transports_without_echoing_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        vec!["login", "example.com", "--password", "sensitive-canary"],
        vec!["login", "https://sensitive-canary@example.com"],
        vec!["build", "-t", "sensitive-canary@example.com/app", "."],
        vec!["login", "example.com", "--password-stdin"],
    ] {
        let r = cli(tmp.path()).args(args).output().unwrap();
        assert!(!r.status.success());
        assert!(!String::from_utf8_lossy(&r.stderr).contains("sensitive-canary"));
    }
}
