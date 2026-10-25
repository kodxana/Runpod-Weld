#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::{fs, path::Path, process::Command};

fn build(root: &Path, number: usize, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .env("HOME", root)
        .env("RPWELD_HOME", root.join("store"))
        .args([
            "build",
            "--no-host-dns",
            "--platform",
            "linux/amd64",
            "-t",
            "test/platform:latest",
        ])
        .arg("--output")
        .arg(root.join(format!("out-{number}")))
        .arg("--work-dir")
        .arg(root.join(format!("work-{number}")))
        .args(args)
        .arg(root.join("context"))
        .output()
        .unwrap()
}

#[test]
fn unsupported_from_fails_before_pull_or_store_mutation() {
    for source in [
        "FROM --platform=linux/arm64 nonexistent.invalid/no-pull",
        "FROM scratch AS base\nFROM --platform=$TARGETPLATFORM base",
        "FROM --platform=$UNDEFINED nonexistent.invalid/no-pull",
        "FROM scratch AS final\nFROM --platform=windows/amd64 scratch AS unused",
    ] {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir(t.path().join("context")).unwrap();
        fs::write(t.path().join("context/Dockerfile"), source).unwrap();
        let mut args = vec!["--build-arg", "TARGETPLATFORM=linux/arm64"];
        if source.contains("AS final") {
            args.extend(["--target", "final"]);
        }
        let r = build(t.path(), 0, &args);
        assert!(!r.status.success());
        assert!(
            String::from_utf8_lossy(&r.stderr).contains("platform"),
            "{:?}",
            r
        );
        for name in ["store", "out-0", "work-0"] {
            assert!(!t.path().join(name).exists(), "{name}");
        }
    }
}

#[test]
#[ignore = "requires root and RPWELD_TEST_LAYOUT with Alpine /bin/sh"]
fn run_only_platform_redeclaration_visibility_and_cache() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let layout = fs::canonicalize(std::env::var_os("RPWELD_TEST_LAYOUT").unwrap()).unwrap();
    let binding = format!("alpine={}", layout.display());
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    fs::create_dir(root.join("context")).unwrap();
    // No COPY or ENV: only RUN's environment and output can distinguish these builds.
    fs::write(root.join("context/Dockerfile"), "ARG TARGETARCH\nFROM alpine\nRUN printf '%s/%s' \"${TARGETARCH-unset}\" \"${BUILDARCH-unset}\" > /before\nARG TARGETARCH\nRUN printf '%s/%s' \"${TARGETARCH-unset}\" \"${BUILDARCH-unset}\" > /after\n").unwrap();
    let mut image_config = None;
    for (n, value) in [None, Some("custom"), Some("custom")]
        .into_iter()
        .enumerate()
    {
        let mut args = vec!["--base", &binding, "--run-timeout-seconds", "20"];
        let arg;
        if let Some(value) = value {
            arg = format!("TARGETARCH={value}");
            args.extend(["--build-arg", &arg]);
        }
        let r = build(root, n, &args);
        let log = String::from_utf8_lossy(&r.stderr);
        assert!(r.status.success(), "{log}");
        assert_eq!(
            fs::read_to_string(root.join(format!("work-{n}/rootfs/before"))).unwrap(),
            "unset/unset"
        );
        assert_eq!(
            fs::read_to_string(root.join(format!("work-{n}/rootfs/after"))).unwrap(),
            format!("{}/unset", value.unwrap_or("amd64"))
        );
        match n {
            0 => assert!(!log.contains("CACHED"), "{log}"),
            1 => {
                assert!(!log.contains("CACHED ("), "{log}");
                assert!(log.contains("CACHED instruction 2 RUN"), "{log}");
                assert!(!log.contains("CACHED instruction 4 RUN"), "{log}");
            }
            2 => assert!(log.contains("CACHED ("), "{log}"),
            _ => unreachable!(),
        }
        let layout = root.join(format!("out-{n}"));
        let read = |p| serde_json::from_slice::<serde_json::Value>(&fs::read(p).unwrap()).unwrap();
        let blob = |d: &str| layout.join("blobs").join(d.replace(':', "/"));
        let index = read(layout.join("index.json"));
        let manifest = read(blob(index["manifests"][0]["digest"].as_str().unwrap()));
        let config = read(blob(manifest["config"]["digest"].as_str().unwrap()));
        assert_eq!(
            image_config.get_or_insert(config["config"].clone()),
            &config["config"]
        );
        assert!(
            !config["config"]["Env"].as_array().unwrap().iter().any(|v| {
                let v = v.as_str().unwrap();
                v.starts_with("TARGETARCH=") || v.starts_with("BUILDARCH=")
            })
        );
    }
}

#[test]
fn platform_arg_cache_identity_and_user_are_preserved() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    fs::create_dir(root.join("context")).unwrap();
    fs::write(root.join("context/Dockerfile"), "FROM --platform=$BUILDPLATFORM scratch\nARG TARGETARCH\nCOPY payload /$TARGETARCH/payload\nUSER 123:456\nENV SAVED=$TARGETARCH").unwrap();
    fs::write(root.join("context/payload"), "payload").unwrap();
    for (n, arch) in ["amd64", "amd64", "custom", "custom"]
        .into_iter()
        .enumerate()
    {
        let arg = format!("TARGETARCH={arch}");
        let r = build(root, n, &["--build-arg", &arg]);
        assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
        let log = String::from_utf8_lossy(&r.stderr);
        if n % 2 == 1 {
            assert!(log.contains("CACHED ("), "{log}");
        }
        if n == 2 {
            assert!(!log.contains("CACHED ("), "{log}");
        }
        assert_eq!(
            fs::read_to_string(root.join(format!("work-{n}/rootfs/{arch}/payload"))).unwrap(),
            "payload"
        );
        if arch == "custom" {
            assert!(!root.join(format!("work-{n}/rootfs/amd64")).exists());
        }
        let layout = root.join(format!("out-{n}"));
        let read = |p| serde_json::from_slice::<serde_json::Value>(&fs::read(p).unwrap()).unwrap();
        let blob = |d: &str| layout.join("blobs").join(d.replace(':', "/"));
        let index = read(layout.join("index.json"));
        let manifest = read(blob(index["manifests"][0]["digest"].as_str().unwrap()));
        let config = read(blob(manifest["config"]["digest"].as_str().unwrap()));
        assert_eq!(config["os"], "linux");
        assert_eq!(config["architecture"], "amd64");
        assert_eq!(config["config"]["User"], "123:456");
        assert_eq!(
            config["config"]["Env"],
            serde_json::json!([format!("SAVED={arch}")])
        );
    }
}
