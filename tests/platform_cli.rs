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
        let r = build(t.path(), 0, &["--build-arg", "TARGETPLATFORM=linux/arm64"]);
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
