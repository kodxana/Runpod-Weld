#![cfg(target_os = "linux")]

use std::{fs, io::Read, path::Path, path::PathBuf, process::Command};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/layered-export")
        .join(name)
}

#[test]
fn compression_cli_contract() {
    let help = Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .args(["build", "--help"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("--compression"));
    for args in [
        vec!["--compression", "zip"],
        vec!["--compression=gzip", "--compression=uncompressed"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .arg("build")
            .args(args)
            .args(["-f", "does-not-exist", "."])
            .output()
            .unwrap();
        assert!(!result.status.success());
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(error.contains("compression"), "{error}");
        assert!(!error.contains("unknown build option"), "{error}");
    }
}

#[test]
fn export_mode_rejects_unknown_values_before_opening_sources() {
    let help = Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .args(["build", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--export-mode"));
    assert!(String::from_utf8_lossy(&help.stdout).contains("Layered export is the default"));
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
fn default_build_preserves_base_layers_through_cache_and_flattened_override() {
    fn blob(layout: &Path, descriptor: &serde_json::Value) -> Vec<u8> {
        let digest = descriptor["digest"].as_str().unwrap();
        let bytes = fs::read(layout.join("blobs").join(digest.replace(':', "/"))).unwrap();
        use sha2::{Digest, Sha256};
        assert_eq!(digest, format!("sha256:{:x}", Sha256::digest(&bytes)));
        assert_eq!(descriptor["size"].as_u64().unwrap(), bytes.len() as u64);
        bytes
    }
    fn image(layout: &Path) -> (serde_json::Value, serde_json::Value) {
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(layout.join("index.json")).unwrap()).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&blob(layout, &index["manifests"][0])).unwrap();
        let config = serde_json::from_slice(&blob(layout, &manifest["config"])).unwrap();
        (manifest, config)
    }
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(context.join("base"), b"base payload\n").unwrap();
    fs::write(context.join("app"), b"app payload\n").unwrap();
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY base /base\n",
    )
    .unwrap();
    let build = |name: &str, extra: &[String]| {
        let output = temp.path().join(format!("{name}-image"));
        let result = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .env("RPWELD_HOME", temp.path().join("store"))
            .args(["build", "--no-host-dns", "-t", "test/default-layered"])
            .arg("--output")
            .arg(&output)
            .arg("--work-dir")
            .arg(temp.path().join(format!("{name}-work")))
            .args(extra)
            .arg(&context)
            .output()
            .unwrap();
        assert!(result.status.success(), "{name}: {result:?}");
        (output, String::from_utf8_lossy(&result.stderr).into_owned())
    };
    let (base, _) = build("base", &[]);
    let (base_manifest, base_config) = image(&base);
    fs::write(context.join("Dockerfile"), "FROM fixture\nCOPY app /app\n").unwrap();
    // Reading the context must not change its cache identity under relatime.
    for path in [&context, &context.join("Dockerfile"), &context.join("app")] {
        let stamp = |seconds| std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds);
        fs::File::open(path)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_accessed(stamp(2_000_000_001))
                    .set_modified(stamp(2_000_000_000)),
            )
            .unwrap();
    }
    let mut cold_manifest = None;
    for (name, flags) in [
        ("cold", vec![]),
        ("warm", vec![]),
        ("uncached", vec!["--no-cache"]),
        ("explicit-layered", vec!["--export-mode", "layered"]),
        ("flat", vec!["--export-mode", "flattened"]),
        ("default-after-flat", vec![]),
    ] {
        let mut args = vec!["--base".to_owned(), format!("fixture={}", base.display())];
        args.extend(flags.into_iter().map(str::to_owned));
        let (output, log) = build(name, &args);
        let (manifest, config) = image(&output);
        let layers = manifest["layers"].as_array().unwrap();
        if name == "flat" {
            assert_eq!(layers.len(), 1);
        } else {
            let prefix = base_manifest["layers"].as_array().unwrap();
            assert_eq!(layers.len(), prefix.len() + 1);
            assert_eq!(&layers[..prefix.len()], prefix);
            assert_eq!(
                &config["rootfs"]["diff_ids"].as_array().unwrap()[..prefix.len()],
                base_config["rootfs"]["diff_ids"].as_array().unwrap()
            );
            for descriptor in prefix {
                assert_eq!(blob(&output, descriptor), blob(&base, descriptor));
            }
        }
        let bytes = blob(&output, layers.last().unwrap());
        let mut files = std::collections::BTreeMap::new();
        for entry in tar::Archive::new(bytes.as_slice()).entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.header().entry_type().is_file() {
                let path = entry.path().unwrap().into_owned();
                let mut contents = Vec::new();
                entry.read_to_end(&mut contents).unwrap();
                files.insert(path, contents);
            }
        }
        assert_eq!(files.get(Path::new("app")).unwrap(), b"app payload\n");
        assert_eq!(files.contains_key(Path::new("base")), name == "flat");
        if name == "cold" {
            cold_manifest = Some(manifest.clone());
        } else if ["warm", "explicit-layered", "default-after-flat"].contains(&name) {
            assert!(log.contains("CACHED"), "{name}: {log}");
            assert_eq!(Some(&manifest), cold_manifest.as_ref());
        } else if name == "uncached" {
            assert!(!log.contains("CACHED"), "{log}");
        }
    }
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
