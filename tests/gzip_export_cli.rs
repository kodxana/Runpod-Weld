#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path, process::Command};

fn blob(layout: &Path, descriptor: &Value) -> Vec<u8> {
    let digest = descriptor["digest"].as_str().unwrap();
    let bytes = fs::read(layout.join("blobs").join(digest.replace(':', "/"))).unwrap();
    assert_eq!(digest, format!("sha256:{:x}", Sha256::digest(&bytes)));
    assert_eq!(descriptor["size"].as_u64().unwrap(), bytes.len() as u64);
    bytes
}

fn image(layout: &Path) -> (Value, Value) {
    let index: Value =
        serde_json::from_slice(&fs::read(layout.join("index.json")).unwrap()).unwrap();
    let manifest: Value = serde_json::from_slice(&blob(layout, &index["manifests"][0])).unwrap();
    let config: Value = serde_json::from_slice(&blob(layout, &manifest["config"])).unwrap();
    for (layer, diff) in manifest["layers"]
        .as_array()
        .unwrap()
        .iter()
        .zip(config["rootfs"]["diff_ids"].as_array().unwrap())
    {
        let bytes = blob(layout, layer);
        let raw = if layer["mediaType"].as_str().unwrap().ends_with("+gzip") {
            assert_eq!(&bytes[..10], &[31, 139, 8, 0, 0, 0, 0, 0, 4, 255]);
            let mut raw = Vec::new();
            flate2::read::GzDecoder::new(bytes.as_slice())
                .read_to_end(&mut raw)
                .unwrap();
            raw
        } else {
            bytes
        };
        assert_eq!(diff, &format!("sha256:{:x}", Sha256::digest(&raw)));
    }
    (manifest, config)
}

#[test]
#[ignore = "requires Linux root, offline Alpine RPWELD_TEST_LAYOUT and new RPWELD_GZIP_EVIDENCE path"]
fn gzip_runtime_export_reimport_metadata_parity() {
    let result = Command::new("python3")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/layered-export/gzip_acceptance.py"),
        )
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_rpweld"))
        .arg("--layout")
        .arg(std::env::var_os("RPWELD_TEST_LAYOUT").unwrap())
        .arg("--evidence")
        .arg(std::env::var_os("RPWELD_GZIP_EVIDENCE").unwrap())
        .status()
        .unwrap();
    assert!(result.success());
}

fn replay(layout: &Path, root: &Path, spool: &Path) {
    use rpweld::{image, layer, oci::BlobStore, rootfs};
    let image = image::load_layout(
        layout,
        None,
        image::Limits {
            max_metadata_bytes: 1 << 20,
            max_total_metadata_bytes: 4 << 20,
            max_descriptors: 100,
            max_layer_bytes: 16 << 20,
            max_total_layer_bytes: 64 << 20,
        },
        || false,
    )
    .unwrap();
    fs::create_dir(root).unwrap();
    let store = BlobStore::open(layout).unwrap();
    for (descriptor, diff) in image.layers.iter().zip(&image.diff_ids) {
        let mut verified = layer::verify(
            &store,
            descriptor,
            diff,
            spool,
            layer::Limits {
                max_blob_bytes: 16 << 20,
                max_uncompressed_bytes: 32 << 20,
                max_entries: 10000,
                max_metadata_bytes: 4 << 20,
                max_gzip_header_bytes: 10,
            },
            || false,
        )
        .unwrap();
        rootfs::apply_layer(root, &mut verified, || false).unwrap();
    }
}

#[test]
fn gzip_cli_preserves_prefix_cache_modes_and_independent_public_blobs() {
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(context.join("base"), vec![17; 1 << 20]).unwrap();
    fs::write(context.join("app"), b"application payload").unwrap();
    let build = |name: &str, flags: &[&str], base: Option<&Path>| {
        let output = temp.path().join(format!("{name}-image"));
        let work = temp.path().join(format!("{name}-work"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        command
            .env("RPWELD_HOME", temp.path().join("store"))
            .args([
                "build",
                "--no-host-dns",
                "--progress",
                "plain",
                "-t",
                "test/gzip",
            ])
            .arg("--output")
            .arg(&output)
            .arg("--work-dir")
            .arg(&work)
            .args(flags);
        if let Some(base) = base {
            command
                .arg("--base")
                .arg(format!("fixture={}", base.display()));
        }
        let result = command.arg(&context).output().unwrap();
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        (
            output,
            work,
            String::from_utf8_lossy(&result.stderr).into_owned(),
        )
    };
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY base /base\n",
    )
    .unwrap();
    let (base, _, _) = build(
        "base",
        &[
            "--compression=gzip",
            "--export-mode=flattened",
            "--no-cache",
        ],
        None,
    );
    // An inherited descriptor is opaque, including extensions and annotations.
    let (mut base_manifest, base_config) = image(&base);
    base_manifest["layers"][0]["annotations"] = json!({"test":"preserve"});
    base_manifest["layers"][0]["future"] = json!({"opaque":[1,2,3]});
    let bytes = serde_json::to_vec(&base_manifest).unwrap();
    let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    fs::write(base.join("blobs").join(digest.replace(':', "/")), &bytes).unwrap();
    let mut index: Value =
        serde_json::from_slice(&fs::read(base.join("index.json")).unwrap()).unwrap();
    index["manifests"][0]["digest"] = json!(digest);
    index["manifests"][0]["size"] = json!(bytes.len());
    fs::write(base.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
    let source =
        "FROM fixture\nCOPY app /app\nENV GREETING=hello\nLABEL purpose=gzip\nCMD [\"/app\"]\n";
    fs::write(context.join("Dockerfile"), source).unwrap();
    let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000_000);
    for path in [&context, &context.join("Dockerfile"), &context.join("app")] {
        fs::File::open(path)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_accessed(stamp + std::time::Duration::from_secs(1))
                    .set_modified(stamp),
            )
            .unwrap();
    }
    for mode in ["layered", "flattened"] {
        let mode_flag = format!("--export-mode={mode}");
        let mut cold = std::collections::BTreeMap::new();
        for (name, compression, warm, no_cache) in [
            ("raw-cold", "uncompressed", false, false),
            ("gzip-cold", "gzip", false, false),
            ("gzip-warm", "gzip", true, false),
            ("raw-warm", "uncompressed", true, false),
            ("gzip-uncached", "gzip", false, true),
        ] {
            let compression_flag = format!("--compression={compression}");
            let mut flags = vec![mode_flag.as_str(), compression_flag.as_str()];
            if no_cache {
                flags.push("--no-cache");
            }
            let name = format!("{mode}-{name}");
            let (output, work, log) = build(&name, &flags, Some(&base));
            assert_eq!(log.contains("CACHED"), warm, "{name}: {log}");
            let (manifest, config) = image(&output);
            if warm {
                assert_eq!(&manifest, cold.get(compression).unwrap());
            } else if !no_cache {
                cold.insert(compression, manifest.clone());
            }
            let layers = manifest["layers"].as_array().unwrap();
            let new = layers.last().unwrap();
            assert_eq!(
                new["mediaType"].as_str().unwrap().ends_with("+gzip"),
                compression == "gzip"
            );
            if mode == "layered" {
                assert_eq!(&layers[..1], base_manifest["layers"].as_array().unwrap());
                assert_eq!(
                    config["rootfs"]["diff_ids"][0],
                    base_config["rootfs"]["diff_ids"][0]
                );
                assert_eq!(blob(&output, &layers[0]), blob(&base, &layers[0]));
                let relative = Path::new("blobs")
                    .join(layers[0]["digest"].as_str().unwrap().replace(':', "/"));
                assert_ne!(
                    fs::metadata(output.join(&relative)).unwrap().ino(),
                    fs::metadata(base.join(relative)).unwrap().ino()
                );
            } else {
                assert_eq!(layers.len(), 1);
            }
            // Public publication must copy every blob out of private checkpoint storage.
            for checkpoint in fs::read_dir(&work)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("checkpoint-image-")
                })
            {
                for descriptor in layers {
                    let relative = Path::new("blobs")
                        .join(descriptor["digest"].as_str().unwrap().replace(':', "/"));
                    if let Ok(private) = fs::metadata(checkpoint.path().join(&relative)) {
                        assert_ne!(
                            private.ino(),
                            fs::metadata(output.join(&relative)).unwrap().ino()
                        );
                    }
                }
            }
            let root = temp.path().join(format!("replay-{name}"));
            replay(&output, &root, temp.path());
            assert_eq!(fs::read(root.join("base")).unwrap(), vec![17; 1 << 20]);
            assert_eq!(fs::read(root.join("app")).unwrap(), b"application payload");
            let app = fs::metadata(root.join("app")).unwrap();
            assert_eq!((app.atime(), app.mtime()), (2_000_000_001, 2_000_000_000));
            assert_eq!(config["config"]["Env"], json!(["GREETING=hello"]));
            assert_eq!(config["config"]["Cmd"], json!(["/app"]));
            assert_eq!(config["config"]["Labels"]["purpose"], "gzip");
        }
    }
}
