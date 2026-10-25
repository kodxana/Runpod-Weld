#![cfg(target_os = "linux")]
use rpweld::{
    image::Limits,
    oci::{BlobStore, Descriptor},
    registry::cached_base,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

fn limits() -> Limits {
    Limits {
        max_metadata_bytes: 65536,
        max_total_metadata_bytes: 262144,
        max_descriptors: 32,
        max_layer_bytes: 1024,
        max_total_layer_bytes: 4096,
    }
}
fn blob(store: &BlobStore, media: &str, bytes: &[u8]) -> Descriptor {
    let descriptor = Descriptor {
        media_type: media.into(),
        digest: format!("sha256:{:x}", Sha256::digest(bytes)),
        size: bytes.len() as i64,
        annotations: Default::default(),
        extensions: Default::default(),
    };
    store.ingest(bytes, &descriptor, 65536, || false).unwrap();
    descriptor
}
fn fixture(path: &Path, version: u32) -> Result<(), String> {
    fs::create_dir(path).unwrap();
    let store = BlobStore::open(path).unwrap();
    let layer = blob(&store, "application/vnd.oci.image.layer.v1.tar", &[0; 1024]);
    let config = blob(
        &store,
        "application/vnd.oci.image.config.v1+json",
        &serde_json::to_vec(&json!({
            "architecture":"amd64", "os":"linux", "config":{}, "version":version,
            "rootfs":{"type":"layers", "diff_ids":[layer.digest]}
        }))
        .unwrap(),
    );
    let manifest = blob(&store, "application/vnd.oci.image.manifest.v1+json", &serde_json::to_vec(&json!({
        "schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json", "config":config,"layers":[layer]
    })).unwrap());
    // Unreferenced content must never be published.
    blob(&store, "application/octet-stream", b"unselected");
    fs::write(
        path.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        path.join("index.json"),
        serde_json::to_vec(&json!({"schemaVersion":2,"manifests":[manifest]})).unwrap(),
    )
    .unwrap();
    Ok(())
}
fn populate(store: &Path, lease: &rpweld::store_lease::StoreLease) -> PathBuf {
    cached_base(
        store,
        lease,
        "alpine",
        false,
        limits(),
        || false,
        |r, p| {
            assert_eq!(r, "docker.io/library/alpine:latest");
            fixture(p, 1)
        },
    )
    .unwrap()
}
fn no_fetch(_: &str, _: &Path) -> Result<(), String> {
    panic!("unexpected fetch")
}
fn record(store: &Path) -> PathBuf {
    fs::read_dir(store.join("base-cache-v1/refs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap()
}

#[test]
fn hits_refresh_failure_and_retained_shared_generations() {
    let tmp = tempfile::tempdir().unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(tmp.path(), &|| false).unwrap();
    let old = populate(tmp.path(), &lease);
    assert_eq!(
        old,
        cached_base(
            tmp.path(),
            &lease,
            "index.docker.io/alpine:latest",
            false,
            limits(),
            || false,
            no_fetch
        )
        .unwrap()
    );
    let before = fs::read(record(tmp.path())).unwrap();
    assert!(
        cached_base(
            tmp.path(),
            &lease,
            "alpine",
            true,
            limits(),
            || false,
            |_, p| {
                fixture(p, 2)?;
                Err("failed transfer".into())
            }
        )
        .is_err()
    );
    assert_eq!(before, fs::read(record(tmp.path())).unwrap());
    assert_eq!(
        old,
        cached_base(
            tmp.path(),
            &lease,
            "alpine",
            false,
            limits(),
            || false,
            no_fetch
        )
        .unwrap()
    );
    let new = cached_base(
        tmp.path(),
        &lease,
        "alpine",
        true,
        limits(),
        || false,
        |_, p| fixture(p, 2),
    )
    .unwrap();
    assert_ne!(old, new);
    let old_meta = rpweld::image::load_layout(&old, None, limits(), || false).unwrap();
    let new_meta = rpweld::image::load_layout(&new, None, limits(), || false).unwrap();
    assert_ne!(old_meta.selected, new_meta.selected);
    let suffix = format!("blobs/sha256/{}", &old_meta.layers[0].digest[7..]);
    let shared = tmp.path().join("base-cache-v1/content").join(&suffix);
    assert_eq!(
        fs::metadata(old.join(&suffix)).unwrap().ino(),
        fs::metadata(&shared).unwrap().ino()
    );
    assert_eq!(
        fs::metadata(new.join(&suffix)).unwrap().ino(),
        fs::metadata(shared).unwrap().ino()
    );
    assert_eq!(fs::read_dir(new.join("blobs/sha256")).unwrap().count(), 3);
}

#[test]
fn pinned_source_digest_is_not_converted_oci_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(tmp.path(), &|| false).unwrap();
    let reference = format!("alpine@sha256:{}", "a".repeat(64));
    let path = cached_base(
        tmp.path(),
        &lease,
        &reference,
        false,
        limits(),
        || false,
        |r, p| {
            assert!(r.ends_with(&"a".repeat(64)));
            fixture(p, 1)
        },
    )
    .unwrap();
    assert_eq!(
        path,
        cached_base(
            tmp.path(),
            &lease,
            &reference,
            true,
            limits(),
            || false,
            no_fetch
        )
        .unwrap()
    );
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(record(tmp.path())).unwrap()).unwrap();
    assert_ne!(record["source_digest"], record["selected"]["digest"]);
}

#[test]
fn corrupt_records_traversal_and_selected_mismatch_fail_closed_even_on_refresh() {
    for corruption in ["json", "../escape", "descriptor", "identity"] {
        let tmp = tempfile::tempdir().unwrap();
        let lease = rpweld::store_lease::StoreLease::shared(tmp.path(), &|| false).unwrap();
        populate(tmp.path(), &lease);
        let file = record(tmp.path());
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        match corruption {
            "json" => {
                fs::write(&file, b"{").unwrap();
            }
            "descriptor" => {
                value["selected"]["size"] = json!(0);
                fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            "identity" => {
                value["reference"] = json!("other");
                fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            other => {
                value["generation"] = json!(other);
                fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
            }
        }
        for refresh in [false, true] {
            assert!(
                cached_base(
                    tmp.path(),
                    &lease,
                    "alpine",
                    refresh,
                    limits(),
                    || false,
                    no_fetch
                )
                .is_err()
            );
        }
    }
}

#[test]
fn corrupt_content_and_requested_limits_are_checked_on_hits() {
    let tmp = tempfile::tempdir().unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(tmp.path(), &|| false).unwrap();
    let path = populate(tmp.path(), &lease);
    let mut small = limits();
    small.max_layer_bytes = 1;
    assert!(
        cached_base(
            tmp.path(),
            &lease,
            "alpine",
            false,
            small,
            || false,
            no_fetch
        )
        .is_err()
    );
    let metadata = rpweld::image::load_layout(&path, None, limits(), || false).unwrap();
    fs::write(
        path.join(format!("blobs/sha256/{}", &metadata.layers[0].digest[7..])),
        b"corrupt",
    )
    .unwrap();
    assert!(
        cached_base(
            tmp.path(),
            &lease,
            "alpine",
            false,
            limits(),
            || false,
            no_fetch
        )
        .is_err()
    );
    assert!(
        cached_base(
            tmp.path(),
            &lease,
            "alpine",
            true,
            limits(),
            || false,
            no_fetch
        )
        .is_err()
    );
}

#[test]
fn invalid_new_content_does_not_replace_reference() {
    let tmp = tempfile::tempdir().unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(tmp.path(), &|| false).unwrap();
    populate(tmp.path(), &lease);
    let before = fs::read(record(tmp.path())).unwrap();
    assert!(
        cached_base(
            tmp.path(),
            &lease,
            "alpine",
            true,
            limits(),
            || false,
            |_, p| {
                fixture(p, 2)?;
                fs::write(p.join("index.json"), b"{}").unwrap();
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(before, fs::read(record(tmp.path())).unwrap());
}

#[test]
fn concurrent_cold_fetch_runs_once() {
    let tmp = tempfile::tempdir().unwrap();
    let _lease = rpweld::store_lease::StoreLease::shared(tmp.path(), &|| false).unwrap();
    let barrier = Arc::new(Barrier::new(6));
    let calls = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..6)
        .map(|_| {
            let barrier = barrier.clone();
            let calls = calls.clone();
            let store = tmp.path().to_owned();
            std::thread::spawn(move || {
                barrier.wait();
                cached_base(
                    &store,
                    &rpweld::store_lease::StoreLease::shared(&store, &|| false).unwrap(),
                    "alpine",
                    false,
                    limits(),
                    || false,
                    |_, p| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(100));
                        fixture(p, 1)
                    },
                )
                .unwrap()
            })
        })
        .collect();
    let paths: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(paths.iter().all(|p| p == &paths[0]));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn waiting_for_lock_is_cancellable() {
    let tmp = tempfile::tempdir().unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(tmp.path(), &|| false).unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let store = tmp.path().to_owned();
    let owner = std::thread::spawn(move || {
        cached_base(
            &store,
            &rpweld::store_lease::StoreLease::shared(&store, &|| false).unwrap(),
            "alpine",
            false,
            limits(),
            || false,
            |_, p| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                fixture(p, 1)
            },
        )
        .unwrap()
    });
    entered_rx.recv().unwrap();
    let cancelled = AtomicBool::new(false);
    let start = std::time::Instant::now();
    let result = cached_base(
        tmp.path(),
        &lease,
        "alpine",
        false,
        limits(),
        || {
            if start.elapsed() > Duration::from_millis(100) {
                cancelled.store(true, Ordering::SeqCst);
            }
            cancelled.load(Ordering::SeqCst)
        },
        no_fetch,
    );
    release_tx.send(()).unwrap();
    owner.join().unwrap();
    assert!(result.unwrap_err().contains("cancelled"));
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn cli_offline_hit_ignores_invalid_credentials_even_with_no_cache() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store");
    rpweld::registry::private_dir(&store).unwrap();
    populate(
        &store,
        &rpweld::store_lease::StoreLease::shared(&store, &|| false).unwrap(),
    );
    let context = tmp.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(context.join("Dockerfile"), "FROM alpine\n").unwrap();
    let auth = tmp.path().join("auth.json");
    fs::write(&auth, "invalid SECRET auth JSON").unwrap();
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .env("RPWELD_HOME", &store)
        .env("HOME", tmp.path())
        .args(["build", "--no-cache", "--authfile"])
        .arg(&auth)
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("Pulling"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("SECRET"));
}

#[test]
fn secrets_in_either_cache_area_are_rejected_without_reading() {
    let tmp = tempfile::tempdir().unwrap();
    for name in ["cache-v1", "base-cache-v1"] {
        let area = tmp.path().join(name);
        fs::create_dir(&area).unwrap();
        let options = rpweld::registry::Options {
            authfile: Some(area.join("absent.json")),
            cert_dir: None,
        };
        assert!(
            rpweld::registry::check_cache_secret_paths(&options, tmp.path())
                .unwrap_err()
                .contains("outside cache")
        );
        let options = rpweld::registry::Options {
            authfile: Some(tmp.path().join("absent.json")),
            cert_dir: Some(area),
        };
        assert!(
            rpweld::registry::check_cache_secret_paths(&options, tmp.path())
                .unwrap_err()
                .contains("outside cache")
        );
    }
}

#[test]
fn symlink_generation_and_oversized_new_content_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(tmp.path(), &|| false).unwrap();
    let old = populate(tmp.path(), &lease);
    let moved = tmp.path().join("moved");
    fs::rename(&old, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &old).unwrap();
    assert!(
        cached_base(
            tmp.path(),
            &lease,
            "alpine",
            false,
            limits(),
            || false,
            no_fetch
        )
        .is_err()
    );
    let tmp = tempfile::tempdir().unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(tmp.path(), &|| false).unwrap();
    let mut small = limits();
    small.max_layer_bytes = 1;
    assert!(
        cached_base(
            tmp.path(),
            &lease,
            "alpine",
            false,
            small,
            || false,
            |_, p| fixture(p, 1)
        )
        .is_err()
    );
    assert!(
        !fs::read_dir(tmp.path().join("base-cache-v1/refs"))
            .unwrap()
            .any(|e| e.unwrap().path().extension().is_some_and(|x| x == "json"))
    );
}
