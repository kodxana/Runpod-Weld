#![cfg(target_os = "linux")]
use rpweld::{
    image::Limits,
    oci::{BlobStore, Descriptor, ManagedCache},
    store_lease::StoreLease,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

fn limits() -> Limits {
    Limits {
        max_metadata_bytes: 65536,
        max_total_metadata_bytes: 262144,
        max_descriptors: 32,
        max_layer_bytes: 4096,
        max_total_layer_bytes: 8192,
    }
}
fn key(n: u8) -> String {
    format!("{n:064x}")
}
fn blob(store: &BlobStore, media_type: &str, bytes: &[u8]) -> Descriptor {
    let descriptor = Descriptor {
        media_type: media_type.into(),
        digest: format!("sha256:{:x}", Sha256::digest(bytes)),
        size: bytes.len() as i64,
        annotations: Default::default(),
        extensions: Default::default(),
    };
    store.ingest(bytes, &descriptor, 65536, || false).unwrap();
    descriptor
}
fn fixture(path: &Path, version: u32) -> Descriptor {
    fs::create_dir(path).unwrap();
    let store = BlobStore::open(path).unwrap();
    let layer = blob(
        &store,
        "application/vnd.oci.image.layer.v1.tar",
        &[42; 4096],
    );
    let config = blob(
        &store,
        "application/vnd.oci.image.config.v1+json",
        &serde_json::to_vec(&json!({
            "architecture": "amd64", "os": "linux", "config": {}, "version": version,
            "rootfs": {"type": "layers", "diff_ids": [layer.digest]}
        }))
        .unwrap(),
    );
    let manifest = blob(
        &store,
        "application/vnd.oci.image.manifest.v1+json",
        &serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config, "layers": [layer]
        }))
        .unwrap(),
    );
    blob(
        &store,
        "application/octet-stream",
        b"unreferenced must not be copied",
    );
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
    layer
}
fn layer_path(root: &Path, layer: &Descriptor) -> PathBuf {
    root.join("blobs/sha256")
        .join(layer.digest.strip_prefix("sha256:").unwrap())
}
fn inode(path: &Path) -> (u64, u64) {
    let m = fs::metadata(path).unwrap();
    (m.dev(), m.ino())
}
fn publish(cache: &ManagedCache<'_>, source: &Path, n: u8) -> PathBuf {
    cache
        .publish(
            source,
            &key(n),
            limits(),
            &[vec![b"payload".to_vec()]],
            1024,
            &|| false,
        )
        .unwrap()
}

use rpweld::{cleanup_apply, cleanup_plan, store_inventory};

struct CacheFixture {
    _temp: tempfile::TempDir,
    store: PathBuf,
    source: PathBuf,
    layer: Descriptor,
    a: PathBuf,
    b: PathBuf,
}
impl CacheFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let source = temp.path().join("source");
        let second = temp.path().join("second");
        let layer = fixture(&source, 1);
        fixture(&second, 2);
        let lease = StoreLease::shared(&store, &|| false).unwrap();
        let cache = ManagedCache::open(&store, &lease, &|| false).unwrap();
        let a = publish(&cache, &source, 1);
        let b = publish(&cache, &second, 2);
        drop(cache);
        drop(lease);
        Self {
            _temp: temp,
            store,
            source,
            layer,
            a,
            b,
        }
    }
    fn tag(&self) -> PathBuf {
        let reference = "example/retained:latest";
        let path = self.store.join(format!(
            "tag-{:x}.json",
            Sha256::digest(reference.as_bytes())
        ));
        fs::write(
            &path,
            serde_json::to_vec(&json!({"reference":reference,"image":self.b})).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    fn prune(&self) -> cleanup_apply::Report {
        cleanup_apply::apply(
            &self.store,
            cleanup_plan::Request::CachePrune,
            Default::default(),
            || false,
        )
        .unwrap()
    }
    fn verify_retained(&self) {
        let lease = StoreLease::shared(&self.store, &|| false).unwrap();
        let cache = ManagedCache::open(&self.store, &lease, &|| false).unwrap();
        assert!(
            cache
                .lookup(&key(2), limits(), 1024, 1, &|| false)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            fs::read(layer_path(&self.b, &self.layer)).unwrap(),
            vec![42; 4096]
        );
    }
}

#[test]
fn shared_blob_survives_one_entry_then_all_references_reclaim_once() {
    let f = CacheFixture::new();
    let tag = f.tag();
    let pool = layer_path(&f.store.join("cache-v2/content"), &f.layer);
    let before = inode(&pool);
    let p = cleanup_plan::inspect(
        &f.store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    assert!(p.consistent, "{p:#?}");
    assert_eq!(p.candidates.len(), 3);
    let r = f.prune();
    assert_eq!(r.status, "complete", "{r:#?}");
    assert_eq!(r.removed.len(), 3);
    assert!(!f.a.exists() && f.b.exists());
    assert_eq!(inode(&pool), before);
    assert_eq!(fs::metadata(&pool).unwrap().nlink(), 3);
    f.verify_retained();
    fs::remove_file(tag).unwrap();
    let r = f.prune();
    assert_eq!(r.status, "complete", "{r:#?}");
    assert_eq!(r.removed.len(), 4);
    assert!(!pool.exists());
    assert!(f.prune().removed.is_empty());
    let lease = StoreLease::shared(&f.store, &|| false).unwrap();
    let cache = ManagedCache::open(&f.store, &lease, &|| false).unwrap();
    publish(&cache, &f.source, 3);
    assert!(
        cache
            .lookup(&key(3), limits(), 1024, 1, &|| false)
            .unwrap()
            .is_some()
    );
}

#[test]
fn unreferenced_anchor_without_pool_is_retired_without_chmod_or_truncation() {
    use std::{cell::Cell, io::Read};
    let f = CacheFixture::new();
    f.tag();
    let journal = f.store.join("cache-v2/retirement.json");
    let armed = Cell::new(false);
    let r = cleanup_apply::apply(
        &f.store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || {
            if journal.exists() {
                armed.set(true);
                false
            } else {
                armed.get()
            }
        },
    )
    .unwrap();
    assert_eq!(r.status, "failed");
    assert!(!f.a.exists() && !journal.exists());
    let retained: std::collections::HashSet<_> = fs::read_dir(f.b.join("blobs/sha256"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let digest = fs::read_dir(f.store.join("cache-v2/objects"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .find(|n| !retained.contains(n))
        .unwrap();
    let object = f.store.join("cache-v2/objects").join(&digest);
    let anchor = object.join("blobs/sha256").join(&digest);
    let before = fs::read(&anchor).unwrap();
    let mut handle = fs::File::open(&anchor).unwrap();
    let mode = handle.metadata().unwrap().mode();
    fs::remove_file(f.store.join("cache-v2/content/blobs/sha256").join(&digest)).unwrap();
    assert_eq!(handle.metadata().unwrap().nlink(), 1);
    let r = f.prune();
    assert_eq!(r.status, "complete", "{r:#?}");
    assert_eq!(r.removed.len(), 2);
    assert!(!object.exists());
    assert_eq!(handle.metadata().unwrap().nlink(), 0);
    assert_eq!(handle.metadata().unwrap().mode(), mode);
    let mut after = Vec::new();
    handle.read_to_end(&mut after).unwrap();
    assert_eq!(after, before);
    f.verify_retained();
}

#[test]
fn every_entry_and_object_crash_boundary_recovers_deletion_only() {
    use std::cell::Cell;
    for kind in ["entry", "object"] {
        for phase in 0..6 {
            let f = CacheFixture::new();
            f.tag();
            let journal = f.store.join("cache-v2/retirement.json");
            let armed = Cell::new(false);
            let hit = Cell::new(false);
            let r = cleanup_apply::apply(
                &f.store,
                cleanup_plan::Request::CachePrune,
                Default::default(),
                || {
                    let Ok(bytes) = fs::read(&journal) else {
                        if phase == 5 && armed.get() {
                            hit.set(true);
                            return true;
                        }
                        return false;
                    };
                    let j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    if j["kind"] != kind {
                        return false;
                    }
                    armed.set(true);
                    let key = j["key"].as_str().unwrap();
                    let parent = if kind == "entry" {
                        "entries"
                    } else {
                        "objects"
                    };
                    let source = f.store.join("cache-v2").join(parent).join(key);
                    let retired = f
                        .store
                        .join("cache-v2")
                        .join(parent)
                        .join(format!(".retire-{key}"));
                    let stop = if kind == "entry" {
                        let count = fs::read_dir(retired.join("blobs/sha256"))
                            .map(|d| d.count())
                            .unwrap_or(0);
                        match phase {
                            0 => source.exists(),
                            1 => retired.exists() && count == 3,
                            2 => retired.exists() && count > 0 && count < 3,
                            3 => retired.exists() && count == 0,
                            4 => !source.exists() && !retired.exists(),
                            _ => false,
                        }
                    } else {
                        let pool = f.store.join("cache-v2/content/blobs/sha256").join(key);
                        let anchor = retired.join("blobs/sha256").join(key);
                        match phase {
                            0 => source.exists() && pool.exists(),
                            1 => source.exists() && !pool.exists(),
                            2 => retired.exists() && anchor.exists(),
                            3 => retired.exists() && !anchor.exists(),
                            4 => !source.exists() && !retired.exists(),
                            _ => false,
                        }
                    };
                    hit.set(stop);
                    stop
                },
            )
            .unwrap();
            assert!(hit.get(), "unreached {kind}/{phase}: {r:#?}");
            assert_eq!(r.status, "failed", "{kind}/{phase}: {r:#?}");
            assert!(r.failure.as_deref().unwrap().contains("cancel"), "{r:#?}");
            if phase < 5 {
                assert!(journal.exists());
                let bytes = fs::read(&journal).unwrap();
                let lease = StoreLease::shared(&f.store, &|| false).unwrap();
                let error = ManagedCache::open(&f.store, &lease, &|| false)
                    .err()
                    .unwrap()
                    .to_string();
                assert!(error.contains("retirement pending"), "{error}");
                drop(lease);
                let p = cleanup_plan::inspect(
                    &f.store,
                    cleanup_plan::Request::CachePrune,
                    Default::default(),
                    || false,
                )
                .unwrap();
                assert!(p.candidates.is_empty());
                assert_eq!(fs::read(&journal).unwrap(), bytes);
            } else {
                assert!(!journal.exists());
                f.verify_retained();
            }
            let r = f.prune();
            assert_eq!(r.status, "complete", "recovery {kind}/{phase}: {r:#?}");
            assert_eq!(r.recovered.len(), usize::from(phase < 5));
            assert!(!journal.exists() && !f.a.exists());
            f.verify_retained();
        }
    }
}

#[test]
fn any_barrier_presence_blocks_open_lookup_and_publish_without_parsing() {
    let f = CacheFixture::new();
    let lease = StoreLease::shared(&f.store, &|| false).unwrap();
    let cache = ManagedCache::open(&f.store, &lease, &|| false).unwrap();
    let journal = f.store.join("cache-v2/retirement.json");
    for symlink_barrier in [false, true] {
        if symlink_barrier {
            symlink("missing", &journal).unwrap();
        } else {
            fs::write(&journal, b"not json").unwrap();
        }
        assert!(
            ManagedCache::open(&f.store, &lease, &|| false)
                .err()
                .unwrap()
                .to_string()
                .contains("retirement pending")
        );
        assert!(
            cache
                .lookup(&key(1), limits(), 1024, 1, &|| false)
                .unwrap_err()
                .to_string()
                .contains("retirement pending")
        );
        assert!(
            cache
                .publish(
                    &f.source,
                    &key(3),
                    limits(),
                    &[vec![b"payload".to_vec()]],
                    1024,
                    &|| false
                )
                .unwrap_err()
                .to_string()
                .contains("retirement pending")
        );
        fs::remove_file(&journal).unwrap();
    }
}

fn interrupt_entry(f: &CacheFixture) -> PathBuf {
    let retired = f
        .store
        .join("cache-v2/entries")
        .join(format!(".retire-{}", key(1)));
    let r = cleanup_apply::apply(
        &f.store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || retired.exists(),
    )
    .unwrap();
    assert_eq!(r.status, "failed", "{r:#?}");
    assert!(retired.exists());
    retired
}

#[test]
fn tampered_retirement_or_aliases_never_mutate_or_follow_external_canaries() {
    for change in [
        "identity",
        "namespace",
        "path",
        "extra",
        "alias",
        "both",
        "symlink",
        "owner",
    ] {
        let f = CacheFixture::new();
        f.tag();
        let retired = interrupt_entry(&f);
        let journal = f.store.join("cache-v2/retirement.json");
        let canary = f._temp.path().join("canary");
        fs::write(&canary, b"EXTERNAL_CANARY").unwrap();
        let canary_id = inode(&canary);
        let mut j: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        match change {
            "identity" => j["nodes"][format!("entries/{}", key(1))]["identity"]["inode"] = json!(0),
            "namespace" => j["namespace"]["inode"] = json!(0),
            "path" => {
                let node = j["nodes"][format!("entries/{}", key(1))].clone();
                j["nodes"]["../canary"] = node;
            }
            "extra" => {
                symlink(&canary, retired.join("extra")).unwrap();
            }
            "alias" => {
                fs::hard_link(
                    layer_path(&retired, &f.layer),
                    f._temp.path().join("external-alias"),
                )
                .unwrap();
            }
            "both" => {
                fs::create_dir(&f.a).unwrap();
            }
            "symlink" => {
                fs::remove_file(&journal).unwrap();
                symlink(&canary, &journal).unwrap();
            }
            "owner" => {
                fs::write(retired.join("weld-cache-entry.json"), b"{}").unwrap();
            }
            _ => unreachable!(),
        }
        if ["identity", "namespace", "path"].contains(&change) {
            fs::write(&journal, serde_json::to_vec(&j).unwrap()).unwrap();
        }
        let before = inode(&retired);
        let r = f.prune();
        assert_eq!(r.status, "failed", "{change}: {r:#?}");
        assert!(
            r.removed.is_empty() && r.recovered.is_empty(),
            "{change}: {r:#?}"
        );
        assert_eq!(inode(&retired), before);
        assert!(layer_path(&retired, &f.layer).exists());
        assert_eq!(inode(&canary), canary_id);
        assert_eq!(fs::read(&canary).unwrap(), b"EXTERNAL_CANARY");
    }
}

fn legacy_transaction(store: &Path) -> Option<PathBuf> {
    fs::read_dir(store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".cleanup-txn-")
                && p.join("journal.json").exists()
        })
}

#[test]
fn validate_every_mixed_journal_before_any_recovery_mutation() {
    for defect in ["none", "cache", "legacy", "unknown", "overlap"] {
        let f = CacheFixture::new();
        let outside = f._temp.path().join("unrelated-target");
        fs::write(&outside, b"KEEP").unwrap();
        let reference = "docker.io/example/unrelated:latest";
        let tag = f.store.join(format!(
            "tag-{:x}.json",
            Sha256::digest(reference.as_bytes())
        ));
        fs::write(
            &tag,
            serde_json::to_vec(&json!({"reference":reference,"image":outside})).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&tag, fs::Permissions::from_mode(0o600)).unwrap();
        let r = cleanup_apply::apply(
            &f.store,
            cleanup_plan::Request::ImageRemove(cleanup_plan::TagId::parse(reference).unwrap()),
            Default::default(),
            || legacy_transaction(&f.store).is_some(),
        )
        .unwrap();
        assert_eq!(r.status, "failed", "{r:#?}");
        let tx = legacy_transaction(&f.store).unwrap();
        let held = f._temp.path().join("held-transaction");
        fs::rename(&tx, &held).unwrap();
        f.tag();
        let retired = interrupt_entry(&f);
        fs::rename(&held, &tx).unwrap();
        let journal = f.store.join("cache-v2/retirement.json");
        match defect {
            "cache" => fs::write(&journal, b"{}").unwrap(),
            "legacy" => fs::write(tx.join("journal.json"), b"{}").unwrap(),
            "unknown" => {
                let unknown = f.store.join(".cleanup-txn-unknown");
                fs::create_dir(&unknown).unwrap();
                fs::set_permissions(&unknown, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(unknown.join("keep"), b"unknown").unwrap();
            }
            "overlap" => {
                let second = f.store.join(".cleanup-txn-overlap");
                fs::create_dir(&second).unwrap();
                fs::set_permissions(&second, fs::Permissions::from_mode(0o700)).unwrap();
                let mut j: serde_json::Value =
                    serde_json::from_slice(&fs::read(tx.join("journal.json")).unwrap()).unwrap();
                let m = fs::metadata(&second).unwrap();
                j["transaction"] = json!({"device":m.dev(),"inode":m.ino()});
                fs::write(second.join("journal.json"), serde_json::to_vec(&j).unwrap()).unwrap();
                fs::set_permissions(
                    second.join("journal.json"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            _ => (),
        }
        let before = inode(&retired);
        let r = f.prune();
        if defect == "none" {
            assert_eq!(r.status, "complete", "{r:#?}");
            assert_eq!(r.recovered.len(), 2);
            assert!(!tx.exists() && !retired.exists());
            f.verify_retained();
        } else {
            assert_eq!(r.status, "failed", "{defect}: {r:#?}");
            assert!(
                r.removed.is_empty() && r.recovered.is_empty(),
                "{defect}: {r:#?}"
            );
            assert!(tx.join("journal.json").exists() && journal.exists());
            assert_eq!(inode(&retired), before);
        }
        assert_eq!(fs::read(&outside).unwrap(), b"KEEP");
        assert!(tag.exists());
    }
}

#[test]
fn mixed_build_payload_and_cache_retirement_validate_before_recovery() {
    use rpweld::build_record::{BuildRecord, Component, Owned, Phase, identity};
    let f = CacheFixture::new();
    let lease = StoreLease::shared(&f.store, &|| false).unwrap();
    let mut build = BuildRecord::allocate(&f.store, &lease, None, None, vec![], false).unwrap();
    let work = build.path.join("work");
    fs::create_dir(&work).unwrap();
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(work.join("keep"), b"BUILD_PAYLOAD").unwrap();
    build
        .update(&lease, |r| {
            r.phase = Phase::Failed;
            r.owned.push(Owned {
                components: vec![Component::try_from("work".to_owned()).unwrap()],
                identity: identity(&fs::metadata(&work).unwrap()),
            });
        })
        .unwrap();
    let id =
        cleanup_plan::BuildId::parse(build.path.file_name().unwrap().to_str().unwrap()).unwrap();
    drop(build);
    drop(lease);
    let r = cleanup_apply::apply(
        &f.store,
        cleanup_plan::Request::BuildRemove(id),
        Default::default(),
        || legacy_transaction(&f.store).is_some_and(|tx| tx.join("payload").exists()),
    )
    .unwrap();
    assert_eq!(r.status, "failed", "{r:#?}");
    let tx = legacy_transaction(&f.store).unwrap();
    let held = f._temp.path().join("held-build");
    fs::rename(&tx, &held).unwrap();
    fs::rename(held.join("payload"), &work).unwrap();
    f.tag();
    interrupt_entry(&f);
    fs::rename(&work, held.join("payload")).unwrap();
    fs::rename(&held, &tx).unwrap();
    let r = f.prune();
    assert_eq!(r.status, "complete", "{r:#?}");
    assert_eq!(r.recovered.len(), 2);
    assert_eq!(fs::read(work.join("keep")).unwrap(), b"BUILD_PAYLOAD");
    f.verify_retained();
}

#[test]
fn retirement_crash_child() {
    let Some(store) = std::env::var_os("RPWELD_RETIREMENT_CHILD_STORE") else {
        return;
    };
    let store = PathBuf::from(store);
    let phase = std::env::var("RPWELD_RETIREMENT_CHILD_PHASE").unwrap();
    let _ = cleanup_apply::apply(
        &store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || {
            let Ok(bytes) = fs::read(store.join("cache-v2/retirement.json")) else {
                return false;
            };
            let j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let key = j["key"].as_str().unwrap();
            let kind = j["kind"].as_str().unwrap();
            let parent = if kind == "entry" {
                "entries"
            } else {
                "objects"
            };
            let retired = store
                .join("cache-v2")
                .join(parent)
                .join(format!(".retire-{key}"));
            if (phase == "entry-renamed" && kind == "entry" && retired.exists())
                || (phase == "anchor-unlinked"
                    && kind == "object"
                    && retired.exists()
                    && !retired.join("blobs/sha256").join(key).exists())
            {
                unsafe {
                    libc::_exit(73);
                }
            }
            false
        },
    )
    .unwrap();
    panic!("crash boundary not reached");
}

#[test]
fn abrupt_process_exit_releases_leases_and_explicit_recovery_restores_access() {
    for phase in ["entry-renamed", "anchor-unlinked"] {
        let f = CacheFixture::new();
        f.tag();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "retirement_crash_child"])
            .env("RPWELD_RETIREMENT_CHILD_STORE", &f.store)
            .env("RPWELD_RETIREMENT_CHILD_PHASE", phase)
            .output()
            .unwrap()
            .status;
        assert_eq!(status.code(), Some(73));
        let lease = StoreLease::shared(&f.store, &|| false).unwrap();
        assert!(
            ManagedCache::open(&f.store, &lease, &|| false)
                .err()
                .unwrap()
                .to_string()
                .contains("retirement pending")
        );
        drop(lease);
        let r = f.prune();
        assert_eq!(r.status, "complete", "{phase}: {r:#?}");
        assert_eq!(r.recovered.len(), 1);
        f.verify_retained();
    }
}

struct AccessWatch(fs::File);
impl AccessWatch {
    fn new(path: &Path) -> Self {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        };
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0);
        let file = unsafe { fs::File::from_raw_fd(fd) };
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert!(
            unsafe { libc::inotify_add_watch(file.as_raw_fd(), path.as_ptr(), libc::IN_ACCESS) }
                >= 0
        );
        Self(file)
    }
    fn accessed(&self) -> bool {
        use std::io::Read;
        match (&self.0).read(&mut [0u8; 4096]) {
            Ok(n) => n != 0,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(e) => panic!("inotify: {e}"),
        }
    }
}

#[test]
fn credential_hardlinks_are_rejected_before_inventory_or_maintenance_reads() {
    for target in ["namespace", "entry", "index", "receipt", "object", "blob"] {
        let f = CacheFixture::new();
        let path = match target {
            "namespace" => f.store.join("cache-v2/weld-cache-owner.json"),
            "entry" => f.a.join("weld-cache-entry.json"),
            "index" => f.a.join("index.json"),
            "receipt" => f.a.join("weld-copy-targets.json"),
            "object" => f
                .store
                .join("cache-v2/objects")
                .join(&f.layer.digest[7..])
                .join("weld-cache-blob.json"),
            _ => layer_path(&f.a, &f.layer),
        };
        let canary = f.store.join("credentials.json");
        fs::hard_link(&path, &canary).unwrap();
        let watch = AccessWatch::new(&canary);
        let i = store_inventory::inspect(&f.store, Default::default(), || false).unwrap();
        assert!(!i.scan_complete);
        let r = f.prune();
        assert!(
            r.removed.is_empty() && r.failure.is_some(),
            "{target}: {r:#?}"
        );
        assert!(!watch.accessed(), "read credential alias {target}");
        assert_eq!(inode(&canary), inode(&path));
    }
}

fn file_usage(root: &Path) -> (u64, u64, u64) {
    fn walk(
        root: &Path,
        files: &mut std::collections::BTreeMap<(u64, u64), (u64, u64)>,
        logical: &mut u64,
    ) {
        for e in fs::read_dir(root).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                walk(&p, files, logical);
            } else if m.is_file() {
                *logical += m.len();
                files.insert((m.dev(), m.ino()), (m.len(), m.blocks() * 512));
            }
        }
    }
    let mut files = Default::default();
    let mut logical = 0;
    walk(root, &mut files, &mut logical);
    (
        logical,
        files.values().map(|v| v.0).sum(),
        files.values().map(|v| v.1).sum(),
    )
}

#[test]
fn inventory_and_plan_have_exact_inode_totals_and_cancellation_is_incomplete() {
    use std::cell::Cell;
    let f = CacheFixture::new();
    let expected = file_usage(&f.store.join("cache-v2"));
    let calls = Cell::new(0);
    let i = store_inventory::inspect(&f.store, Default::default(), || {
        calls.set(calls.get() + 1);
        false
    })
    .unwrap();
    assert!(i.scan_complete && i.best_effort);
    assert_eq!(
        (
            i.cache_usage.logical_bytes,
            i.cache_usage.unique_logical_bytes,
            i.cache_usage.allocated_bytes
        ),
        expected
    );
    let p = cleanup_plan::inspect(
        &f.store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    let owner = fs::metadata(f.store.join("cache-v2/weld-cache-owner.json")).unwrap();
    let lock = fs::metadata(f.store.join("cache-v2/publication.lock")).unwrap();
    assert_eq!(
        p.estimate.unique_logical_bytes,
        expected.1 - owner.len() - lock.len()
    );
    assert_eq!(
        p.estimate.reclaimable_file_allocated_bytes,
        expected.2 - (owner.blocks() + lock.blocks()) * 512
    );
    let total = calls.get();
    let mut census = false;
    let mut usage = false;
    for threshold in (1..total).step_by(7) {
        let n = Cell::new(0);
        let i = store_inventory::inspect(&f.store, Default::default(), || {
            n.set(n.get() + 1);
            n.get() >= threshold
        })
        .unwrap();
        assert!(!i.scan_complete);
        census |= i.cache_usage.files == 0;
        usage |= i.cache_usage.files > 0;
    }
    assert!(census && usage);
    assert!(f.a.exists() && f.b.exists());
}

#[test]
fn capped_diagnostics_cannot_hide_cache_provenance_failure() {
    let f = CacheFixture::new();
    // Build payload diagnostics sort before cache-v2 and fill the issue cap.
    let legacy = f.store.join("build-old");
    fs::create_dir(&legacy).unwrap();
    for n in 0..1024 {
        symlink("missing", legacy.join(format!("link-{n:04}"))).unwrap();
    }
    fs::write(f.store.join("cache-v2/weld-cache-owner.json"), b"{}").unwrap();
    let i = store_inventory::inspect(&f.store, Default::default(), || false).unwrap();
    assert_eq!(i.issues.len(), 1024);
    assert!(i.issues_truncated && !i.scan_complete);
    let p = cleanup_plan::inspect(
        &f.store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    assert!(!p.consistent && p.candidates.is_empty());
}

#[test]
#[ignore = "requires isolated user/mount namespace with CAP_SYS_ADMIN"]
fn cache_directory_file_and_retirement_bind_mounts_are_refused() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0
    );
    struct Mount(CString);
    impl Drop for Mount {
        fn drop(&mut self) {
            assert_eq!(
                unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) },
                0
            );
        }
    }
    for target in ["entry", "file", "journal"] {
        let f = CacheFixture::new();
        f.tag();
        let path = match target {
            "entry" => f.a.clone(),
            "file" => layer_path(&f.a, &f.layer),
            _ => {
                interrupt_entry(&f);
                f.store.join("cache-v2/retirement.json")
            }
        };
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    path.as_ptr(),
                    path.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0
        );
        let mounted = Mount(path);
        let i = store_inventory::inspect(&f.store, Default::default(), || false).unwrap();
        assert!(!i.scan_complete);
        let r = f.prune();
        assert_eq!(r.status, "failed", "{target}: {r:#?}");
        assert!(r.removed.is_empty() && r.recovered.is_empty());
        assert!(f.b.exists());
        drop(mounted);
        let r = f.prune();
        assert_eq!(r.status, "complete", "{target}: {r:#?}");
        f.verify_retained();
    }
}

#[test]
fn cancellation_during_pending_scan_preserves_primary_error_and_journal() {
    use std::cell::Cell;
    let f = CacheFixture::new();
    f.tag();
    let retired = interrupt_entry(&f);
    let journal = f.store.join("cache-v2/retirement.json");
    let before = fs::read(&journal).unwrap();
    let n = Cell::new(0);
    let r = cleanup_apply::apply(
        &f.store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || {
            n.set(n.get() + 1);
            n.get() >= 10
        },
    )
    .unwrap();
    assert_eq!(r.status, "failed");
    assert!(r.failure.as_deref().unwrap().contains("cancel"), "{r:#?}");
    assert!(r.removed.is_empty() && r.recovered.is_empty());
    assert_eq!(fs::read(&journal).unwrap(), before);
    assert!(layer_path(&retired, &f.layer).exists());
    assert_eq!(f.prune().status, "complete");
    f.verify_retained();
}

#[test]
fn interrupted_publication_is_unknown_without_repair_or_adoption() {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    drop(cache);
    drop(lease);
    let pending = t.path().join("cache-v2/entries/.publish-interrupted");
    fs::create_dir(&pending).unwrap();
    let canary = pending.join("unfinished");
    fs::write(&canary, b"preserve").unwrap();
    let before = inode(&canary);
    let i = store_inventory::inspect(t.path(), Default::default(), || false).unwrap();
    assert!(!i.scan_complete);
    let r = cleanup_apply::apply(
        t.path(),
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    assert!(r.removed.is_empty() && r.failure.is_some());
    assert_eq!(inode(&canary), before);
    assert_eq!(fs::read(canary).unwrap(), b"preserve");
}

#[test]
fn census_counts_shared_pool_anchor_and_entries_once_and_never_creates_locks() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let store = t.path().join("store");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let lease = StoreLease::shared(&store, &|| false).unwrap();
    let cache = ManagedCache::open(&store, &lease, &|| false).unwrap();
    let a = publish(&cache, &source, 1);
    let b = publish(&cache, &source, 2);
    assert_eq!(
        inode(&layer_path(&a, &layer)),
        inode(&layer_path(&b, &layer))
    );
    assert_eq!(fs::metadata(layer_path(&a, &layer)).unwrap().nlink(), 4);
    let i = store_inventory::inspect(&store, Default::default(), || false).unwrap();
    assert!(i.scan_complete, "{:?}", i.issues);
    assert_eq!(i.stages.len(), 2);
    assert!(
        i.stages
            .iter()
            .all(|e| e.protected && e.status == store_inventory::Status::Unknown)
    );
    assert_eq!(i.cache_usage.files, 25); // 12 blob paths, 8 entry records, 3 object records, 2 namespace files
    assert_eq!(i.cache_usage.shared_hardlink_paths, 9);
    assert_eq!(
        i.usage.unique_logical_bytes,
        i.cache_usage.unique_logical_bytes
    );
    assert_eq!(i.builds_usage.files, 0);
    let busy = cleanup_plan::inspect(
        &store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    assert_eq!(busy.status, "store_busy");
    assert!(busy.candidates.is_empty());
    let busy_apply = cleanup_apply::apply(
        &store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    assert_eq!(busy_apply.status, "store_busy");
    assert!(busy_apply.removed.is_empty());
    drop(cache);
    drop(lease);
    let report = cleanup_apply::apply(
        &store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    assert_eq!(report.status, "complete", "{report:#?}");
    assert_eq!(report.removed.len(), 5);
    assert!(store.join("store.lock").exists());
    assert!(store.join("cache-v2/publication.lock").exists());
    assert!(!a.exists() && !b.exists());
    assert_eq!(
        fs::read_dir(store.join("cache-v2/objects"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        fs::read_dir(store.join("cache-v2/content/blobs/sha256"))
            .unwrap()
            .count(),
        0
    );

    let empty = tempfile::tempdir().unwrap();
    fs::set_permissions(empty.path(), fs::Permissions::from_mode(0o700)).unwrap();
    store_inventory::inspect(empty.path(), Default::default(), || false).unwrap();
    assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
    let missing = empty.path().join("absent");
    store_inventory::inspect(&missing, Default::default(), || false).unwrap();
    assert!(!missing.exists());
}

#[test]
fn external_links_unknown_children_and_budgets_protect_the_whole_namespace() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let store = t.path().join("store");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let lease = StoreLease::shared(&store, &|| false).unwrap();
    let cache = ManagedCache::open(&store, &lease, &|| false).unwrap();
    let a = publish(&cache, &source, 1);
    drop(cache);
    drop(lease);
    let alias = t.path().join("external");
    fs::hard_link(layer_path(&a, &layer), &alias).unwrap();
    let i = store_inventory::inspect(&store, Default::default(), || false).unwrap();
    assert!(!i.scan_complete);
    assert!(
        i.stages
            .iter()
            .all(|e| e.ownership == store_inventory::Ownership::Unknown)
    );
    let p = cleanup_plan::inspect(
        &store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    assert!(!p.consistent && p.candidates.is_empty());
    fs::remove_file(alias).unwrap();
    symlink(t.path(), store.join("cache-v2/unknown")).unwrap();
    assert!(
        !store_inventory::inspect(&store, Default::default(), || false)
            .unwrap()
            .scan_complete
    );
    fs::remove_file(store.join("cache-v2/unknown")).unwrap();
    for limits in [
        store_inventory::Limits {
            max_entries: 2,
            ..Default::default()
        },
        store_inventory::Limits {
            max_depth: 3,
            ..Default::default()
        },
        store_inventory::Limits {
            max_metadata_bytes: 100,
            ..Default::default()
        },
    ] {
        let p = cleanup_plan::inspect(&store, cleanup_plan::Request::CachePrune, limits, || false)
            .unwrap();
        assert!(!p.consistent && p.candidates.is_empty());
    }
    let p = cleanup_plan::inspect(
        &store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || true,
    )
    .unwrap();
    assert!(!p.consistent && p.candidates.is_empty());
    fs::write(a.join("weld-cache-entry.json"), b"{}").unwrap();
    assert!(
        !store_inventory::inspect(&store, Default::default(), || false)
            .unwrap()
            .scan_complete
    );
    assert!(layer_path(&a, &layer).exists());
}
