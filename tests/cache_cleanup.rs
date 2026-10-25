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
    drop(cache);
    drop(lease);
    let report = cleanup_apply::apply(
        &store,
        cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    assert!(report.removed.is_empty());
    assert!(store.join("store.lock").exists());
    assert!(store.join("cache-v2/publication.lock").exists());
    assert!(a.exists() && b.exists());

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
