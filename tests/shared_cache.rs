#![cfg(target_os = "linux")]
use rpweld::{
    image::{self, Limits},
    oci::{BlobStore, Descriptor, ManagedCache},
    store_lease::StoreLease,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    fs,
    os::unix::fs::{MetadataExt, symlink},
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
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
fn lookup(cache: &ManagedCache<'_>, n: u8) -> bool {
    cache
        .lookup(&key(n), limits(), 1024, 1, &|| false)
        .unwrap()
        .is_some()
}

#[test]
fn shares_only_verified_pool_inodes_and_never_adopts_mutable_source() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let a = publish(&cache, &source, 1);
    let b = publish(&cache, &source, 2);
    let pool = layer_path(&t.path().join("cache-v2/content"), &layer);
    assert_eq!(inode(&pool), inode(&layer_path(&a, &layer)));
    assert_eq!(inode(&pool), inode(&layer_path(&b, &layer)));
    assert_ne!(inode(&pool), inode(&layer_path(&source, &layer)));
    assert_eq!(fs::metadata(&pool).unwrap().nlink(), 4); // durable anchor, pool, two entries
    assert_eq!(
        fs::read_dir(t.path().join("cache-v2/content/blobs/sha256"))
            .unwrap()
            .count(),
        3
    );
    fs::write(
        layer_path(&source, &layer),
        b"mutable source was overwritten",
    )
    .unwrap();
    assert!(lookup(&cache, 1));
    assert!(lookup(&cache, 2));
    assert!(
        StoreLease::try_exclusive_existing(t.path())
            .unwrap()
            .is_none()
    );
}

#[test]
fn rejects_preseeded_pool_hardlink_without_touching_external_source() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let original = layer_path(&source, &layer);
    let pooled = layer_path(&t.path().join("cache-v2/content"), &layer);
    fs::hard_link(&original, &pooled).unwrap();
    let before = inode(&original);
    assert!(
        cache
            .publish(&source, &key(1), limits(), &[], 0, &|| false)
            .is_err()
    );
    assert_eq!(inode(&original), before);
    assert_eq!(inode(&pooled), before);
    assert_eq!(fs::read(&original).unwrap(), vec![42; 4096]);
    assert!(!t.path().join("cache-v2/entries").join(key(1)).exists());
}

#[test]
fn rejects_external_alias_added_after_publication_without_touching_it() {
    let t = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let entry = publish(&cache, &source, 1);
    let alias = outside.path().join("mutable-alias");
    fs::hard_link(layer_path(&entry, &layer), &alias).unwrap();
    let before = inode(&alias);
    assert!(cache.lookup(&key(1), limits(), 1024, 1, &|| false).is_err());
    assert!(
        cache
            .publish(&source, &key(2), limits(), &[], 0, &|| false)
            .is_err()
    );
    assert_eq!(inode(&alias), before);
    assert_eq!(fs::read(&alias).unwrap(), vec![42; 4096]);
}

#[test]
fn valid_single_link_blob_without_provenance_is_not_adopted() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let pooled = layer_path(&t.path().join("cache-v2/content"), &layer);
    fs::copy(layer_path(&source, &layer), &pooled).unwrap();
    assert_eq!(fs::metadata(&pooled).unwrap().nlink(), 1);
    let before = inode(&pooled);
    assert!(
        cache
            .publish(&source, &key(1), limits(), &[], 0, &|| false)
            .is_err()
    );
    assert_eq!(inode(&pooled), before);
    assert_eq!(fs::read(pooled).unwrap(), vec![42; 4096]);
}

#[test]
fn durable_owned_object_can_restore_missing_pool_link_but_not_replace_one() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    publish(&cache, &source, 1);
    let pooled = layer_path(&t.path().join("cache-v2/content"), &layer);
    let original = inode(&pooled);
    fs::remove_file(&pooled).unwrap();
    publish(&cache, &source, 2);
    assert_eq!(inode(&pooled), original);
    fs::remove_file(&pooled).unwrap();
    fs::hard_link(layer_path(&source, &layer), &pooled).unwrap();
    let replacement = inode(&pooled);
    assert_ne!(replacement, original);
    assert!(
        cache
            .publish(&source, &key(3), limits(), &[], 0, &|| false)
            .is_err()
    );
    assert_eq!(inode(&pooled), replacement);
}

#[test]
fn lock_waiting_is_cancellable_and_legacy_namespace_is_not_upgraded() {
    use std::os::fd::AsRawFd;
    let t = tempfile::tempdir().unwrap();
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let lock = fs::File::open(t.path().join("cache-v2/publication.lock")).unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let checks = Cell::new(0);
    assert!(
        cache
            .lookup(&key(1), limits(), 0, 0, &|| {
                checks.set(checks.get() + 1);
                checks.get() >= 4
            })
            .is_err()
    );
    drop(lock);
    let owner = t.path().join("cache-v2/weld-cache-owner.json");
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&owner).unwrap()).unwrap();
    record["version"] = json!(1);
    record.as_object_mut().unwrap().remove("objects");
    record.as_object_mut().unwrap().remove("lock");
    let bytes = serde_json::to_vec(&record).unwrap();
    fs::write(&owner, &bytes).unwrap();
    assert!(ManagedCache::open(t.path(), &lease, &|| false).is_err());
    assert_eq!(fs::read(owner).unwrap(), bytes);
}

#[test]
fn does_not_adopt_empty_unmarked_or_replaced_namespaces() {
    let t = tempfile::tempdir().unwrap();
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    fs::create_dir(t.path().join("cache-v2")).unwrap();
    assert!(ManagedCache::open(t.path(), &lease, &|| false).is_err());
    fs::rename(t.path().join("cache-v2"), t.path().join("unmarked")).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    fs::rename(
        t.path().join("cache-v2/entries"),
        t.path().join("saved-entries"),
    )
    .unwrap();
    fs::create_dir(t.path().join("cache-v2/entries")).unwrap();
    assert!(cache.lookup(&key(1), limits(), 1024, 1, &|| false).is_err());
    assert!(ManagedCache::open(t.path(), &lease, &|| false).is_err());
}

#[test]
fn concurrent_initialization_and_publication_validate_one_winner() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    fixture(&source, 1);
    // Initialize only the persistent lease before racing namespace creation.
    drop(StoreLease::shared(t.path(), &|| false).unwrap());
    let barrier = Arc::new(Barrier::new(4));
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let barrier = barrier.clone();
            let root = t.path();
            let source = &source;
            scope.spawn(move || {
                let lease = StoreLease::shared(root, &|| false).unwrap();
                barrier.wait();
                let cache = ManagedCache::open(root, &lease, &|| false).unwrap();
                barrier.wait();
                publish(&cache, source, 1);
                assert!(lookup(&cache, 1));
            });
        }
    });
    assert_eq!(
        fs::read_dir(t.path().join("cache-v2/entries"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        fs::read_dir(t.path().join("cache-v2/content/blobs/sha256"))
            .unwrap()
            .count(),
        3
    );
}

#[test]
fn existing_winner_is_self_consistent_not_required_to_match_losing_execution() {
    let t = tempfile::tempdir().unwrap();
    let a = t.path().join("a");
    fixture(&a, 1);
    let b = t.path().join("b");
    fixture(&b, 2);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let entry = publish(&cache, &a, 1);
    let original = inode(&entry);
    let winner_manifest = image::load_layout(&entry, None, limits(), || false)
        .unwrap()
        .selected;
    let loser_manifest = image::load_layout(&b, None, limits(), || false)
        .unwrap()
        .selected;
    assert_ne!(winner_manifest, loser_manifest);
    let winner_receipt = fs::read(entry.join("weld-copy-targets.json")).unwrap();
    assert_eq!(
        cache
            .publish(
                &b,
                &key(1),
                limits(),
                &[vec![b"payload".to_vec()]],
                1024,
                &|| false
            )
            .unwrap(),
        entry
    );
    assert_eq!(
        cache
            .publish(
                &a,
                &key(1),
                limits(),
                &[vec![b"different".to_vec()]],
                1024,
                &|| false
            )
            .unwrap(),
        entry
    );
    assert_eq!(inode(&entry), original);
    assert_eq!(
        image::load_layout(&entry, None, limits(), || false)
            .unwrap()
            .selected,
        winner_manifest
    );
    assert_eq!(
        image::load_layout(&b, None, limits(), || false)
            .unwrap()
            .selected,
        loser_manifest
    );
    assert_eq!(
        fs::read(entry.join("weld-copy-targets.json")).unwrap(),
        winner_receipt
    );
    // Different receipt contents may reflect nondeterministic path resolution;
    // a different number of COPY instructions is still an invalid same-key hit.
    assert!(
        cache
            .publish(&b, &key(1), limits(), &[], 1024, &|| false)
            .is_err()
    );
    assert!(
        cache
            .publish(&b, &key(1), limits(), &[vec![]], 0, &|| false)
            .is_err()
    );
    assert!(lookup(&cache, 1));
    // Receipt self-integrity is still mandatory, even when a loser's receipt
    // happens to match the corrupted (but structurally valid) bytes.
    fs::write(entry.join("weld-copy-targets.json"), b"[[]]").unwrap();
    assert!(
        cache
            .publish(&b, &key(1), limits(), &[vec![]], 1024, &|| false)
            .is_err()
    );
    fs::create_dir(t.path().join("cache-v2/entries").join(key(2))).unwrap();
    assert!(
        cache
            .publish(&a, &key(2), limits(), &[], 0, &|| false)
            .is_err()
    );
}

#[test]
fn concurrent_distinct_executions_keep_one_complete_winner_and_all_sources() {
    let t = tempfile::tempdir().unwrap();
    let mut sources = Vec::new();
    for n in 0..4 {
        let path = t.path().join(format!("source-{n}"));
        fixture(&path, n);
        let manifest = image::load_layout(&path, None, limits(), || false)
            .unwrap()
            .selected;
        sources.push((
            path,
            manifest,
            vec![vec![format!("resolved-{n}").into_bytes()]],
        ));
    }
    drop(StoreLease::shared(t.path(), &|| false).unwrap());
    let barrier = Barrier::new(4);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = sources
            .iter()
            .map(|(source, _, receipt)| {
                let barrier = &barrier;
                let root = t.path();
                scope.spawn(move || {
                    let lease = StoreLease::shared(root, &|| false).unwrap();
                    let cache = ManagedCache::open(root, &lease, &|| false).unwrap();
                    barrier.wait();
                    cache.publish(source, &key(1), limits(), receipt, 1024, &|| false)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    let path = results[0].as_ref().unwrap();
    assert!(results.iter().all(|r| r.as_ref().unwrap() == path));
    let winner = image::load_layout(path, None, limits(), || false).unwrap();
    let receipt: Vec<Vec<Vec<u8>>> =
        serde_json::from_slice(&fs::read(path.join("weld-copy-targets.json")).unwrap()).unwrap();
    assert!(
        sources
            .iter()
            .any(|(_, manifest, targets)| *manifest == winner.selected && *targets == receipt)
    );
    for (source, manifest, _) in sources {
        assert_eq!(
            image::load_layout(source, None, limits(), || false)
                .unwrap()
                .selected,
            manifest
        );
    }
}

#[test]
fn in_place_corruption_poisoning_is_detected_and_never_repaired() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let a = publish(&cache, &source, 1);
    publish(&cache, &source, 2);
    fs::write(layer_path(&a, &layer), b"corrupt shared inode").unwrap();
    for n in [1, 2] {
        assert!(cache.lookup(&key(n), limits(), 1024, 1, &|| false).is_err());
    }
    assert!(
        cache
            .publish(&source, &key(3), limits(), &[], 0, &|| false)
            .is_err()
    );
    assert!(image::load_layout(&source, None, limits(), || false).is_ok());
    assert!(!t.path().join("cache-v2/entries").join(key(3)).exists());
}

#[test]
fn replacement_corruption_is_isolated_but_even_valid_detached_blobs_are_rejected() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let a = publish(&cache, &source, 1);
    publish(&cache, &source, 2);
    let path = layer_path(&a, &layer);
    fs::remove_file(&path).unwrap();
    fs::copy(layer_path(&source, &layer), &path).unwrap();
    assert!(cache.lookup(&key(1), limits(), 1024, 1, &|| false).is_err());
    assert!(lookup(&cache, 2));
    fs::write(path, b"corrupt detached inode").unwrap();
    assert!(cache.lookup(&key(1), limits(), 1024, 1, &|| false).is_err());
    assert!(lookup(&cache, 2));
}

#[test]
fn receipts_keys_and_metadata_are_bounded_and_validated_on_hits() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    assert!(
        cache
            .publish(&source, "../outside", limits(), &[], 0, &|| false)
            .is_err()
    );
    assert!(
        cache
            .publish(
                &source,
                &key(1),
                limits(),
                &[vec![vec![1; 4097]]],
                10000,
                &|| false
            )
            .is_err()
    );
    assert!(
        cache
            .publish(
                &source,
                &key(1),
                limits(),
                &[vec![b"payload".to_vec()]],
                0,
                &|| false
            )
            .is_err()
    );
    let entry = publish(&cache, &source, 1);
    assert!(cache.lookup(&key(1), limits(), 0, 1, &|| false).is_err());
    assert!(cache.lookup(&key(1), limits(), 1024, 2, &|| false).is_err());
    let receipt = entry.join("weld-copy-targets.json");
    fs::write(&receipt, b"[[]]").unwrap();
    assert!(cache.lookup(&key(1), limits(), 1024, 1, &|| false).is_err());
    fs::write(entry.join("weld-cache-entry.json"), vec![b' '; 16385]).unwrap();
    assert!(cache.lookup(&key(1), limits(), 1024, 1, &|| false).is_err());
}

#[test]
fn symlinks_and_cross_store_inputs_never_bypass_ownership() {
    let t = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let source = outside.path().join("source");
    fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let other_lease = StoreLease::shared(outside.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    assert!(
        cache
            .publish(&source, &key(1), limits(), &[], 0, &|| false)
            .is_err()
    );
    assert!(ManagedCache::open(t.path(), &other_lease, &|| false).is_err());
    symlink(&source, t.path().join("cache-v2/entries").join(key(1))).unwrap();
    assert!(cache.lookup(&key(1), limits(), 1024, 1, &|| false).is_err());
    fs::rename(t.path().join("cache-v2"), t.path().join("original")).unwrap();
    symlink(t.path().join("original"), t.path().join("cache-v2")).unwrap();
    assert!(ManagedCache::open(t.path(), &lease, &|| false).is_err());
}

#[test]
fn cancellation_at_every_check_never_exposes_a_partial_entry() {
    // Establish the exact check count for this fixture, then interrupt each check.
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let count = Cell::new(0);
    cache
        .publish(&source, &key(1), limits(), &[], 0, &|| {
            count.set(count.get() + 1);
            false
        })
        .unwrap();
    let checks = count.get();
    assert!(checks > 10);
    for stop in 1..=checks {
        let attempt = tempfile::tempdir().unwrap();
        let lease = StoreLease::shared(attempt.path(), &|| false).unwrap();
        let cache = ManagedCache::open(attempt.path(), &lease, &|| false).unwrap();
        // Source must be external to the first fixture's leased store.
        let input = attempt.path().join("source");
        fixture(&input, 1);
        let calls = Cell::new(0);
        let result = cache.publish(&input, &key(1), limits(), &[], 0, &|| {
            calls.set(calls.get() + 1);
            calls.get() == stop
        });
        assert!(result.is_err(), "check {stop} did not cancel");
        assert!(
            !attempt
                .path()
                .join("cache-v2/entries")
                .join(key(1))
                .exists(),
            "check {stop} published"
        );
        assert_eq!(
            fs::read_dir(attempt.path().join("cache-v2/entries"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[test]
fn crash_child() {
    let Some(root) = std::env::var_os("RPWELD_SHARED_CACHE_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let stop: usize = std::env::var("RPWELD_SHARED_CACHE_CRASH_STOP")
        .unwrap()
        .parse()
        .unwrap();
    let lease = StoreLease::shared(&root, &|| false).unwrap();
    let cache = ManagedCache::open(&root, &lease, &|| false).unwrap();
    let calls = Cell::new(0);
    cache
        .publish(&root.join("source"), &key(1), limits(), &[], 0, &|| {
            calls.set(calls.get() + 1);
            if calls.get() == stop {
                unsafe { libc::_exit(77) };
            }
            false
        })
        .unwrap();
    // No destructors: also exercise reopening a completed publication.
    unsafe { libc::_exit(78) };
}

#[test]
fn abrupt_process_exit_leaves_only_valid_entries_or_unpublished_debris() {
    let baseline = tempfile::tempdir().unwrap();
    fixture(&baseline.path().join("source"), 1);
    let lease = StoreLease::shared(baseline.path(), &|| false).unwrap();
    let cache = ManagedCache::open(baseline.path(), &lease, &|| false).unwrap();
    let count = Cell::new(0);
    cache
        .publish(
            &baseline.path().join("source"),
            &key(1),
            limits(),
            &[],
            0,
            &|| {
                count.set(count.get() + 1);
                false
            },
        )
        .unwrap();
    for stop in [1, 15, count.get() / 2, count.get() - 1, count.get(), 0] {
        let t = tempfile::tempdir().unwrap();
        fixture(&t.path().join("source"), 1);
        drop(StoreLease::shared(t.path(), &|| false).unwrap());
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_child", "--nocapture"])
            .env("RPWELD_SHARED_CACHE_CRASH_ROOT", t.path())
            .env("RPWELD_SHARED_CACHE_CRASH_STOP", stop.to_string())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(if stop == 0 { 78 } else { 77 }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lease = StoreLease::shared(t.path(), &|| false).unwrap();
        let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
        assert_eq!(
            cache
                .lookup(&key(1), limits(), 0, 0, &|| false)
                .unwrap()
                .is_some(),
            stop == 0
        );
        // Recovery does not adopt/delete crash debris; verified orphan blobs may be reused.
        cache
            .publish(&t.path().join("source"), &key(1), limits(), &[], 0, &|| {
                false
            })
            .unwrap();
        assert!(
            cache
                .lookup(&key(1), limits(), 0, 0, &|| false)
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn missing_blob_never_falls_back_to_pool_and_unknown_entry_children_fail_closed() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let layer = fixture(&source, 1);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
    let a = publish(&cache, &source, 1);
    let b = publish(&cache, &source, 2);
    fs::remove_file(layer_path(&a, &layer)).unwrap();
    assert!(cache.lookup(&key(1), limits(), 1024, 1, &|| false).is_err());
    assert!(lookup(&cache, 2));
    fs::write(b.join("user-file"), b"never adopt me").unwrap();
    assert!(cache.lookup(&key(2), limits(), 1024, 1, &|| false).is_err());
    assert!(
        cache
            .publish(
                &source,
                &key(2),
                limits(),
                &[vec![b"payload".to_vec()]],
                1024,
                &|| false
            )
            .is_err()
    );
    assert_eq!(fs::read(b.join("user-file")).unwrap(), b"never adopt me");
}
