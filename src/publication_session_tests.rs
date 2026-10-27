use crate::oci::publication_session::faults::{self, Timing};
use std::sync::atomic::AtomicBool;

fn owned(path: &Path, limits: image::Limits) -> OwnedCheckpoint {
    OwnedCheckpoint::verified_for_test(path, limits)
        .unwrap()
        .expect("test has FD headroom")
}

fn session_read_count(
    session: &mut PublicationSession<'_, '_, '_>,
    source: &OwnedCheckpoint,
    layer: &Descriptor,
    limits: image::Limits,
    key: char,
) -> (u64, u64) {
    let (result, count, bytes) = super::super::hash_reads::observe(&layer.digest, || {
        session.publish_instruction(source, &key.to_string().repeat(64), limits, &[], 0)
    });
    result.unwrap();
    (count, bytes)
}

#[test]
fn session_reuses_only_later_publications_and_final_is_full() {
    for copies in [1, 4] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        let layer = source_layers(&path, 1, &[42; 4096], copies);
        let mut limits = limits();
        limits.max_total_layer_bytes = layer.size as u64 * copies as u64;
        let source = owned(&path, limits);
        let cancelled = AtomicBool::new(false);
        let control = ManagedControl::for_test(&cancelled).unwrap();
        let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
        let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
        let mut session: crate::oci::PublicationSession<'_, '_, '_> =
            cache.publication_session(&control, limits);
        let first = 7 * copies as u64 + 1;
        assert_eq!(
            session_read_count(&mut session, &source, &layer, limits, 'a'),
            (first, first * 4096)
        );
        let source_id =
            identity(&fs::metadata(path.join("blobs/sha256").join(&layer.digest[7..])).unwrap());
        let pool_id = identity(
            &fs::metadata(
                cache
                    .root
                    .join("content/blobs/sha256")
                    .join(&layer.digest[7..]),
            )
            .unwrap(),
        );
        assert_ne!(source_id, pool_id);
        let source_reads: Vec<_> = session
            .evidence
            .reads
            .iter()
            .filter(|(_, dev, ino, size)| {
                (*dev, *ino, *size) == (source_id.device, source_id.inode, 4096)
            })
            .map(|(boundary, ..)| *boundary)
            .collect();
        assert_eq!(
            source_reads
                .iter()
                .filter(|b| **b == Boundary::Source)
                .count(),
            copies
        );
        assert_eq!(
            source_reads
                .iter()
                .filter(|b| **b == Boundary::IngestSource)
                .count(),
            1
        );
        assert_eq!(
            source_reads
                .iter()
                .filter(|b| **b == Boundary::Ingest)
                .count(),
            1
        );
        let pool_reads = session
            .evidence
            .reads
            .iter()
            .filter(|(_, dev, ino, size)| {
                (*dev, *ino, *size) == (pool_id.device, pool_id.inode, 4096)
            })
            .count();
        assert_eq!(pool_reads, first as usize - source_reads.len());
        for (boundary, expected) in [
            (Boundary::Fresh, 1),
            (Boundary::Anchor, 2 * copies - 1),
            (Boundary::PoolLink, 2 * copies - 1),
            (Boundary::Pending, copies),
            (Boundary::FinalPool, copies),
        ] {
            assert_eq!(
                session
                    .evidence
                    .reads
                    .iter()
                    .filter(|(at, dev, ino, _)| {
                        (*at, *dev, *ino) == (boundary, pool_id.device, pool_id.inode)
                    })
                    .count(),
                expected,
                "{boundary:?}"
            );
        }
        for file in session.evidence.files() {
            // SAFETY: both calls only inspect a live descriptor retained by the session.
            let (status, flags) = unsafe {
                (
                    libc::fcntl(file.as_raw_fd(), libc::F_GETFL),
                    libc::fcntl(file.as_raw_fd(), libc::F_GETFD),
                )
            };
            assert!(status >= 0 && flags >= 0);
            assert_eq!(status & libc::O_ACCMODE, libc::O_RDONLY);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
        let before = session.evidence.reads.len();
        assert_eq!(
            session_read_count(&mut session, &source, &layer, limits, 'b'),
            (0, 0)
        );
        assert_eq!(session.evidence.reads.len(), before);
        assert_eq!(session.evidence.reused, 7 * copies - 1);
        // Every intermediate entry is already usable before stage completion.
        assert!(
            cache
                .lookup(&"b".repeat(64), limits, 0, 0, &|| false)
                .unwrap()
                .is_some()
        );
        session.invalidate();
        assert!(
            session
                .publish_instruction(&source, &"c".repeat(64), limits, &[], 0)
                .is_err()
        );
        let (result, count, _) = super::super::hash_reads::observe(&layer.digest, || {
            cache.publish(source.path(), &"c".repeat(64), limits, &[], 0, &|| false)
        });
        result.unwrap();
        assert_eq!(count, 7 * copies as u64 - 1);
    }
}

#[test]
fn session_new_source_object_never_inherits_digest_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("source-a");
    let b = temp.path().join("source-b");
    let c = temp.path().join("source-c");
    let layer = source(&a, 1);
    source(&b, 2);
    source(&c, 3);
    let payload = |p: &Path| p.join("blobs/sha256").join(&layer.digest[7..]);
    fs::remove_file(payload(&b)).unwrap();
    fs::hard_link(payload(&a), payload(&b)).unwrap();
    let (a, b, c) = (
        owned(&a, limits()),
        owned(&b, limits()),
        owned(&c, limits()),
    );
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
    let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
    let mut session = cache.publication_session(&control, limits());
    assert_eq!(
        session_read_count(&mut session, &a, &layer, limits(), 'a').0,
        8
    );
    assert_eq!(
        session_read_count(&mut session, &b, &layer, limits(), 'b').0,
        0
    );
    assert_eq!(
        session_read_count(&mut session, &c, &layer, limits(), 'c').0,
        1
    );
}

#[test]
fn session_faults_keep_first_admission_and_pending_boundaries() {
    for existing in [false, true] {
        for (boundary, timing, repeats, skip) in [
            (Boundary::Source, Timing::Before, 1, 0),
            (Boundary::Source, Timing::Buffered, 1, 0),
            (Boundary::Source, Timing::After, 1, 0),
            (Boundary::Fresh, Timing::Before, 1, 0),
            (Boundary::Fresh, Timing::Buffered, 1, 0),
            (Boundary::Fresh, Timing::After, 1, 0),
            (Boundary::Anchor, Timing::Before, 1, 0),
            (Boundary::PoolLink, Timing::Before, 1, 0),
            (Boundary::PoolLink, Timing::After, 2, 0),
            (Boundary::Pending, Timing::Buffered, 1, 0),
            (Boundary::Pending, Timing::After, 1, 0),
            (Boundary::Pending, Timing::Buffered, 2, 1),
            (Boundary::FinalPool, Timing::Buffered, 1, 0),
        ] {
            if existing && matches!(boundary, Boundary::Fresh) {
                continue;
            }
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("source");
            let layer = source_layers(&path, 1, &[42; 4096], repeats);
            let source = owned(&path, limits());
            let cancelled = AtomicBool::new(false);
            let control = ManagedControl::for_test(&cancelled).unwrap();
            let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
            let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
            if existing {
                cache
                    .publish(source.path(), &"f".repeat(64), limits(), &[], 0, &|| false)
                    .unwrap();
            }
            let mut session = cache.publication_session(&control, limits());
            let fault = faults::arm(boundary, timing, &layer.digest, skip);
            assert!(
                session
                    .publish_instruction(&source, &"a".repeat(64), limits(), &[], 0)
                    .is_err(),
                "{boundary:?}/{timing:?}"
            );
            assert!(fault.fired(), "unreached {boundary:?}/{timing:?}");
            assert!(session.ended);
            assert!(!cache.root.join("entries").join("a".repeat(64)).exists());
            assert!(
                session
                    .publish_instruction(&source, &"b".repeat(64), limits(), &[], 0)
                    .is_err()
            );
        }
    }
}

#[test]
fn session_reused_pending_faults_invalidate_before_publication() {
    for (boundary, timing) in [
        (Boundary::Pending, Timing::Before),
        (Boundary::Pending, Timing::After),
        (Boundary::Source, Timing::After),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        let layer = source(&path, 1);
        let source = owned(&path, limits());
        let cancelled = AtomicBool::new(false);
        let control = ManagedControl::for_test(&cancelled).unwrap();
        let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
        let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
        let mut session = cache.publication_session(&control, limits());
        session_read_count(&mut session, &source, &layer, limits(), 'a');
        let fault = faults::arm(boundary, timing, &layer.digest, 0);
        assert!(
            session
                .publish_instruction(&source, &"b".repeat(64), limits(), &[], 0)
                .is_err()
        );
        assert!(fault.fired());
        assert!(session.ended);
        assert!(!cache.root.join("entries").join("b".repeat(64)).exists());
    }
}

#[test]
fn session_final_publication_and_new_session_reject_pool_corruption() {
    for final_stage in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        let layer = source(&path, 1);
        let source = owned(&path, limits());
        let cancelled = AtomicBool::new(false);
        let control = ManagedControl::for_test(&cancelled).unwrap();
        let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
        let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
        let mut session = cache.publication_session(&control, limits());
        session_read_count(&mut session, &source, &layer, limits(), 'a');
        session_read_count(&mut session, &source, &layer, limits(), 'b');
        session.invalidate();
        fs::write(
            cache
                .root
                .join("content/blobs/sha256")
                .join(&layer.digest[7..]),
            [99; 4096],
        )
        .unwrap();
        let result = if final_stage {
            cache.publish(source.path(), &"c".repeat(64), limits(), &[], 0, &|| false)
        } else {
            cache
                .publication_session(&control, limits())
                .publish_instruction(&source, &"c".repeat(64), limits(), &[], 0)
        };
        assert!(result.is_err());
        assert!(!cache.root.join("entries").join("c".repeat(64)).exists());
    }
}

#[test]
fn session_winner_keeps_manifest_receipt_pair_and_is_fully_hashed() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let loser = temp.path().join("loser");
    let layer = source(&first, 1);
    source(&loser, 2);
    let first = owned(&first, limits());
    let loser = owned(&loser, limits());
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
    let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
    let mut session = cache.publication_session(&control, limits());
    let original = vec![vec![b"/original".to_vec()]];
    let losing = vec![vec![b"/losing".to_vec()]];
    let published = session
        .publish_instruction(&first, &"a".repeat(64), limits(), &original, 65536)
        .unwrap();
    let index = fs::read(published.join("index.json")).unwrap();
    let receipt = fs::read(published.join(COPY_TARGETS)).unwrap();
    let (result, count, _) = super::super::hash_reads::observe(&layer.digest, || {
        session.publish_instruction(&loser, &"a".repeat(64), limits(), &losing, 65536)
    });
    assert_eq!(result.unwrap(), published);
    assert_eq!(
        count, 3,
        "source, winner layout and pool must all be hashed"
    );
    assert_eq!(fs::read(published.join("index.json")).unwrap(), index);
    assert_eq!(fs::read(published.join(COPY_TARGETS)).unwrap(), receipt);
    assert_ne!(fs::read(loser.path().join("index.json")).unwrap(), index);
}

#[test]
fn session_sync_error_ends_session_but_keeps_visible_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    let layer = source(&path, 1);
    let source = owned(&path, limits());
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
    let mut cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
    {
        let mut session = cache.publication_session(&control, limits());
        session_read_count(&mut session, &source, &layer, limits(), 'a');
    }
    cache.before_objects_sync = Some(|_| Err(io::Error::other("named objects durability fault")));
    let mut session = cache.publication_session(&control, limits());
    assert!(
        session
            .publish_instruction(&source, &"b".repeat(64), limits(), &[], 0)
            .is_err()
    );
    assert!(session.ended);
    assert!(
        cache
            .lookup(&"a".repeat(64), limits(), 0, 0, &|| false)
            .unwrap()
            .is_some()
    );
    assert!(!cache.root.join("entries").join("b".repeat(64)).exists());
}

#[test]
fn session_cancellation_keeps_the_completed_prefix_durable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    let layer = source(&path, 1);
    let source = owned(&path, limits());
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
    let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
    let mut session = cache.publication_session(&control, limits());
    session_read_count(&mut session, &source, &layer, limits(), 'a');
    cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        session
            .publish_instruction(&source, &"b".repeat(64), limits(), &[], 0)
            .is_err()
    );
    assert!(session.ended);
    assert!(
        cache
            .lookup(&"a".repeat(64), limits(), 0, 0, &|| false)
            .unwrap()
            .is_some()
    );
    cancelled.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(
        session
            .publish_instruction(&source, &"b".repeat(64), limits(), &[], 0)
            .is_err()
    );
    assert_eq!(
        session_read_count(
            &mut cache.publication_session(&control, limits()),
            &source,
            &layer,
            limits(),
            'b'
        )
        .0,
        6
    );
}

#[test]
fn session_corrupt_fresh_copy_has_no_anchor_and_healthy_retry_passes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    let layer = source(&path, 1);
    let source = owned(&path, limits());
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
    let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
    let mut session = cache.publication_session(&control, limits());
    let fault = faults::arm(Boundary::Fresh, Timing::Before, &layer.digest, 0);
    assert!(
        session
            .publish_instruction(&source, &"a".repeat(64), limits(), &[], 0)
            .is_err()
    );
    assert!(fault.fired());
    assert!(!cache.root.join("objects").join(&layer.digest[7..]).exists());
    assert!(
        !cache
            .root
            .join("content/blobs/sha256")
            .join(&layer.digest[7..])
            .exists()
    );
    drop(fault);
    let mut retry = cache.publication_session(&control, limits());
    assert_eq!(
        session_read_count(&mut retry, &source, &layer, limits(), 'a').0,
        8
    );
}

#[test]
fn session_winner_and_restart_reverify_corrupt_sources() {
    for winner in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        let layer = source(&path, 1);
        let source = owned(&path, limits());
        let cancelled = AtomicBool::new(false);
        let control = ManagedControl::for_test(&cancelled).unwrap();
        let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
        let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
        let mut session = cache.publication_session(&control, limits());
        session_read_count(&mut session, &source, &layer, limits(), 'a');
        if !winner {
            session = cache.publication_session(&control, limits());
        }
        fs::write(
            path.join("blobs/sha256").join(&layer.digest[7..]),
            [99; 4096],
        )
        .unwrap();
        assert!(
            session
                .publish_instruction(
                    &source,
                    &if winner { "a" } else { "b" }.repeat(64),
                    limits(),
                    &[],
                    0
                )
                .is_err()
        );
        assert!(session.ended);
        assert!(
            cache
                .lookup(&"a".repeat(64), limits(), 0, 0, &|| false)
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn session_metadata_receipts_and_descriptor_limits_are_always_checked() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    let layer = source(&path, 1);
    let source = owned(&path, limits());
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
    let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
    let mut session = cache.publication_session(&control, limits());
    session_read_count(&mut session, &source, &layer, limits(), 'a');
    fs::write(
        cache
            .root
            .join("entries")
            .join("a".repeat(64))
            .join(COPY_TARGETS),
        b"{}",
    )
    .unwrap();
    assert!(
        session
            .publish_instruction(&source, &"a".repeat(64), limits(), &[], 0)
            .is_err()
    );
    let mut session = cache.publication_session(&control, limits());
    let mut tight = limits();
    tight.max_descriptors = 2;
    assert!(
        session
            .publish_instruction(&source, &"b".repeat(64), tight, &[], 0)
            .is_err()
    );
    let mut session = cache.publication_session(&control, limits());
    session_read_count(&mut session, &source, &layer, limits(), 'b');
    fs::write(path.join("index.json"), b"{}").unwrap();
    assert!(
        session
            .publish_instruction(&source, &"c".repeat(64), limits(), &[], 0)
            .is_err()
    );
    assert!(!cache.root.join("entries").join("c".repeat(64)).exists());
}

#[test]
fn session_repeated_descriptor_fault_stops_before_later_blob_admission() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    let layer = source_layers(&path, 1, &[42; 2048], 2);
    let store = BlobStore::open(&path).unwrap();
    let later = blob(
        &store,
        "application/vnd.oci.image.layer.v1.tar",
        &[19; 2048],
    );
    let mut metadata = image::load_layout(&path, None, limits(), || false).unwrap();
    metadata.config["rootfs"]["diff_ids"] =
        serde_json::json!([layer.digest, layer.digest, later.digest]);
    let config = blob(
        &store,
        "application/vnd.oci.image.config.v1+json",
        &serde_json::to_vec(&metadata.config).unwrap(),
    );
    metadata.manifest["config"] = serde_json::to_value(config).unwrap();
    metadata.manifest["layers"] = serde_json::json!([layer, layer, later]);
    let manifest = blob(
        &store,
        "application/vnd.oci.image.manifest.v1+json",
        &serde_json::to_vec(&metadata.manifest).unwrap(),
    );
    fs::write(
        path.join("index.json"),
        serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"manifests":[manifest]})).unwrap(),
    )
    .unwrap();
    let source = owned(&path, limits());
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
    let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
    let mut session = cache.publication_session(&control, limits());
    let fault = faults::arm(Boundary::PoolLink, Timing::After, &layer.digest, 0);
    assert!(
        session
            .publish_instruction(&source, &"a".repeat(64), limits(), &[], 0)
            .is_err()
    );
    assert!(fault.fired());
    assert!(!cache.root.join("objects").join(&later.digest[7..]).exists());
    assert!(
        !cache
            .root
            .join("content/blobs/sha256")
            .join(&later.digest[7..])
            .exists()
    );
}

#[test]
fn session_directory_and_cache_identity_substitution_fail_closed() {
    for replace_source in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        let layer = source(&path, 1);
        let source = owned(&path, limits());
        let cancelled = AtomicBool::new(false);
        let control = ManagedControl::for_test(&cancelled).unwrap();
        let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
        let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
        let mut session = cache.publication_session(&control, limits());
        session_read_count(&mut session, &source, &layer, limits(), 'a');
        if replace_source {
            fs::rename(path.join("blobs/sha256"), path.join("blobs/old")).unwrap();
            fs::create_dir(path.join("blobs/sha256")).unwrap();
            for entry in fs::read_dir(path.join("blobs/old")).unwrap() {
                let entry = entry.unwrap();
                fs::hard_link(
                    entry.path(),
                    path.join("blobs/sha256").join(entry.file_name()),
                )
                .unwrap();
            }
        } else {
            let pooled = cache
                .root
                .join("content/blobs/sha256")
                .join(&layer.digest[7..]);
            fs::remove_file(&pooled).unwrap();
            fs::write(&pooled, [42; 4096]).unwrap();
        }
        assert!(
            session
                .publish_instruction(&source, &"b".repeat(64), limits(), &[], 0)
                .is_err()
        );
        assert!(session.ended);
    }
}

#[test]
fn session_metadata_budget_falls_back_without_cache_failure() {
    for metadata_budget in [511, 512] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        let layer = source(&path, 1);
        let source = owned(&path, limits());
        let cancelled = AtomicBool::new(false);
        let control = ManagedControl::for_test(&cancelled).unwrap();
        let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
        let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
        let mut budget = limits();
        budget.max_total_metadata_bytes = metadata_budget;
        let mut session = cache.publication_session(&control, budget);
        assert_eq!(
            session_read_count(&mut session, &source, &layer, limits(), 'a').0,
            8
        );
        assert_eq!(
            session_read_count(&mut session, &source, &layer, limits(), 'b').0,
            6
        );
        assert_eq!(session.evidence.reused, 0);
        assert_eq!(session.evidence.files().count(), 0);
    }
}

#[test]
fn session_soft_fd_limit_falls_back_and_releases_retention() {
    const CHILD: &str = "RPWELD_SESSION_FD_TEST";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "oci::cache_store::tests::session_soft_fd_limit_falls_back_and_releases_retention",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    let layer = source(&path, 1);
    let source = owned(&path, limits());
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
    let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
    let mut session = cache.publication_session(&control, limits());
    session_read_count(&mut session, &source, &layer, limits(), 'a');
    let before = fs::read_dir("/proc/self/fd").unwrap().count();
    let mut cap = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: valid output pointer; isolated child changes only its own soft limit.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, cap.as_mut_ptr()) },
        0
    );
    // SAFETY: getrlimit succeeded.
    let mut cap = unsafe { cap.assume_init() };
    cap.rlim_cur = 200;
    // SAFETY: valid limit within the inherited hard ceiling.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &cap) }, 0);
    assert_eq!(
        session_read_count(&mut session, &source, &layer, limits(), 'b').0,
        6
    );
    assert!(fs::read_dir("/proc/self/fd").unwrap().count() < before);
}

#[test]
fn session_admission_checks_actual_pinned_output_sink() {
    const CHILD: &str = "RPWELD_SESSION_OUTPUT_TEST";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "oci::cache_store::tests::session_admission_checks_actual_pinned_output_sink",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    let layer = source(&path, 1);
    let source = owned(&path, limits());
    let payload = path.join("blobs/sha256").join(&layer.digest[7..]);
    let write = OpenOptions::new().append(true).open(&payload).unwrap();
    // SAFETY: only this isolated test subprocess changes its standard descriptor.
    let saved = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(saved >= 0);
    // SAFETY: both descriptors are live; dup2 replaces only stderr in this child.
    assert_eq!(unsafe { libc::dup2(write.as_raw_fd(), 2) }, 2);
    let output = crate::progress::Output::capture().unwrap();
    // SAFETY: restore stderr before the harness can report test failures.
    assert_eq!(unsafe { libc::dup2(saved, 2) }, 2);
    // SAFETY: saved is the extra descriptor owned by this test.
    assert_eq!(unsafe { libc::close(saved) }, 0);
    let _scope = output.enter();
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    let lease = StoreLease::shared(temp.path(), &|| false).unwrap();
    let cache = ManagedCache::open(temp.path(), &lease, &|| false).unwrap();
    let mut session = cache.publication_session(&control, limits());
    let error = session
        .publish_instruction(&source, &"a".repeat(64), limits(), &[], 0)
        .unwrap_err();
    assert!(error.to_string().contains("output disabled"));
    output.diagnostic(format_args!("must not append to the payload"));
    assert_eq!(fs::read(payload).unwrap(), vec![42; 4096]);
    assert!(session.ended);
    assert!(!cache.root.join("entries").join("a".repeat(64)).exists());
}

#[test]
fn session_releases_pins_for_pruning_and_public_output_remains_independent() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    let store_path = temp.path().join("store");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&store_path)
        .unwrap();
    let layer = source(&path, 1);
    let source = owned(&path, limits());
    let public_path = temp.path().join("public");
    fs::create_dir(&public_path).unwrap();
    let public = BlobStore::open(&public_path).unwrap();
    let cancelled = AtomicBool::new(false);
    let control = ManagedControl::for_test(&cancelled).unwrap();
    {
        let lease = StoreLease::shared(&store_path, &|| false).unwrap();
        let cache = ManagedCache::open(&store_path, &lease, &|| false).unwrap();
        let mut session = cache.publication_session(&control, limits());
        session_read_count(&mut session, &source, &layer, limits(), 'a');
        session_read_count(&mut session, &source, &layer, limits(), 'b');
        let pool = BlobStore::open(cache.root.join("content")).unwrap();
        let input = pool.open_verified(&layer, 4096, || false).unwrap();
        let cache_id = identity(&input.metadata().unwrap());
        public.ingest(input, &layer, 4096, || false).unwrap();
        let output = public.open_verified(&layer, 4096, || false).unwrap();
        assert_ne!(identity(&output.metadata().unwrap()), cache_id);
        fs::write(
            public_path.join("blobs/sha256").join(&layer.digest[7..]),
            [11; 4096],
        )
        .unwrap();
        assert!(
            cache
                .lookup(&"a".repeat(64), limits(), 0, 0, &|| false)
                .unwrap()
                .is_some()
        );
        let busy = crate::cleanup_apply::apply(
            &store_path,
            crate::cleanup_plan::Request::CachePrune,
            Default::default(),
            || false,
        )
        .unwrap();
        assert_eq!(busy.status, "store_busy");
        session.invalidate();
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let report = loop {
        let report = crate::cleanup_apply::apply(
            &store_path,
            crate::cleanup_plan::Request::CachePrune,
            Default::default(),
            || false,
        )
        .unwrap();
        if report.status != "store_busy" || std::time::Instant::now() >= deadline {
            break report;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(report.failure.is_none(), "{report:?}");
    assert_ne!(report.status, "store_busy");
    assert!(
        !store_path
            .join("cache-v2/entries")
            .join("a".repeat(64))
            .exists()
    );
    assert_eq!(
        fs::read(path.join("blobs/sha256").join(&layer.digest[7..])).unwrap(),
        vec![42; 4096]
    );
    assert_eq!(
        fs::read(public_path.join("blobs/sha256").join(&layer.digest[7..])).unwrap(),
        vec![11; 4096]
    );
}
