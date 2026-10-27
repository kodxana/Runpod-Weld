//! Standalone flattened OCI export on Linux. The caller owns a stable, disposable
//! source and stable destination ancestors: no concurrent writers or pathname
//! swaps. This is not a snapshot or a sandbox. Never pass a live container root.
//! Export includes root directory metadata and one uncompressed full-tree layer.
//! Old rootfs/history are replaced by one truthful flattened history entry; all
//! other config fields survive. ctime is not exported (Linux cannot restore it).
//! Symlink xattrs, empty xattrs (PAX deletion semantics), special files, external
//! hardlinks, whiteout names and nested mounts are rejected, never omitted.
//! Failures leave an explicitly partial destination; no user tree is deleted.
//! Transfers use at most 64 KiB chunks; metadata is bounded by caller budgets.
//! File reads require ownership or CAP_FOWNER for O_NOATIME. Directory/symlink
//! reads may update source atimes; the archived timestamps are captured first.

pub use crate::export_compression::Compression;
use crate::export_compression::EncodedLayer;
use crate::oci::Descriptor;
use serde_json::Value;
use std::{fmt, io, path::Path};

#[derive(Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct Encoding {
    pub compression: Compression,
    pub max_blob_bytes: u64,
}

pub(crate) struct Exported {
    pub manifest: Descriptor,
    pub layer: EncodedLayer,
}

/// Required resource budgets. Layer bytes include tar headers/padding. Metadata
/// counts path/link bytes, PAX records, headers and serialized OCI JSON in total.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Uncompressed new tar bytes, including headers and padding. Also caps
    /// total unique regular-file bytes hashed per inventory in layered
    /// mode. Base blobs use the image limits supplied to Baseline::capture.
    pub max_layer_bytes: u64,
    /// Logical filesystem entries, including the root directory; not tar headers.
    pub max_entries: usize,
    pub max_metadata_bytes: u64,
}

/// Aggregate bounds for the temporary verified base replay (uncompressed tar
/// bytes and physical nonzero tar headers, including extensions, across layers).
#[derive(Clone, Copy, Debug)]
pub struct ReplayLimits {
    pub max_bytes: u64,
    pub max_entries: usize,
}

/// Immutable fingerprints of a just-replayed base. The caller attests that the
/// root is the replay of the selected layout, with stable exclusive ownership.
/// In particular, symlink targets come from a private verified replay: matching
/// stat metadata cannot independently prove the caller's symlink target bytes.
pub struct Baseline {
    #[cfg(target_os = "linux")]
    state: linux::delta::State,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg_attr(
    all(not(test), target_os = "linux"),
    expect(
        dead_code,
        reason = "Standalone replay admission is exercised by internal regression tests; the engine uses replay receipts"
    )
)]
pub(crate) enum CaptureAllocation<'a> {
    Spool {
        path: &'a Path,
        descriptor: &'a Descriptor,
    },
    Replay {
        root: &'a Path,
        layer: &'a crate::layer::VerifiedLayer,
    },
}

impl Baseline {
    /// Retain symlink evidence for a private checkpoint whose root was not replayed.
    pub(crate) fn receipt(
        &self,
        root: &Path,
        config: &Value,
        limit: u64,
        cancelled: impl Fn() -> bool,
    ) -> Result<Option<crate::rootfs::ReplayReceipt>, Error> {
        #[cfg(target_os = "linux")]
        {
            linux::delta::checkpoint_receipt(self, root, config, limit, &cancelled)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, config, limit, cancelled);
            Err(Error::Invalid("export requires Linux"))
        }
    }
    /// Inventory an engine-owned root after a verified checkpoint was applied.
    pub(crate) fn capture_checkpoint(
        root: &Path,
        layout: &Path,
        metadata: &crate::image::ImageMetadata,
        limits: Limits,
        blob_limit: u64,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        {
            linux::delta::capture_checkpoint(root, layout, metadata, limits, blob_limit, &cancelled)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, layout, metadata, limits, blob_limit, cancelled);
            Err(Error::Invalid("export requires Linux"))
        }
    }
    /// Reuse the engine's complete initial replay; never reread live symlink targets.
    /// The engine retains the stable base layout and exclusively owns the root.
    pub(crate) fn capture_replayed(
        root: &Path,
        layout: &Path,
        metadata: &crate::image::ImageMetadata,
        receipt: crate::rootfs::ReplayReceipt,
        limits: Limits,
        blob_limit: u64,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        {
            linux::delta::capture_replayed(
                root, layout, metadata, receipt, limits, blob_limit, &cancelled,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                root, layout, metadata, receipt, limits, blob_limit, cancelled,
            );
            Err(Error::Invalid("export requires Linux"))
        }
    }

    /// Capture BEFORE any build instruction. `workspace` is an owned canonical
    /// directory for a bounded temporary replay, removed on return. Keep the
    /// original layout immutable and available until the final delta export.
    /// Directory reads use O_NOATIME; real baseline symlinks are never read.
    /// Capture replays and scans the base once in workspace, then fingerprints
    /// the real root. This uses transient disk for a full base replay, plus one
    /// verified-layer spool, and requires permissions to replay its metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn capture(
        root: &Path,
        layout: &Path,
        reference: Option<&str>,
        workspace: &Path,
        limits: Limits,
        image_limits: crate::image::Limits,
        layer_limits: crate::layer::Limits,
        replay_limits: ReplayLimits,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, Error> {
        Self::capture_with_admission(
            root,
            layout,
            reference,
            workspace,
            limits,
            image_limits,
            layer_limits,
            replay_limits,
            |_| Ok(()),
            cancelled,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture_with_admission(
        root: &Path,
        layout: &Path,
        reference: Option<&str>,
        workspace: &Path,
        limits: Limits,
        image_limits: crate::image::Limits,
        layer_limits: crate::layer::Limits,
        replay_limits: ReplayLimits,
        admit: impl Fn(CaptureAllocation<'_>) -> Result<(), Error>,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        {
            linux::delta::capture(
                root,
                layout,
                reference,
                workspace,
                limits,
                image_limits,
                layer_limits,
                replay_limits,
                &admit,
                &cancelled,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                root,
                layout,
                reference,
                workspace,
                limits,
                image_limits,
                layer_limits,
                replay_limits,
                admit,
                cancelled,
            );
            Err(Error::Invalid("export requires Linux"))
        }
    }
    /// Capture an empty, newly created scratch root, including its metadata.
    pub fn scratch(
        root: &Path,
        limits: Limits,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        {
            linux::delta::scratch(root, limits, &cancelled)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, limits, cancelled);
            Err(Error::Invalid("export requires Linux"))
        }
    }
}

/// Export original base blobs plus one cumulative filesystem delta. The source
/// ownership, destination, cancellation and failure contracts of export_layout
/// apply. Symlink target reads may update live source atime; archived metadata
/// is captured first, including all hardlink aliases. Callers continuing a build
/// must replay this snapshot, as for flattened export. No timestamp restoration
/// is performed (it would change ctime). Root metadata is always emitted.
/// Base history is preserved and extended when present; absent history on a
/// nonempty base stays absent rather than inventing historical entries. Base
/// blobs are verified and copied into independent destination inodes: public
/// layouts and work snapshots must not share mutable storage with their bases.
pub fn export_delta_layout(
    root: &Path,
    destination: &Path,
    config: &Value,
    baseline: &Baseline,
    limits: Limits,
    cancelled: impl Fn() -> bool,
) -> Result<Descriptor, Error> {
    export_delta_layout_created(
        root,
        destination,
        config,
        baseline,
        limits,
        cancelled,
        || Ok(()),
    )
}

pub(crate) fn export_delta_layout_created(
    root: &Path,
    destination: &Path,
    config: &Value,
    baseline: &Baseline,
    limits: Limits,
    cancelled: impl Fn() -> bool,
    created: impl FnOnce() -> std::io::Result<()>,
) -> Result<Descriptor, Error> {
    #[cfg(target_os = "linux")]
    {
        linux::export(
            root,
            destination,
            config,
            limits,
            Encoding {
                compression: Compression::Uncompressed,
                max_blob_bytes: limits.max_layer_bytes,
            },
            &cancelled,
            created,
            Some(baseline),
            None,
            linux::SourceState::Observed,
        )
        .map(|result| result.manifest)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            root,
            destination,
            config,
            baseline,
            limits,
            cancelled,
            created,
        );
        Err(Error::Invalid("export requires Linux"))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{image, layer, oci::BlobStore, rootfs};
    use serde_json::json;
    use std::{
        cell::Cell,
        ffi::CString,
        fs,
        io::{Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt, symlink},
        },
        path::PathBuf,
        process::Command,
    };

    const LIMITS: Limits = Limits {
        max_layer_bytes: 32 * 1024 * 1024,
        max_entries: 100,
        max_metadata_bytes: 1024 * 1024,
    };
    struct Fixture {
        temp: tempfile::TempDir,
        root: PathBuf,
        dest: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir_in("/tmp").unwrap();
            let root = temp.path().join("root");
            fs::create_dir(&root).unwrap();
            let dest = temp.path().join("layout");
            Self { temp, root, dest }
        }
        fn export(&self, l: Limits, c: impl Fn() -> bool) -> Result<Descriptor, Error> {
            export_layout(&self.root, &self.dest, &config(), l, c)
        }
        fn load(&self) -> image::ImageMetadata {
            image::load_layout(
                &self.dest,
                None,
                image::Limits {
                    max_metadata_bytes: LIMITS.max_metadata_bytes,
                    max_total_metadata_bytes: 4 * LIMITS.max_metadata_bytes,
                    max_descriptors: 10,
                    max_layer_bytes: LIMITS.max_layer_bytes,
                    max_total_layer_bytes: LIMITS.max_layer_bytes,
                },
                || false,
            )
            .unwrap()
        }
    }
    fn config() -> Value {
        json!({"os":"linux","architecture":"amd64","config":{"Env":["A=B"],"Cmd":["/bin/app"],"User":"123:456","OnBuild":["RUN true"]},"future":{"keep":true},"rootfs":{"diff_ids":["stale"]},"history":[{"created_by":"stale"}]})
    }

    #[test]
    fn exported_root_receipt_is_bounded_pinned_and_keeps_symlink_metadata() {
        let f = Fixture::new();
        let baseline = Baseline::scratch(&f.root, LIMITS, || false).unwrap();
        fs::write(f.root.join("file"), b"payload").unwrap();
        symlink("file", f.root.join("link")).unwrap();
        fs::hard_link(f.root.join("link"), f.root.join("alias")).unwrap();
        let mut receipt = None;
        export_created_with_resources(
            &f.root,
            &f.dest,
            &config(),
            Some(&baseline),
            LIMITS,
            Encoding {
                compression: Compression::Uncompressed,
                max_blob_bytes: LIMITS.max_layer_bytes,
            },
            None,
            Some((&mut receipt, LIMITS.max_metadata_bytes)),
            || false,
            || Ok(()),
        )
        .unwrap();
        let receipt = receipt.unwrap();
        let metadata = f.load();
        receipt.validate(&f.root, &metadata.diff_ids).unwrap();
        assert!(receipt.validate(&f.root, &[]).is_err());
        let moved = f.temp.path().join("moved");
        fs::rename(&f.root, &moved).unwrap();
        fs::create_dir(&f.root).unwrap();
        assert!(receipt.validate(&f.root, &metadata.diff_ids).is_err());
        receipt.validate(&moved, &metadata.diff_ids).unwrap();
        let before = fs::symlink_metadata(moved.join("link")).unwrap();
        let inherited = Baseline::capture_replayed(
            &moved,
            &f.dest,
            &metadata,
            receipt,
            LIMITS,
            LIMITS.max_layer_bytes,
            || false,
        )
        .unwrap();
        let after = fs::symlink_metadata(moved.join("alias")).unwrap();
        assert_eq!(
            (
                before.atime(),
                before.atime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.atime(),
                after.atime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        let child = f.temp.path().join("child");
        export_delta_layout(&moved, &child, &config(), &inherited, LIMITS, || false).unwrap();
        let f = Fixture::new();
        let baseline = Baseline::scratch(&f.root, LIMITS, || false).unwrap();
        let mut receipt = None;
        export_created_with_resources(
            &f.root,
            &f.dest,
            &config(),
            Some(&baseline),
            LIMITS,
            Encoding {
                compression: Compression::Uncompressed,
                max_blob_bytes: LIMITS.max_layer_bytes,
            },
            None,
            Some((&mut receipt, 1)),
            || false,
            || Ok(()),
        )
        .unwrap();
        assert!(receipt.is_none());
        assert!(f.dest.join("index.json").exists());
        f.load();
    }

    #[test]
    fn gzip_exports_enforce_independent_caps_and_publish_only_complete_streams() {
        use sha2::{Digest, Sha256};
        for layered in [false, true] {
            let f = Fixture::new();
            let baseline = layered.then(|| Baseline::scratch(&f.root, LIMITS, || false).unwrap());
            fs::write(f.root.join("data"), vec![42; 1 << 20]).unwrap();
            let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000_000);
            for path in [&f.root, &f.root.join("data")] {
                fs::File::open(path)
                    .unwrap()
                    .set_times(
                        fs::FileTimes::new()
                            .set_accessed(stamp + std::time::Duration::from_secs(1))
                            .set_modified(stamp),
                    )
                    .unwrap();
            }
            let run = |name: &str, raw, stored, cancelled: &dyn Fn() -> bool| {
                export_created_with_resources(
                    &f.root,
                    &f.temp.path().join(name),
                    &config(),
                    baseline.as_ref(),
                    Limits {
                        max_layer_bytes: raw,
                        ..LIMITS
                    },
                    Encoding {
                        compression: Compression::Gzip,
                        max_blob_bytes: stored,
                    },
                    None,
                    None,
                    cancelled,
                    || Ok(()),
                )
            };
            let first = run("first", LIMITS.max_layer_bytes, 16384, &|| false).unwrap();
            let encoded = &first.layer;
            assert!(encoded.uncompressed_bytes > 1 << 20);
            assert!(encoded.descriptor.size < 16384);
            assert_eq!(
                encoded.descriptor.media_type,
                "application/vnd.oci.image.layer.v1.tar+gzip"
            );
            let bytes = fs::read(
                f.temp
                    .path()
                    .join("first/blobs")
                    .join(encoded.descriptor.digest.replace(':', "/")),
            )
            .unwrap();
            assert_eq!(&bytes[..10], &[31, 139, 8, 0, 0, 0, 0, 0, 4, 255]);
            assert_eq!(
                encoded.descriptor.digest,
                format!("sha256:{:x}", Sha256::digest(&bytes))
            );
            let mut raw = Vec::new();
            flate2::read::GzDecoder::new(bytes.as_slice())
                .read_to_end(&mut raw)
                .unwrap();
            assert_eq!(raw.len() as u64, encoded.uncompressed_bytes);
            assert_eq!(
                encoded.diff_id.as_str(),
                format!("sha256:{:x}", Sha256::digest(&raw))
            );
            assert_ne!(encoded.diff_id.as_str(), encoded.descriptor.digest);
            let exact = run(
                "exact",
                encoded.uncompressed_bytes,
                encoded.descriptor.size as u64,
                &|| false,
            )
            .unwrap();
            assert_eq!(exact.layer.descriptor, encoded.descriptor);
            for (name, raw_limit, stored_limit) in [
                ("raw-small", encoded.uncompressed_bytes - 1, 16384),
                (
                    "footer-small",
                    encoded.uncompressed_bytes,
                    encoded.descriptor.size as u64 - 1,
                ),
            ] {
                assert!(run(name, raw_limit, stored_limit, &|| false).is_err());
                let dest = f.temp.path().join(name);
                assert!(!dest.join("index.json").exists());
                assert_eq!(fs::read_dir(dest.join("blobs/sha256")).unwrap().count(), 0);
            }
            let cancelled_after_write = std::cell::Cell::new(false);
            assert!(
                run("cancelled", LIMITS.max_layer_bytes, 16384, &|| {
                    let pending = f.temp.path().join("cancelled/blobs/sha256");
                    let allocated = fs::read_dir(pending).ok().is_some_and(|entries| {
                        entries
                            .filter_map(Result::ok)
                            .any(|e| e.metadata().is_ok_and(|m| m.len() > 0))
                    });
                    cancelled_after_write.set(cancelled_after_write.get() || allocated);
                    allocated
                })
                .is_err()
            );
            assert!(cancelled_after_write.get());
            assert!(!f.temp.path().join("cancelled/index.json").exists());
        }
    }

    #[test]
    fn measured_resource_exports_preserve_flattened_and_layered_results() {
        for compression in [Compression::Uncompressed, Compression::Gzip] {
            for layered in [false, true] {
                let f = Fixture::new();
                let baseline =
                    layered.then(|| Baseline::scratch(&f.root, LIMITS, || false).unwrap());
                fs::write(f.root.join("data"), vec![42; 65537]).unwrap();
                fs::hard_link(f.root.join("data"), f.root.join("alias")).unwrap();
                let paths = crate::build_resources::Paths {
                    work: f.root.clone(),
                    output: f.dest.clone(),
                    store: f.temp.path().to_owned(),
                };
                let snapshot = crate::build_resources::Snapshot::observe(&paths).unwrap();
                let policy = crate::build_resources::Policy::resolve(
                    paths,
                    &snapshot,
                    crate::build_resources::Overrides::default(),
                    1,
                    0,
                )
                .unwrap();
                export_created_with_resources(
                    &f.root,
                    &f.dest,
                    &config(),
                    baseline.as_ref(),
                    LIMITS,
                    Encoding {
                        compression,
                        max_blob_bytes: LIMITS.max_layer_bytes,
                    },
                    Some(&policy),
                    None,
                    || false,
                    || Ok(()),
                )
                .unwrap();
                let metadata = f.load();
                let spool = f.temp.path().join("verify");
                fs::create_dir(&spool).unwrap();
                let store = BlobStore::open(&f.dest).unwrap();
                let verified = layer::verify(
                    &store,
                    &metadata.layers[0],
                    &metadata.diff_ids[0],
                    &spool,
                    layer::Limits {
                        max_blob_bytes: 1 << 20,
                        max_uncompressed_bytes: 1 << 20,
                        max_entries: 100,
                        max_metadata_bytes: 1 << 20,
                        max_gzip_header_bytes: 65536,
                    },
                    || false,
                )
                .unwrap();
                assert_eq!(
                    verified
                        .entries()
                        .iter()
                        .filter(|e| e.kind == layer::EntryKind::File)
                        .count(),
                    1
                );
                assert_eq!(
                    verified
                        .entries()
                        .iter()
                        .filter(|e| e.kind == layer::EntryKind::Hardlink)
                        .count(),
                    1
                );
                assert_eq!(
                    verified.entries().iter().map(|e| e.size).sum::<u64>(),
                    65537
                );
            }
        }
    }

    #[test]
    fn symlink_target_is_budgeted_before_read_and_size_checked() {
        let f = Fixture::new();
        let path = f.root.join("link");
        let target = "x".repeat(4000);
        symlink(&target, &path).unwrap();
        let mut budget = 100;
        assert!(matches!(
            linux::bounded_link(&path, 4000, &mut budget),
            Err(Error::Limit("metadata bytes"))
        ));
        // Even a missing path must fail the budget before attempting readlink.
        assert!(matches!(
            linux::bounded_link(&f.root.join("missing"), 4000, &mut budget),
            Err(Error::Limit("metadata bytes"))
        ));
        let mut budget = 4001;
        assert_eq!(
            linux::bounded_link(&path, 4000, &mut budget).unwrap(),
            PathBuf::from(&target)
        );
        assert_eq!(budget, 0);
        assert!(matches!(
            linux::bounded_link(&path, 3999, &mut 5000),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            linux::bounded_link(&path, 4001, &mut 5000),
            Err(Error::Invalid(_))
        ));
    }
    fn attr(path: &Path, value: &[u8]) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::lsetxattr(
                    path.as_ptr(),
                    c"user.weld".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
    }
    fn times(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let ts = [
            libc::timespec {
                tv_sec: -1,
                tv_nsec: 123456789,
            },
            libc::timespec {
                tv_sec: 1234,
                tv_nsec: 987654321,
            },
        ];
        assert_eq!(
            unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    ts.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            },
            0
        );
    }
    #[test]
    fn flattened_roundtrip_loader_verifier_replayer_and_gnu_tar() {
        let f = Fixture::new();
        let dir = f.root.join("dir");
        fs::create_dir(&dir).unwrap();
        let file = dir.join("file");
        // Many buffers; no payload-sized allocation in exporter or fixture.
        let mut writer = fs::File::create(&file).unwrap();
        for _ in 0..129 {
            writer.write_all(&[0x5a; 65536]).unwrap();
        }
        drop(writer);
        if unsafe { libc::geteuid() } == 0 {
            let p = CString::new(file.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(p.as_ptr(), 123, 456) }, 0);
        }
        fs::set_permissions(&file, fs::Permissions::from_mode(0o6751)).unwrap();
        fs::hard_link(&file, f.root.join("hard")).unwrap();
        attr(&file, b"binary\0\n=value");
        attr(&dir, b"directory");
        symlink("../../outside-never-read", dir.join("link")).unwrap();
        fs::hard_link(dir.join("link"), f.root.join("hard-symlink")).unwrap();
        symlink("/etc/passwd", f.root.join("absolute")).unwrap();
        symlink("z".repeat(180), f.root.join("long-link")).unwrap();
        let long = "n".repeat(180);
        fs::write(dir.join(&long), b"long path").unwrap();
        for p in [&f.root, &dir, &file, &dir.join("link")] {
            times(p);
        }
        let before = fs::metadata(&file).unwrap();
        let root_before = fs::metadata(&f.root).unwrap();
        let dir_before = fs::metadata(&dir).unwrap();
        let d = f.export(LIMITS, || false).unwrap();
        let metadata = f.load();
        assert_eq!(d, metadata.selected);
        assert_eq!(metadata.config["config"], config()["config"]);
        assert_eq!(metadata.config["future"], config()["future"]);
        assert_eq!(metadata.config["history"].as_array().unwrap().len(), 1);
        assert_eq!(metadata.layers[0].digest, metadata.diff_ids[0].as_str());
        let store = BlobStore::open(&f.dest).unwrap();
        let mut verified = layer::verify(
            &store,
            &metadata.layers[0],
            &metadata.diff_ids[0],
            f.temp.path(),
            layer::Limits {
                max_blob_bytes: LIMITS.max_layer_bytes,
                max_uncompressed_bytes: LIMITS.max_layer_bytes,
                max_entries: LIMITS.max_entries,
                max_metadata_bytes: LIMITS.max_metadata_bytes,
                max_gzip_header_bytes: 1024,
            },
            || false,
        )
        .unwrap();
        assert_eq!(
            verified
                .entries()
                .iter()
                .filter(|e| e.kind == layer::EntryKind::Hardlink)
                .count(),
            2
        );
        let out = f.temp.path().join("replay");
        fs::create_dir(&out).unwrap();
        rootfs::apply_layer(&out, &mut verified, || false).unwrap();
        for (path, original) in [(&out, &root_before), (&out.join("dir"), &dir_before)] {
            let m = fs::metadata(path).unwrap();
            assert_eq!(
                (
                    m.mode(),
                    m.mtime(),
                    m.mtime_nsec(),
                    m.atime(),
                    m.atime_nsec()
                ),
                (
                    original.mode(),
                    original.mtime(),
                    original.mtime_nsec(),
                    original.atime(),
                    original.atime_nsec()
                )
            );
        }
        let after = fs::metadata(out.join("dir/file")).unwrap();
        assert_eq!(
            (
                after.uid(),
                after.gid(),
                after.mode(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.atime(),
                after.atime_nsec()
            ),
            (
                before.uid(),
                before.gid(),
                before.mode(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.atime(),
                before.atime_nsec()
            )
        );
        assert_eq!(after.ino(), fs::metadata(out.join("hard")).unwrap().ino());
        assert_eq!(
            fs::read_link(out.join("dir/link")).unwrap(),
            Path::new("../../outside-never-read")
        );
        assert_eq!(
            fs::symlink_metadata(out.join("dir/link")).unwrap().ino(),
            fs::symlink_metadata(out.join("hard-symlink"))
                .unwrap()
                .ino()
        );
        assert_eq!(
            fs::read_link(out.join("absolute")).unwrap(),
            Path::new("/etc/passwd")
        );
        assert_eq!(
            fs::read_link(out.join("long-link")).unwrap(),
            PathBuf::from("z".repeat(180))
        );
        let p = CString::new(out.join("dir/file").as_os_str().as_bytes()).unwrap();
        let mut value = [0u8; 64];
        let n = unsafe {
            libc::getxattr(
                p.as_ptr(),
                c"user.weld".as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        assert_eq!(&value[..n as usize], b"binary\0\n=value");
        let mut reader = fs::File::open(out.join("hard")).unwrap();
        let mut chunk = [0; 65536];
        for _ in 0..129 {
            reader.read_exact(&mut chunk).unwrap();
            assert!(chunk.iter().all(|b| *b == 0x5a));
        }
        assert_eq!(reader.read(&mut chunk).unwrap(), 0);
        if Command::new("tar").arg("--version").output().is_ok() {
            let tar_path = f
                .dest
                .join("blobs/sha256")
                .join(&metadata.layers[0].digest[7..]);
            let independent = f.temp.path().join("gnu");
            fs::create_dir(&independent).unwrap();
            let result = Command::new("tar")
                .args(["--xattrs", "-xf"])
                .arg(tar_path)
                .arg("-C")
                .arg(&independent)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                fs::metadata(independent.join("hard")).unwrap().ino(),
                fs::metadata(independent.join("dir/file")).unwrap().ino()
            );
            assert_eq!(
                fs::read_link(independent.join("absolute")).unwrap(),
                Path::new("/etc/passwd")
            );
            assert_eq!(
                fs::metadata(independent.join("hard")).unwrap().mtime_nsec(),
                987654321
            );
        }
    }
    #[test]
    fn budgets_and_midstream_cancellation_never_publish_index() {
        for l in [
            Limits {
                max_entries: 0,
                ..LIMITS
            },
            Limits {
                max_layer_bytes: 1000,
                ..LIMITS
            },
            Limits {
                max_metadata_bytes: 20,
                ..LIMITS
            },
        ] {
            let f = Fixture::new();
            assert!(f.export(l, || false).is_err());
            assert!(!f.dest.join("index.json").exists());
        }
        let f = Fixture::new();
        fs::File::create(f.root.join("big"))
            .unwrap()
            .set_len(8 * 1024 * 1024)
            .unwrap();
        let calls = Cell::new(0);
        assert!(
            f.export(LIMITS, || {
                calls.set(calls.get() + 1);
                calls.get() >= 30
            })
            .is_err()
        );
        assert!(calls.get() >= 30);
        assert!(!f.dest.join("index.json").exists());
        let f = Fixture::new();
        assert!(matches!(f.export(LIMITS, || true), Err(Error::Cancelled)));
        assert!(!f.dest.exists());
    }
    #[test]
    fn unsafe_paths_and_unsupported_inputs_are_explicit() {
        let f = Fixture::new();
        assert!(
            export_layout(&f.root, &f.root.join("nested"), &config(), LIMITS, || false).is_err()
        );
        assert!(!f.root.join("nested").exists());
        let alias = f.temp.path().join("alias");
        symlink(&f.root, &alias).unwrap();
        assert!(export_layout(&alias, &f.dest, &config(), LIMITS, || false).is_err());
        fs::create_dir(&f.dest).unwrap();
        fs::write(f.dest.join("keep"), b"keep").unwrap();
        assert!(f.export(LIMITS, || false).is_err());
        assert_eq!(fs::read(f.dest.join("keep")).unwrap(), b"keep");
        for variant in 0..4 {
            let f = Fixture::new();
            let p = f
                .root
                .join(if variant == 0 { ".wh.hidden" } else { "file" });
            if variant == 1 {
                let p = CString::new(p.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(p.as_ptr(), 0o600) }, 0);
            } else {
                fs::write(&p, b"payload").unwrap();
                if variant == 2 {
                    fs::hard_link(&p, f.temp.path().join("outside")).unwrap();
                }
                if variant == 3 {
                    attr(&p, b"");
                }
            }
            assert!(f.export(LIMITS, || false).is_err(), "variant {variant}");
            assert!(!f.dest.join("index.json").exists());
        }
    }
    #[test]
    fn nested_bind_mount_rejected_when_mount_capability_available() {
        let f = Fixture::new();
        let nested = f.root.join("nested");
        let elsewhere = f.temp.path().join("elsewhere");
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&elsewhere).unwrap();
        let a = CString::new(elsewhere.as_os_str().as_bytes()).unwrap();
        let b = CString::new(nested.as_os_str().as_bytes()).unwrap();
        if unsafe {
            libc::mount(
                a.as_ptr(),
                b.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            let e = io::Error::last_os_error();
            assert_eq!(e.raw_os_error(), Some(libc::EPERM));
            eprintln!("mount capability unavailable; bind mount test skipped");
            return;
        }
        let result = f.export(LIMITS, || false);
        assert_eq!(unsafe { libc::umount2(b.as_ptr(), libc::MNT_DETACH) }, 0);
        assert!(matches!(result, Err(Error::Invalid("nested mount"))));
        assert!(!f.dest.join("index.json").exists());
    }

    #[test]
    fn output_bind_alias_of_source_subdirectory_rejected_before_creation() {
        let f = Fixture::new();
        let sub = f.root.join("sub");
        let alias = f.temp.path().join("alias");
        fs::create_dir(&sub).unwrap();
        fs::create_dir(&alias).unwrap();
        let a = CString::new(sub.as_os_str().as_bytes()).unwrap();
        let b = CString::new(alias.as_os_str().as_bytes()).unwrap();
        if unsafe {
            libc::mount(
                a.as_ptr(),
                b.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            eprintln!("mount capability unavailable; alias test skipped");
            return;
        }
        let result = export_layout(&f.root, &alias.join("output"), &config(), LIMITS, || false);
        assert_eq!(unsafe { libc::umount2(b.as_ptr(), libc::MNT_DETACH) }, 0);
        assert!(matches!(
            result,
            Err(Error::Invalid("source/destination inode alias"))
        ));
        assert!(!sub.join("output").exists());
    }

    #[test]
    fn empty_root_and_non_utf8_filename_are_supported() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        for populated in [false, true] {
            let f = Fixture::new();
            if populated {
                fs::write(f.root.join(OsStr::from_bytes(b"non-utf8-\xff")), b"data").unwrap();
            }
            f.export(LIMITS, || false).unwrap();
            let image = f.load();
            let store = BlobStore::open(&f.dest).unwrap();
            let file = store
                .open_verified(&image.layers[0], LIMITS.max_layer_bytes, || false)
                .unwrap();
            let mut tar = tar::Archive::new(file);
            let names: Vec<_> = tar
                .entries()
                .unwrap()
                .map(|e| e.unwrap().path_bytes().into_owned())
                .collect();
            assert_eq!(names.len(), if populated { 2 } else { 1 });
            if populated {
                assert!(names.iter().any(|n| n == b"non-utf8-\xff"));
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Blob(crate::oci::Error),
    Json(serde_json::Error),
    Image(crate::image::Error),
    Layer(crate::layer::Error),
    Replay(crate::rootfs::Error),
    /// Cleanup failed; the owned path may remain. Preserve any primary failure.
    Cleanup {
        primary: Option<Box<Error>>,
        path: std::path::PathBuf,
        cleanup: io::Error,
    },
    Invalid(&'static str),
    Limit(&'static str),
    Cancelled,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OCI export failed: {self:?}; a destination created by this call may be partial (no index means unpublished); existing destinations are left untouched"
        )
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cleanup {
                primary: Some(error),
                ..
            } => Some(error.as_ref()),
            Self::Cleanup { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if let Some(cause) = e.get_ref().and_then(|e| e.downcast_ref::<Error>()) {
            match cause {
                Error::Cancelled => return Self::Cancelled,
                Error::Limit(name) => return Self::Limit(name),
                _ => {}
            }
        }
        Self::Io(e)
    }
}
impl From<crate::oci::Error> for Error {
    fn from(e: crate::oci::Error) -> Self {
        Self::Blob(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Export to a NEW directory beneath an existing owned parent. Both paths must
/// be absolute, canonical and disjoint (including directory inode aliases).
/// `config` must describe linux/amd64, matching the current loader contract.
/// Returns the published manifest descriptor. `index.json` is published last,
/// atomically; cancellation after that publication cannot revoke success.
/// Cancellation is cooperative between entries and 64 KiB writes, not an I/O
/// timeout. Temporary tar storage is inside destination and removed on return;
/// the stored spool becomes the verified blob without another payload copy.
pub fn export_layout(
    root: &Path,
    destination: &Path,
    config: &Value,
    limits: Limits,
    cancelled: impl Fn() -> bool,
) -> Result<Descriptor, Error> {
    export_layout_created(root, destination, config, limits, cancelled, || Ok(()))
}

pub(crate) fn export_layout_created(
    root: &Path,
    destination: &Path,
    config: &Value,
    limits: Limits,
    cancelled: impl Fn() -> bool,
    created: impl FnOnce() -> std::io::Result<()>,
) -> Result<Descriptor, Error> {
    #[cfg(target_os = "linux")]
    {
        linux::export(
            root,
            destination,
            config,
            limits,
            Encoding {
                compression: Compression::Uncompressed,
                max_blob_bytes: limits.max_layer_bytes,
            },
            &cancelled,
            created,
            None,
            None,
            linux::SourceState::Observed,
        )
        .map(|result| result.manifest)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, destination, config, limits, cancelled, created);
        Err(Error::Invalid("export requires Linux"))
    }
}

/// Engine-only current-space preflight; standalone callers retain explicit limits.
#[allow(clippy::too_many_arguments)]
pub(crate) fn export_created_with_resources(
    root: &Path,
    destination: &Path,
    config: &Value,
    baseline: Option<&Baseline>,
    limits: Limits,
    encoding: Encoding,
    resources: Option<&crate::build_resources::Policy>,
    receipt: Option<(&mut Option<crate::rootfs::ReplayReceipt>, u64)>,
    cancelled: impl Fn() -> bool,
    created: impl FnOnce() -> io::Result<()>,
) -> Result<Exported, Error> {
    #[cfg(target_os = "linux")]
    {
        linux::export(
            root,
            destination,
            config,
            limits,
            encoding,
            &cancelled,
            created,
            baseline,
            resources,
            linux::SourceState::Archived(receipt),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            root,
            destination,
            config,
            baseline,
            limits,
            encoding,
            resources,
            receipt,
            cancelled,
            created,
        );
        Err(Error::Invalid("export requires Linux"))
    }
}

/// Private, immutable instruction layout plus its already-inventoried baseline.
/// Only these engine-owned layouts may share inherited blob inodes with each other.
#[allow(clippy::too_many_arguments)]
pub(crate) fn export_checkpoint(
    root: &Path,
    destination: &Path,
    config: &Value,
    baseline: &Baseline,
    limits: Limits,
    encoding: Encoding,
    resources: Option<&crate::build_resources::Policy>,
    cancelled: impl Fn() -> bool,
) -> Result<(Exported, Baseline), Error> {
    #[cfg(target_os = "linux")]
    {
        let mut next = None;
        let manifest = linux::export(
            root,
            destination,
            config,
            limits,
            encoding,
            &cancelled,
            || Ok(()),
            Some(baseline),
            resources,
            linux::SourceState::Checkpoint(&mut next),
        )?;
        Ok((
            manifest,
            next.ok_or(Error::Invalid("checkpoint baseline missing"))?,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            root,
            destination,
            config,
            baseline,
            limits,
            encoding,
            resources,
            cancelled,
        );
        Err(Error::Invalid("export requires Linux"))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    pub(super) mod delta {
        include!("export_delta.rs");
    }
    use super::*;
    use crate::{
        export_compression::{LayerWriter, Limits as EncodingLimits, payload_peak},
        oci::BlobStore,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        collections::HashMap,
        ffi::CString,
        fs::{self, File, Metadata, OpenOptions},
        io::{Read, Write},
        os::unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{MetadataExt, OpenOptionsExt},
        },
        path::{Component, PathBuf},
    };
    const CONFIG: &str = "application/vnd.oci.image.config.v1+json";
    #[cfg(test)]
    const LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
    const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    const INDEX: &str = "application/vnd.oci.image.index.v1+json";
    fn check(c: &impl Fn() -> bool) -> Result<(), Error> {
        if c() { Err(Error::Cancelled) } else { Ok(()) }
    }
    fn charge(remaining: &mut u64, n: u64) -> Result<(), Error> {
        *remaining = remaining
            .checked_sub(n)
            .ok_or(Error::Limit("metadata bytes"))?;
        Ok(())
    }
    pub(super) fn bounded_link(
        path: &Path,
        expected: u64,
        remaining: &mut u64,
    ) -> Result<PathBuf, Error> {
        let capacity = expected
            .checked_add(1)
            .ok_or(Error::Limit("metadata bytes"))?;
        charge(remaining, capacity)?;
        let capacity = usize::try_from(capacity).map_err(|_| Error::Limit("metadata bytes"))?;
        let path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Invalid("NUL path"))?;
        let mut bytes = vec![0u8; capacity];
        let size = unsafe { libc::readlink(path.as_ptr(), bytes.as_mut_ptr().cast(), capacity) };
        if size < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if size as u64 != expected {
            return Err(Error::Invalid("symlink target size changed or truncated"));
        }
        bytes.truncate(size as usize);
        Ok(std::ffi::OsString::from_vec(bytes).into())
    }
    fn canonical_dir(path: &Path) -> Result<(), Error> {
        if !path.is_absolute()
            || path
                .components()
                .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
        {
            return Err(Error::Invalid("absolute canonical directory required"));
        }
        for p in path.ancestors() {
            if !fs::symlink_metadata(p)?.is_dir() {
                return Err(Error::Invalid("symlink/non-directory ancestor"));
            }
        }
        if fs::canonicalize(path)? != path {
            return Err(Error::Invalid("directory alias"));
        }
        Ok(())
    }
    fn identity(m: &Metadata) -> (u64, u64) {
        (m.dev(), m.ino())
    }
    // Check every source directory against destination ancestors before creating
    // output: lexical/canonical checks alone miss bind aliases of subdirectories.
    // Save directory metadata before read_dir can update its atime.
    struct Preflight<'a, C> {
        forbidden: Vec<(u64, u64)>,
        directories: HashMap<PathBuf, Metadata>,
        mount: u64,
        remaining_entries: usize,
        remaining_metadata: u64,
        cancelled: &'a C,
        noatime: bool,
        estimate: Option<TarEstimate>,
    }
    impl<C: Fn() -> bool> Preflight<'_, C> {
        fn visit(&mut self, path: &Path, depth: usize) -> Result<(), Error> {
            check(self.cancelled)?;
            if depth > 256 {
                return Err(Error::Limit("directory depth"));
            }
            self.remaining_entries = self
                .remaining_entries
                .checked_sub(1)
                .ok_or(Error::Limit("entries"))?;
            charge(
                &mut self.remaining_metadata,
                path.as_os_str().len() as u64 + 512,
            )?;
            if mount_id(path)? != self.mount {
                return Err(Error::Invalid("nested mount"));
            }
            let m = fs::symlink_metadata(path)?;
            if let Some(estimate) = &mut self.estimate {
                let attrs = xattrs(path, &mut estimate.remaining_metadata)?;
                estimate.add(path, &m, &attrs)?;
            }
            if m.is_dir() {
                if self.forbidden.contains(&identity(&m)) {
                    return Err(Error::Invalid("source/destination inode alias"));
                }
                self.directories.insert(path.to_owned(), m);
                if self.noatime {
                    for name in delta::names(path, self.cancelled)? {
                        self.visit(&path.join(name?), depth + 1)?;
                    }
                } else {
                    for entry in fs::read_dir(path)? {
                        self.visit(&entry?.path(), depth + 1)?;
                    }
                }
            }
            Ok(())
        }
    }

    // Sizes come from the selected files and attributes, not workload ceilings.
    // Allow tar/PAX/GNU headers and padding, and deduplicate hardlink payloads.
    struct TarEstimate {
        bytes: u64,
        links: HashMap<(u64, u64), u64>,
        remaining_metadata: u64,
    }
    impl TarEstimate {
        fn new(metadata: u64) -> Self {
            Self {
                bytes: 1024,
                links: HashMap::new(),
                remaining_metadata: metadata,
            }
        }
        fn add_bytes(&mut self, bytes: u64) -> Result<(), Error> {
            self.bytes = self
                .bytes
                .checked_add(bytes)
                .ok_or(Error::Limit("export space estimate"))?;
            Ok(())
        }
        fn padded(bytes: u64) -> Result<u64, Error> {
            bytes
                .checked_add(511)
                .map(|n| n / 512 * 512)
                .ok_or(Error::Limit("export space estimate"))
        }
        fn add(
            &mut self,
            path: &Path,
            m: &Metadata,
            attrs: &[(String, Vec<u8>)],
        ) -> Result<(), Error> {
            let path_bytes = path.as_os_str().len() as u64;
            let first = if !m.is_dir() && m.nlink() > 1 {
                if let Some(first) = self.links.get(&identity(m)) {
                    Some(*first)
                } else {
                    charge(&mut self.remaining_metadata, 128)?;
                    self.links.insert(identity(m), path_bytes);
                    None
                }
            } else {
                None
            };
            self.add_bytes(3072)?;
            self.add_bytes(Self::padded(path_bytes + 1)?)?;
            let link_bytes = first.unwrap_or(if m.file_type().is_symlink() {
                m.len()
            } else {
                0
            });
            self.add_bytes(Self::padded(
                link_bytes
                    .checked_add(1)
                    .ok_or(Error::Limit("export space estimate"))?,
            )?)?;
            let mut pax_bytes = 128u64;
            for (key, value) in attrs {
                pax_bytes = pax_bytes
                    .checked_add(key.len() as u64)
                    .and_then(|n| n.checked_add(value.len() as u64))
                    .and_then(|n| n.checked_add(32))
                    .ok_or(Error::Limit("export space estimate"))?;
            }
            self.add_bytes(Self::padded(pax_bytes)?)?;
            if m.is_file() && first.is_none() {
                self.add_bytes(Self::padded(m.len())?)?;
            }
            Ok(())
        }
    }
    #[cfg(test)]
    #[test]
    fn layered_admission_counts_only_coexisting_payloads() {
        let mib = 1024 * 1024;
        // The verification spool is gone before inherited base blobs are copied.
        // At 400 MiB free, a 120 MiB peak keeps the 256 MiB reserve intact.
        assert_eq!(
            payload_peak(60 * mib, 60 * mib, 60 * mib).unwrap(),
            120 * mib
        );
        assert_eq!(
            payload_peak(60 * mib, 60 * mib, 100 * mib).unwrap(),
            160 * mib
        );
        assert_eq!(payload_peak(60 * mib, 60 * mib, 0).unwrap(), 120 * mib);
        assert!(payload_peak(u64::MAX, 1, 0).is_err());
        assert_eq!(
            payload_peak(5 * mib, 60 * mib, 100 * mib).unwrap(),
            105 * mib
        );
        assert_eq!(payload_peak(5 * mib, 60 * mib, 0).unwrap(), 65 * mib);
    }

    #[cfg(test)]
    #[test]
    fn measured_export_space_deduplicates_payload_and_ignores_workload_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("long-first-name");
        fs::write(&first, vec![7; 2 * 1024 * 1024]).unwrap();
        let second = dir.path().join("b");
        let third = dir.path().join("c");
        fs::hard_link(&first, &second).unwrap();
        fs::hard_link(&first, &third).unwrap();
        let attrs = vec![("SCHILY.xattr.user.example".to_string(), vec![42; 1025])];
        let measure = |ceiling| {
            let mut estimate = TarEstimate::new(ceiling);
            for path in [&first, &second, &third] {
                estimate
                    .add(path, &fs::metadata(path).unwrap(), &attrs)
                    .unwrap();
            }
            assert_eq!(
                estimate.links[&identity(&fs::metadata(&first).unwrap())],
                first.as_os_str().len() as u64
            );
            estimate.bytes
        };
        let measured = measure(65536);
        assert_eq!(measured, measure(4 * 1024 * 1024 * 1024));
        assert!(measured >= 2 * 1024 * 1024 + 3 * 4096);
        assert!(measured < 2 * 1024 * 1024 + 64 * 1024);
    }

    fn mount_id(path: &Path) -> Result<u64, Error> {
        let p =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Invalid("NUL path"))?;
        let mut st: libc::statx = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::statx(
                libc::AT_FDCWD,
                p.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_MNT_ID,
                &mut st,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if st.stx_mask & libc::STATX_MNT_ID == 0 {
            return Err(Error::Invalid("statx mount IDs required"));
        }
        Ok(st.stx_mnt_id)
    }
    // Signed PAX decimals represent an instant, unlike timespec's floor seconds.
    fn timestamp(seconds: i64, nanos: i64) -> Vec<u8> {
        let ns = seconds as i128 * 1_000_000_000 + nanos as i128;
        format!(
            "{}{}.{:09}",
            if ns < 0 { "-" } else { "" },
            ns.abs() / 1_000_000_000,
            ns.abs() % 1_000_000_000
        )
        .into_bytes()
    }
    fn xattrs(path: &Path, remaining: &mut u64) -> Result<Vec<(String, Vec<u8>)>, Error> {
        let p = CString::new(path.as_os_str().as_bytes()).unwrap();
        let n = unsafe { libc::llistxattr(p.as_ptr(), std::ptr::null_mut(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error().into());
        }
        charge(remaining, n as u64)?;
        let mut names = vec![0u8; n as usize];
        let got = unsafe { libc::llistxattr(p.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
        if got != n {
            return Err(Error::Invalid("xattr list changed or unreadable"));
        }
        let mut result = Vec::new();
        for name in names.split(|&b| b == 0).filter(|n| !n.is_empty()) {
            let name_str =
                std::str::from_utf8(name).map_err(|_| Error::Invalid("non-UTF8 xattr name"))?;
            if name.contains(&b'=') || name.contains(&b'\n') {
                return Err(Error::Invalid("unrepresentable PAX xattr name"));
            }
            let key = CString::new(name).unwrap();
            let n = unsafe { libc::lgetxattr(p.as_ptr(), key.as_ptr(), std::ptr::null_mut(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if n == 0 {
                return Err(Error::Invalid("empty xattrs cannot roundtrip through PAX"));
            }
            charge(remaining, n as u64 + name.len() as u64 + 64)?;
            let mut value = vec![0; n as usize];
            if unsafe {
                libc::lgetxattr(
                    p.as_ptr(),
                    key.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            } != n
            {
                return Err(Error::Invalid("xattr changed or unreadable"));
            }
            result.push((format!("SCHILY.xattr.{name_str}"), value));
        }
        Ok(result)
    }

    struct Payload<'a, C> {
        file: &'a mut File,
        remaining: u64,
        cancelled: &'a C,
    }
    impl<C: Fn() -> bool> Read for Payload<'_, C> {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            if (self.cancelled)() {
                return Err(io::Error::other(Error::Cancelled));
            }
            let cap = self.remaining.min(65536).min(b.len() as u64) as usize;
            if cap == 0 {
                return Ok(0);
            }
            let n = self.file.read(&mut b[..cap])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "source shrank",
                ));
            }
            self.remaining -= n as u64;
            Ok(n)
        }
    }
    struct Walk<'a, C: Fn() -> bool> {
        tar: tar::Builder<LayerWriter<'a, &'a mut File, C>>,
        remaining: u64,
        entries: usize,
        max_entries: usize,
        mount: u64,
        links: HashMap<(u64, u64), (PathBuf, u64, u64, Metadata)>,
        directories: HashMap<PathBuf, Metadata>,
        cancelled: &'a C,
        snapshot: Option<&'a delta::Inventory>,
    }
    impl<C: Fn() -> bool> Walk<'_, C> {
        fn entry(&mut self, root: &Path, relative: &Path, depth: usize) -> Result<(), Error> {
            check(self.cancelled)?;
            if depth > 256 {
                return Err(Error::Limit("directory depth"));
            }
            if self.entries >= self.max_entries {
                return Err(Error::Limit("entries"));
            }
            self.entries += 1;
            charge(
                &mut self.remaining,
                relative.as_os_str().len() as u64 + 2048,
            )?;
            let path = root.join(relative);
            if mount_id(&path)? != self.mount {
                return Err(Error::Invalid("nested mount"));
            }
            let mut m = self
                .snapshot
                .and_then(|s| s.entries.get(relative))
                .map(|e| e.metadata.clone())
                .map_or_else(
                    || {
                        self.directories
                            .remove(&path)
                            .map_or_else(|| fs::symlink_metadata(&path), Ok)
                    },
                    Ok,
                )?;
            if let Some((_, _, expected, original)) = self.links.get(&identity(&m)) {
                if *expected != m.nlink() {
                    return Err(Error::Invalid("hardlink topology changed"));
                }
                // read_link may update shared symlink atime, so all aliases use
                // the metadata captured before the first payload/target read.
                m = original.clone();
            }
            let kind = m.file_type();
            if !(kind.is_dir() || kind.is_file() || kind.is_symlink()) {
                return Err(Error::Invalid("unsupported special file"));
            }
            if relative
                .file_name()
                .is_some_and(|n| n.as_bytes().starts_with(b".wh."))
            {
                return Err(Error::Invalid("reserved OCI whiteout name"));
            }
            let mut pax = xattrs(&path, &mut self.remaining)?;
            if self.snapshot.is_some() {
                // Filesystem xattr enumeration order may change after replay.
                pax.sort();
            }
            if kind.is_symlink() && (!pax.is_empty() || m.mode() & 0o7777 != 0o777) {
                return Err(Error::Invalid("unsupported symlink metadata"));
            }
            pax.push(("mtime".into(), timestamp(m.mtime(), m.mtime_nsec())));
            pax.push(("atime".into(), timestamp(m.atime(), m.atime_nsec())));
            // USTAR has no ctime slot; GNU's zero-filled slot is a real ctime
            // declaration to our verifier and cannot be restored on Linux.
            let mut header = tar::Header::new_ustar();
            header.set_uid(m.uid() as u64);
            header.set_gid(m.gid() as u64);
            header.set_mode(m.mode() & 0o7777);
            header.set_mtime(0); // exact signed instant is in PAX
            header.set_size(0);
            let name = if relative.as_os_str().is_empty() {
                Path::new(".")
            } else {
                relative
            };
            let mut link = None;
            if kind.is_dir() {
                header.set_entry_type(tar::EntryType::Directory);
            } else if let Some((first, count, expected, _)) = self.links.get_mut(&identity(&m)) {
                if *expected != m.nlink() {
                    return Err(Error::Invalid("hardlink topology changed"));
                }
                *count += 1;
                header.set_entry_type(tar::EntryType::Link);
                charge(&mut self.remaining, first.as_os_str().len() as u64)?;
                link = Some(first.clone());
            } else if kind.is_symlink() {
                self.links
                    .insert(identity(&m), (relative.to_owned(), 1, m.nlink(), m.clone()));
                header.set_entry_type(tar::EntryType::Symlink);
                link = Some(if let Some(s) = self.snapshot {
                    s.entries[relative]
                        .target
                        .clone()
                        .ok_or(Error::Invalid("missing symlink target"))?
                } else {
                    bounded_link(&path, m.len(), &mut self.remaining)?
                });
            } else {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(m.len());
                self.links
                    .insert(identity(&m), (relative.to_owned(), 1, m.nlink(), m.clone()));
            }
            self.tar
                .append_pax_extensions(pax.iter().map(|(k, v)| (k.as_str(), v.as_slice())))?;
            if let Some(target) = link {
                self.tar.append_link(&mut header, name, target)?;
            } else if kind.is_file() {
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOATIME)
                    .open(&path)?;
                let opened = file.metadata()?;
                if identity(&opened) != identity(&m) || !opened.is_file() || opened.len() != m.len()
                {
                    return Err(Error::Invalid("source changed"));
                }
                // Neither side of tar's streaming copy can issue >64 KiB I/O.
                self.tar.append_data(
                    &mut header,
                    name,
                    Payload {
                        file: &mut file,
                        remaining: m.len(),
                        cancelled: self.cancelled,
                    },
                )?;
                let after = file.metadata()?;
                if after.len() != m.len()
                    || after.mtime() != m.mtime()
                    || after.mtime_nsec() != m.mtime_nsec()
                {
                    return Err(Error::Invalid("source changed"));
                }
            } else {
                self.tar.append_data(&mut header, name, io::empty())?;
            }
            if kind.is_dir() && self.snapshot.is_none() {
                for child in fs::read_dir(&path)? {
                    check(self.cancelled)?;
                    self.entry(root, &relative.join(child?.file_name()), depth + 1)?;
                }
            }
            Ok(())
        }
    }
    fn descriptor(media: &str, size: u64, hash: Sha256) -> Result<Descriptor, Error> {
        Ok(Descriptor {
            media_type: media.into(),
            digest: format!("sha256:{:x}", hash.finalize()),
            size: i64::try_from(size).map_err(|_| Error::Limit("OCI size"))?,
            annotations: Default::default(),
            extensions: Default::default(),
        })
    }
    // Serialize through a capped writer, so a caller's huge config is not copied
    // into another unbounded allocation before the metadata limit is enforced.
    fn json_bytes(value: &Value, remaining: &mut u64) -> Result<Vec<u8>, Error> {
        struct Capped {
            bytes: Vec<u8>,
            cap: u64,
        }
        impl Write for Capped {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                if b.len() as u64 > self.cap - self.bytes.len() as u64 {
                    return Err(io::Error::other("metadata byte limit"));
                }
                self.bytes.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut out = Capped {
            bytes: Vec::new(),
            cap: *remaining,
        };
        serde_json::to_writer(&mut out, value)?;
        charge(remaining, out.bytes.len() as u64)?;
        Ok(out.bytes)
    }
    fn blob(
        store: &BlobStore,
        media: &str,
        bytes: &[u8],
        c: &impl Fn() -> bool,
    ) -> Result<Descriptor, Error> {
        let mut hash = Sha256::new();
        hash.update(bytes);
        let d = descriptor(media, bytes.len() as u64, hash)?;
        store.ingest(bytes, &d, bytes.len() as u64, c)?;
        Ok(d)
    }
    pub(super) enum SourceState<'a> {
        Observed,
        Archived(Option<(&'a mut Option<crate::rootfs::ReplayReceipt>, u64)>),
        Checkpoint(&'a mut Option<Baseline>),
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn export(
        root: &Path,
        dest: &Path,
        config: &Value,
        limits: Limits,
        encoding: Encoding,
        c: &impl Fn() -> bool,
        created: impl FnOnce() -> std::io::Result<()>,
        baseline: Option<&Baseline>,
        resources: Option<&crate::build_resources::Policy>,
        source_state: SourceState<'_>,
    ) -> Result<Exported, Error> {
        check(c)?;
        // Our writer emits at most PAX + GNU long path + GNU long link + entry
        // for each logical record. Untrusted base replay gets no multiplier.
        let physical_limit = baseline
            .map(|_| {
                limits
                    .max_entries
                    .checked_mul(4)
                    .ok_or(Error::Limit("physical header count"))
            })
            .transpose()?;
        canonical_dir(root)?;
        let root_c = CString::new(root.as_os_str().as_bytes()).unwrap();
        let mut fs_info: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(root_c.as_ptr(), &mut fs_info) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if matches!(
            fs_info.f_type,
            libc::PROC_SUPER_MAGIC | libc::SYSFS_MAGIC | libc::DEVPTS_SUPER_MAGIC
        ) {
            return Err(Error::Invalid("synthetic filesystem root"));
        }
        let parent = dest
            .parent()
            .ok_or(Error::Invalid("destination parent required"))?;
        canonical_dir(parent)?;
        if dest.file_name().is_none()
            || dest
                .components()
                .any(|p| matches!(p, Component::CurDir | Component::ParentDir))
            || dest.starts_with(root)
            || root.starts_with(dest)
        {
            return Err(Error::Invalid("source/destination overlap"));
        }
        let root_identity = identity(&fs::metadata(root)?);
        for p in parent.ancestors() {
            if identity(&fs::metadata(p)?) == root_identity {
                return Err(Error::Invalid("source/destination inode alias"));
            }
        }
        let object = config
            .as_object()
            .ok_or(Error::Invalid("config must be an object"))?;
        if object.get("os").and_then(Value::as_str) != Some("linux")
            || object.get("architecture").and_then(Value::as_str) != Some("amd64")
            || ["variant", "os.version", "os.features"]
                .iter()
                .any(|k| object.get(*k).is_some_and(|v| !v.is_null()))
        {
            return Err(Error::Invalid(
                "only unconstrained linux/amd64 config supported",
            ));
        }
        let mut remaining = limits.max_metadata_bytes;
        // Budget the input before cloning; stale history can be large too.
        let input = json_bytes(config, &mut remaining)?;
        let mut output: Value = serde_json::from_slice(&input)?;
        drop(input);
        let plan = baseline
            .map(|base| delta::plan(root, base, limits, &mut remaining, c))
            .transpose()?;
        let mut preflight = Preflight {
            forbidden: parent
                .ancestors()
                .map(|p| fs::metadata(p).map(|m| identity(&m)))
                .collect::<io::Result<Vec<_>>>()?,
            directories: HashMap::new(),
            mount: mount_id(root)?,
            remaining_entries: limits.max_entries,
            remaining_metadata: remaining,
            cancelled: c,
            noatime: baseline.is_some(),
            estimate: (resources.is_some() && plan.is_none())
                .then(|| TarEstimate::new(limits.max_metadata_bytes)),
        };
        preflight.visit(root, 0)?;
        remaining = preflight.remaining_metadata;
        if let Some(resources) = resources {
            let mut estimate = preflight
                .estimate
                .take()
                .unwrap_or_else(|| TarEstimate::new(limits.max_metadata_bytes));
            if let Some(plan) = &plan {
                for path in &plan.changed {
                    let node = &plan.inventory.entries[path];
                    estimate.add(path, &node.metadata, &node.attrs)?;
                }
                for path in &plan.whiteouts {
                    estimate.add_bytes(
                        1024 + TarEstimate::padded(path.as_os_str().len() as u64 + 1)?,
                    )?;
                }
            }
            let mut bytes = encoding.compression.max_encoded_size(estimate.bytes)?;
            let mut inodes = 8u64;
            if let Some(base) = baseline {
                // Account for the larger of verification and base-copy phases.
                // Public base blobs still receive independent output inodes.
                let mut base_bytes = 0u64;
                let mut seen = std::collections::BTreeSet::new();
                for descriptor in &base.state.layers {
                    if seen.insert(&descriptor.digest) {
                        if !matches!(source_state, SourceState::Checkpoint(_))
                            || !base.state.shareable
                        {
                            base_bytes = base_bytes
                                .checked_add(
                                    u64::try_from(descriptor.size)
                                        .map_err(|_| Error::Invalid("negative base blob size"))?,
                                )
                                .ok_or(Error::Limit("export space estimate"))?;
                        }
                        inodes += 1;
                    }
                }
                bytes = payload_peak(bytes, estimate.bytes, base_bytes)?;
            }
            bytes = bytes
                .checked_add(65536)
                .ok_or(Error::Limit("export space estimate"))?;
            resources.recheck("exporting selected filesystem records (measured payloads plus tar/padding allowance)", &[
                crate::build_resources::Requirement { path: dest.to_owned(), bytes, inodes }
            ]).map_err(io::Error::other)?;
        }
        fs::create_dir(dest)?; // exclusive ownership; never reuse existing output
        created()?;
        let store = BlobStore::open(dest)?;
        let mut spool = store.pending_export()?;
        let encoded = {
            let sink = LayerWriter::new(
                spool.as_file_mut(),
                encoding.compression,
                EncodingLimits {
                    max_uncompressed_bytes: limits.max_layer_bytes,
                    max_blob_bytes: encoding.max_blob_bytes,
                },
                c,
            );
            let mut walk = Walk {
                tar: tar::Builder::new(sink),
                remaining,
                entries: 0,
                max_entries: limits.max_entries,
                mount: mount_id(root)?,
                links: HashMap::new(),
                directories: preflight.directories,
                cancelled: c,
                snapshot: plan.as_ref().map(|p| &p.inventory),
            };
            walk.tar.follow_symlinks(false);
            if let Some(plan) = &plan {
                for path in &plan.whiteouts {
                    check(c)?;
                    if walk.entries >= walk.max_entries {
                        return Err(Error::Limit("entries"));
                    }
                    walk.entries += 1;
                    charge(&mut walk.remaining, path.as_os_str().len() as u64 + 2048)?;
                    let mut header = tar::Header::new_ustar();
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(0);
                    header.set_mode(0);
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_mtime(0);
                    walk.tar.append_data(&mut header, path, io::empty())?;
                }
                for path in &plan.changed {
                    walk.entry(root, path, 0)?;
                }
            } else {
                walk.entry(root, Path::new(""), 0)?;
            }
            if walk
                .links
                .values()
                .any(|(_, count, expected, _)| count != expected)
            {
                return Err(Error::Invalid("hardlinks outside source tree"));
            }
            remaining = walk.remaining;
            walk.tar.into_inner()?.finish()?.1
        };
        let layer = &encoded.descriptor;
        store.publish_export(spool, layer, encoding.max_blob_bytes, c)?;
        if baseline.is_some() {
            crate::layer::verify(
                &store,
                layer,
                &encoded.diff_id,
                dest,
                crate::layer::Limits {
                    max_blob_bytes: encoding.max_blob_bytes,
                    max_uncompressed_bytes: limits.max_layer_bytes,
                    max_entries: physical_limit.unwrap(),
                    max_metadata_bytes: limits.max_metadata_bytes,
                    max_gzip_header_bytes: 10,
                },
                c,
            )
            .map_err(Error::Layer)?;
        }
        let layers = if let Some(base) = baseline {
            if matches!(source_state, SourceState::Checkpoint(_)) {
                delta::inherit_with_sharing(
                    base,
                    &store,
                    layer,
                    &encoded.diff_id,
                    &mut output,
                    &mut remaining,
                    true,
                    c,
                )?
            } else {
                delta::inherit(
                    base,
                    &store,
                    layer,
                    &encoded.diff_id,
                    &mut output,
                    &mut remaining,
                    c,
                )?
            }
        } else {
            output["rootfs"] = json!({"type":"layers", "diff_ids":[encoded.diff_id.as_str()]});
            output["history"] = json!([{"created_by":"Weld flattened rootfs export", "comment":"Full filesystem snapshot; original layer history replaced."}]);
            vec![layer.clone()]
        };
        if let (SourceState::Archived(_) | SourceState::Checkpoint(_), Some(plan)) =
            (&source_state, &plan)
        {
            delta::restore_observed_links(root, &plan.inventory, c)?;
        }
        let config = blob(&store, CONFIG, &json_bytes(&output, &mut remaining)?, c)?;
        let manifest = blob(
            &store,
            MANIFEST,
            &json_bytes(
                &json!({"schemaVersion":2,"mediaType":MANIFEST,"config":config,"layers":&layers}),
                &mut remaining,
            )?,
            c,
        )?;
        let layout = json_bytes(&json!({"imageLayoutVersion":"1.0.0"}), &mut remaining)?;
        let index = json_bytes(
            &json!({"schemaVersion":2,"mediaType":INDEX,"manifests":[manifest]}),
            &mut remaining,
        )?;
        let receipt = if let SourceState::Archived(Some((_, limit))) = &source_state {
            let plan = plan
                .as_ref()
                .ok_or(Error::Invalid("root handoff requires layered export"))?;
            delta::exported_receipt(root, &plan.inventory, &output, &mut remaining, *limit, c)?
        } else {
            None
        };
        let next_baseline = if matches!(source_state, SourceState::Checkpoint(_)) {
            Some(delta::checkpoint_baseline(
                dest,
                layers,
                &output,
                plan.ok_or(Error::Invalid("checkpoint requires layered inventory"))?
                    .inventory,
                baseline
                    .ok_or(Error::Invalid("checkpoint baseline missing"))?
                    .state
                    .blob_limit
                    .max(encoding.max_blob_bytes),
                &mut remaining,
            )?)
        } else {
            None
        };
        check(c)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest.join("oci-layout"))?
            .write_all(&layout)?;
        let mut pending = tempfile::NamedTempFile::new_in(dest)?;
        pending.write_all(&index)?;
        pending.as_file().sync_all()?;
        check(c)?;
        pending
            .persist_noclobber(dest.join("index.json"))
            .map_err(|e| Error::Io(e.error))?;
        match source_state {
            SourceState::Archived(Some((slot, _))) => *slot = receipt,
            SourceState::Checkpoint(slot) => *slot = next_baseline,
            _ => (),
        }
        Ok(Exported {
            manifest,
            layer: encoded,
        })
    }
}
