#![cfg(target_os = "linux")]

use rpweld::{
    build::{self, BuildOptions, Limits},
    export, image, layer,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

fn never_cancel() -> bool {
    false
}

fn options(root: &Path) -> BuildOptions {
    let context = root.join("context");
    let cache = root.join("cache");
    fs::create_dir(&context).unwrap();
    fs::create_dir(&cache).unwrap();
    BuildOptions {
        work: root.join("work"),
        output: root.join("output"),
        context,
        cache: Some(cache),
        dockerfile: None,
        bases: BTreeMap::new(),
        args: BTreeMap::new(),
        host_dns: false,
        verbose: false,
        target: None,
        no_cache: false,
        limits: Limits {
            image: image::Limits {
                max_metadata_bytes: 1 << 20,
                max_total_metadata_bytes: 4 << 20,
                max_descriptors: 100,
                max_layer_bytes: 64 << 20,
                max_total_layer_bytes: 128 << 20,
            },
            layer: layer::Limits {
                max_blob_bytes: 64 << 20,
                max_uncompressed_bytes: 128 << 20,
                max_entries: 100_000,
                max_metadata_bytes: 32 << 20,
                max_gzip_header_bytes: 65536,
            },
            export: export::Limits {
                max_layer_bytes: 128 << 20,
                max_entries: 100_000,
                max_metadata_bytes: 32 << 20,
            },
            max_replay_bytes: 128 << 20,
            max_replay_entries: 100_000,
            max_rootfs_bytes: 128 << 20,
            max_rootfs_entries: 100_000,
            max_plan_bytes: 1 << 20,
            run_timeout_seconds: 30,
        },
    }
}

fn write(path: &Path, value: &str) {
    fs::write(path, value).unwrap();
    let stamp = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    fs::File::open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_accessed(stamp).set_modified(stamp))
        .unwrap();
}

fn next(o: &mut BuildOptions, root: &Path, name: &str) {
    o.work = root.join(format!("work-{name}"));
    o.output = root.join(format!("output-{name}"));
}

#[test]
fn late_copy_and_metadata_changes_reuse_dependency_copy() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    write(&o.context.join("requirements"), "dependency==1");
    write(&o.context.join("app"), "app one");
    let source = "FROM scratch\nCOPY requirements /requirements\nCOPY app /app\nLABEL revision=one\nCMD [\"one\"]\n";
    build::build(source, &o, never_cancel).unwrap();
    write(&o.context.join("app"), "app two");
    next(&mut o, t.path(), "changed-app");
    build::build(source, &o, never_cancel).unwrap();
    assert!(
        o.work.join("rootfs-before-2").is_dir(),
        "dependency COPY must hit"
    );
    assert!(
        !o.work.join("rootfs-before-3").exists(),
        "changed app COPY must miss"
    );
    assert_eq!(fs::read(o.work.join("rootfs/app")).unwrap(), b"app two");
    next(&mut o, t.path(), "changed-config");
    let changed = source
        .replace("revision=one", "revision=two")
        .replace("[\"one\"]", "[\"two\"]");
    build::build(&changed, &o, never_cancel).unwrap();
    assert!(o.work.join("rootfs-before-2").is_dir());
    assert!(o.work.join("rootfs-before-3").is_dir());
    let metadata = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
    assert_eq!(metadata.config["config"]["Labels"]["revision"], "two");
    assert_eq!(metadata.config["config"]["Cmd"], serde_json::json!(["two"]));
}

#[test]
fn earlier_arg_and_env_inputs_invalidate_only_their_consumers() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    write(&o.context.join("requirements"), "dependency==1");
    write(&o.context.join("app"), "app");
    let source = "FROM scratch\nCOPY requirements /requirements\nARG DEST=first\nENV APP=$DEST\nCOPY app /$APP\n";
    build::build(source, &o, never_cancel).unwrap();
    o.args.insert("DEST".into(), "second".into());
    next(&mut o, t.path(), "arg");
    build::build(source, &o, never_cancel).unwrap();
    assert!(o.work.join("rootfs-before-2").is_dir());
    assert!(!o.work.join("rootfs-before-5").exists());
    assert!(o.work.join("rootfs/second").is_file());
    assert!(!o.work.join("rootfs/first").exists());
}

#[test]
fn corrupted_checkpoint_is_fatal_and_never_publishes_output() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    write(&o.context.join("requirements"), "dependency==1");
    write(&o.context.join("app"), "app one");
    let source = "FROM scratch\nCOPY requirements /requirements\nCOPY app /app\n";
    build::build(source, &o, never_cancel).unwrap();
    let checkpoint = image::load_layout(
        o.work.join("checkpoint-image-2"),
        None,
        o.limits.image,
        never_cancel,
    )
    .unwrap();
    let entry: PathBuf = fs::read_dir(o.cache.as_ref().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|path| {
            image::load_layout(path, None, o.limits.image, never_cancel)
                .unwrap()
                .selected
                == checkpoint.selected
        })
        .unwrap();
    let digest = checkpoint.layers[0].digest.to_string();
    fs::write(
        entry
            .join("blobs/sha256")
            .join(digest.strip_prefix("sha256:").unwrap()),
        b"corrupted",
    )
    .unwrap();
    write(&o.context.join("app"), "app two");
    next(&mut o, t.path(), "corrupted");
    assert!(build::build(source, &o, never_cancel).is_err());
    assert!(!o.output.exists());
    assert!(!o.work.join("rootfs-before-2").exists());
}

#[test]
fn no_cache_neither_requires_cache_directory_nor_creates_checkpoints() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.cache = Some(t.path().join("nonexistent-cache"));
    o.no_cache = true;
    write(&o.context.join("app"), "app");
    build::build("FROM scratch\nCOPY app /app\n", &o, never_cancel).unwrap();
    assert!(!o.cache.as_ref().unwrap().exists());
    assert!(!o.work.join("checkpoint-image-1").exists());
    assert_eq!(fs::read(o.work.join("rootfs/app")).unwrap(), b"app");
}

#[test]
fn sequential_hits_recharge_ignored_traversal_cumulatively() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.limits.layer.max_entries = 20;
    write(
        &o.context.join(".dockerignore"),
        ".dockerignore\nignored\n!never\n",
    );
    write(&o.context.join("keep"), "keep");
    fs::create_dir(o.context.join("ignored")).unwrap();
    let source = "FROM scratch\nCOPY . /a/\nCOPY . /b/\nLABEL revision=one\n";
    build::build(source, &o, never_cancel).unwrap();
    for n in 0..7 {
        write(&o.context.join(format!("ignored/{n}")), "ignored");
    }
    next(&mut o, t.path(), "budget");
    let error = build::build(
        &source.replace("revision=one", "revision=two"),
        &o,
        never_cancel,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("entries"), "{error}");
    assert!(!o.output.exists());
}

fn local_base(o: &mut BuildOptions, root: &Path, prepare: impl FnOnce(&Path)) {
    let tree = root.join("base-tree");
    fs::create_dir(&tree).unwrap();
    prepare(&tree);
    let layout = root.join("base-image");
    export::export_layout(
        &tree,
        &layout,
        &serde_json::json!({"os":"linux","architecture":"amd64","config":{}}),
        o.limits.export,
        never_cancel,
    )
    .unwrap();
    o.bases.insert(
        "local".into(),
        build::LocalBase {
            layout,
            reference: None,
        },
    );
}

#[test]
fn cold_and_hit_retained_roots_preserve_checkpoint_directory_atime() {
    use std::os::unix::fs::MetadataExt;
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    local_base(&mut o, t.path(), |root| {
        let stamp = root.join("stamp");
        fs::create_dir(&stamp).unwrap();
        fs::File::open(stamp)
            .unwrap()
            .set_times(
                fs::FileTimes::new().set_accessed(UNIX_EPOCH + Duration::from_secs(946684800)),
            )
            .unwrap();
    });
    write(&o.context.join("payload"), "payload");
    let source = "FROM local\nCOPY payload /payload\nLABEL revision=one\n";
    build::build(source, &o, never_cancel).unwrap();
    assert_eq!(
        fs::metadata(o.work.join("rootfs/stamp")).unwrap().atime(),
        946684800
    );
    next(&mut o, t.path(), "suffix");
    build::build(
        &source.replace("revision=one", "revision=two"),
        &o,
        never_cancel,
    )
    .unwrap();
    assert!(o.work.join("rootfs-before-2").exists());
    assert_eq!(
        fs::metadata(o.work.join("rootfs/stamp")).unwrap().atime(),
        946684800
    );
}

fn exported_atime(o: &BuildOptions, path: &str) -> layer::Timestamp {
    let metadata = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
    let store = rpweld::oci::BlobStore::open(&o.output).unwrap();
    let spool = tempfile::tempdir().unwrap();
    let verified = layer::verify(
        &store,
        &metadata.layers[0],
        &metadata.diff_ids[0],
        spool.path(),
        o.limits.layer,
        never_cancel,
    )
    .unwrap();
    verified
        .entries()
        .iter()
        .find(|e| e.path == path.as_bytes())
        .unwrap()
        .atime
        .clone()
        .unwrap()
}

#[test]
fn no_cache_stage_copy_preserves_exported_directory_atime() {
    let expected = layer::Timestamp {
        negative: false,
        seconds: 946684800,
        fraction: Vec::new(),
    };
    for suffix in ["", "LABEL producer=metadata-only\n"] {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        local_base(&mut o, t.path(), |root| {
            let stamp = root.join("stamp");
            fs::create_dir(&stamp).unwrap();
            fs::File::open(stamp)
                .unwrap()
                .set_times(
                    fs::FileTimes::new().set_accessed(UNIX_EPOCH + Duration::from_secs(946684800)),
                )
                .unwrap();
        });
        let source = format!(
            "FROM local AS producer\n{suffix}FROM scratch\nCOPY --from=producer /stamp /stamp\nLABEL final=metadata-only\n"
        );
        build::build(&source, &o, never_cancel).unwrap();
        assert_eq!(exported_atime(&o, "stamp"), expected);
        next(&mut o, t.path(), "no-cache");
        o.no_cache = true;
        o.cache = Some(t.path().join("nonexistent-cache"));
        build::build(&source, &o, never_cancel).unwrap();
        assert_eq!(exported_atime(&o, "stamp"), expected);
        assert!(!o.cache.as_ref().unwrap().exists());
        assert!(
            !o.work.join("rootfs-final-export").exists(),
            "final uncached stage does not need normalization for a consumer"
        );
    }
}

#[test]
fn no_cache_empty_scratch_stage_can_be_copied() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.no_cache = true;
    o.cache = Some(t.path().join("nonexistent-cache"));
    build::build(
        "FROM scratch AS empty\nLABEL stage=empty\nFROM scratch\nCOPY --from=empty . /empty/\n",
        &o,
        never_cancel,
    )
    .unwrap();
    assert!(o.work.join("rootfs/empty").is_dir());
    assert!(!o.cache.as_ref().unwrap().exists());
}

#[test]
fn unavailable_symlink_fingerprints_execute_copy_and_refresh_downstream_identity() {
    use std::os::unix::fs::symlink;
    for account in [false, true] {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        local_base(&mut o, t.path(), |root| {
            fs::create_dir(root.join("real")).unwrap();
            symlink("/real", root.join("link")).unwrap();
            fs::create_dir(root.join("etc")).unwrap();
            write(&root.join("real/passwd"), "builder:x:123:456::/:/bin/sh\n");
            symlink("/real/passwd", root.join("etc/passwd")).unwrap();
        });
        write(&o.context.join("payload"), "one");
        write(&o.context.join("tail"), "tail");
        let source = if account {
            "FROM local\nCOPY --chown=builder:456 payload /payload\nCOPY tail /tail\nLABEL revision=one\n"
        } else {
            "FROM local\nCOPY payload /link/payload\nCOPY tail /tail\nLABEL revision=one\n"
        };
        let result_path = if account {
            "rootfs/payload"
        } else {
            "rootfs/real/payload"
        };
        build::build(source, &o, never_cancel).unwrap();
        assert_eq!(fs::read(o.work.join(result_path)).unwrap(), b"one");
        assert!(o.work.join("checkpoint-image-2").exists());
        write(&o.context.join("payload"), "two");
        next(&mut o, t.path(), "changed");
        build::build(source, &o, never_cancel).unwrap();
        assert_eq!(fs::read(o.work.join(result_path)).unwrap(), b"two");
        assert!(
            !o.work.join("rootfs-before-3").exists(),
            "downstream must not use the stale pre-COPY identity"
        );
        o.no_cache = true;
        next(&mut o, t.path(), "uncached");
        build::build(source, &o, never_cancel).unwrap();
        assert_eq!(fs::read(o.work.join(result_path)).unwrap(), b"two");
    }
}
