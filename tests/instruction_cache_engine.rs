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

#[test]
fn cached_parent_receipt_exhaustion_falls_back_to_verified_replay() {
    use std::os::unix::fs::symlink;
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.export_mode = build::ExportMode::Layered;
    o.limits.image.max_descriptors = 500;
    o.limits.export.max_metadata_bytes = 160_000;
    for name in ["a", "b"] {
        fs::create_dir(o.context.join(name)).unwrap();
        symlink(name.repeat(4000), o.context.join(name).join("link")).unwrap();
    }
    let mut source = String::from("FROM scratch AS parent\n");
    for i in 0..60 {
        source.push_str(&format!(
            "COPY {}/ /tree/\n",
            if i % 2 == 0 { "a" } else { "b" }
        ));
    }
    source.push_str("FROM parent\nLABEL version=one\n");
    let mut cold = None;
    for phase in ["cold", "warm"] {
        if phase == "warm" {
            next(&mut o, t.path(), phase);
        }
        build::build(&source, &o, never_cancel).unwrap();
        let output = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
        if let Some(manifest) = &cold {
            assert_eq!(
                &output.selected, manifest,
                "warm replay preserves exact output"
            );
        } else {
            cold = Some(output.selected.clone());
        }
        assert_eq!(
            fs::read_link(o.work.join("rootfs/tree/link")).unwrap(),
            PathBuf::from("b".repeat(4000))
        );
    }
}

#[test]
fn layered_instruction_checkpoints_reuse_prefix_and_apply_only_the_next_delta() {
    use std::os::unix::fs::MetadataExt;
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.export_mode = build::ExportMode::Layered;
    write(&o.context.join("dependency"), &"x".repeat(1024 * 1024));
    write(&o.context.join("app"), "version-one");
    let source = "FROM scratch\nCOPY dependency /dependency\nCOPY app /app\n";
    build::build(source, &o, never_cancel).unwrap();
    let cold = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
    assert_eq!(
        cold.layers.len(),
        2,
        "two filesystem instruction deltas; FROM reuses the verified base"
    );
    let last = cold.layers.last().unwrap();
    assert!(
        last.size < 16384,
        "app delta must not repeat the dependency: {}",
        last.size
    );
    let archive =
        fs::File::open(o.output.join("blobs").join(last.digest.replace(':', "/"))).unwrap();
    let paths: Vec<_> = tar::Archive::new(archive)
        .entries()
        .unwrap()
        .map(|entry| entry.unwrap().path().unwrap().into_owned())
        .collect();
    assert_eq!(paths, vec![PathBuf::from("."), PathBuf::from("app")]);
    let dependency_blob = PathBuf::from("blobs").join(cold.layers[0].digest.replace(':', "/"));
    let first = o.work.join("checkpoint-image-2").join(&dependency_blob);
    let second = o.work.join("checkpoint-image-3").join(&dependency_blob);
    assert_eq!(
        fs::metadata(&first).unwrap().ino(),
        fs::metadata(&second).unwrap().ino(),
        "immutable private checkpoints must share unchanged blob storage"
    );
    assert_ne!(
        fs::metadata(&second).unwrap().ino(),
        fs::metadata(o.output.join(&dependency_blob)).unwrap().ino(),
        "mutable public output must have an independent inode"
    );
    write(&o.context.join("app"), "version-two");
    next(&mut o, t.path(), "edit");
    build::build(source, &o, never_cancel).unwrap();
    let edited = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
    assert_eq!(
        &cold.layers[..1],
        &edited.layers[..1],
        "unchanged instruction layers stay byte-identical"
    );
    assert_eq!(fs::read(o.work.join("rootfs/app")).unwrap(), b"version-two");
    assert_eq!(
        fs::metadata(o.work.join("rootfs/dependency"))
            .unwrap()
            .len(),
        1024 * 1024
    );
    assert!(
        !o.work.join("rootfs-before-2").exists(),
        "prefix hits must not retain a replaced full root"
    );
    next(&mut o, t.path(), "warm");
    build::build(source, &o, never_cancel).unwrap();
    let warm = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
    assert_eq!(
        edited.selected, warm.selected,
        "whole-stage hits preserve exact output"
    );
}

#[test]
fn cached_parent_root_handoff_preserves_prefix_after_a_child_edit() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.export_mode = build::ExportMode::Layered;
    write(&o.context.join("dependency"), "parent bytes");
    write(&o.context.join("app"), "one");
    let source =
        "FROM scratch AS parent\nCOPY dependency /dependency\nFROM parent\nCOPY app /app\n";
    for phase in ["cold", "edit"] {
        if phase == "edit" {
            write(&o.context.join("app"), "two");
            next(&mut o, t.path(), phase);
        }
        build::build(source, &o, never_cancel).unwrap();
        assert_eq!(
            fs::read(o.work.join("rootfs/dependency")).unwrap(),
            b"parent bytes"
        );
        let intermediates: Vec<_> = fs::read_dir(t.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".weld-stages-")
            })
            .collect();
        for intermediate in intermediates {
            assert!(
                !intermediate.join("stage-0-work/rootfs").exists(),
                "eligible cached parent root must move to its last child"
            );
            let parent = image::load_layout(
                intermediate.join("stage-0-image"),
                None,
                o.limits.image,
                never_cancel,
            )
            .unwrap();
            let child = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
            assert!(
                child.layers.starts_with(&parent.layers),
                "parent output remains independently verified"
            );
        }
    }
    assert_eq!(fs::read(o.work.join("rootfs/app")).unwrap(), b"two");
}

fn stages(root: &Path) -> PathBuf {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".weld-stages-")
        })
        .expect("intermediate stage directory")
}

#[test]
fn no_cache_last_from_consumer_takes_owned_root_without_changing_parent_image() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.no_cache = true;
    o.export_mode = build::ExportMode::Layered;
    fs::create_dir(o.context.join("tree")).unwrap();
    write(&o.context.join("tree/file"), "original");
    fs::set_permissions(
        o.context.join("tree/file"),
        fs::Permissions::from_mode(0o440),
    )
    .unwrap();
    symlink("file", o.context.join("tree/link")).unwrap();
    write(&o.context.join("replacement"), "child-only");
    let source = "FROM scratch AS parent\nCOPY --chown=123:456 tree /tree\nENV INHERITED=yes\nFROM parent AS earlier\nCOPY replacement /earlier\nFROM parent\nCOPY replacement /tree/file\nCOPY --from=earlier /earlier /earlier\n";
    build::build(source, &o, never_cancel).unwrap();
    let intermediate = stages(t.path());
    assert!(
        !intermediate.join("stage-0-work/rootfs").exists(),
        "last FROM consumer must take the parent root"
    );
    assert!(
        intermediate.join("stage-1-work/rootfs").exists(),
        "COPY source remains available"
    );
    assert_eq!(
        fs::read(o.work.join("rootfs/tree/file")).unwrap(),
        b"child-only"
    );
    assert_eq!(
        fs::read(o.work.join("rootfs/earlier")).unwrap(),
        b"child-only"
    );
    let original = fs::metadata(intermediate.join("stage-1-work/rootfs/tree/file")).unwrap();
    assert_eq!(
        (original.uid(), original.gid(), original.mode() & 0o777),
        (123, 456, 0o440)
    );
    assert_eq!(
        fs::read(intermediate.join("stage-1-work/rootfs/tree/file")).unwrap(),
        b"original"
    );
    assert_eq!(
        fs::read_link(o.work.join("rootfs/tree/link")).unwrap(),
        Path::new("file")
    );
    let parent = image::load_layout(
        intermediate.join("stage-0-image"),
        None,
        o.limits.image,
        never_cancel,
    )
    .unwrap();
    let child = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
    assert!(child.layers.starts_with(&parent.layers));
    assert!(child.diff_ids.starts_with(&parent.diff_ids));
    assert_eq!(child.layers.len(), parent.layers.len() + 1);
    assert!(
        child.config["config"]["Env"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("INHERITED=yes"))
    );
    let store = rpweld::oci::BlobStore::open(intermediate.join("stage-0-image")).unwrap();
    let spool = t.path().join("parent-check");
    fs::create_dir(&spool).unwrap();
    let mut verified = layer::verify(
        &store,
        &parent.layers[0],
        &parent.diff_ids[0],
        &spool,
        o.limits.layer,
        never_cancel,
    )
    .unwrap();
    let restored = t.path().join("parent-root");
    fs::create_dir(&restored).unwrap();
    rpweld::rootfs::apply_layer(&restored, &mut verified, never_cancel).unwrap();
    assert_eq!(fs::read(restored.join("tree/file")).unwrap(), b"original");
}

#[test]
fn root_handoff_preserves_link_topology_metadata_and_empty_children() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.no_cache = true;
    o.export_mode = build::ExportMode::Layered;
    local_base(&mut o, t.path(), |root| {
        fs::write(root.join("file"), b"shared payload").unwrap();
        fs::set_permissions(root.join("file"), fs::Permissions::from_mode(0o450)).unwrap();
        std::os::unix::fs::chown(root.join("file"), Some(123), Some(456)).unwrap();
        fs::hard_link(root.join("file"), root.join("alias")).unwrap();
        symlink("/file", root.join("link")).unwrap();
        fs::hard_link(root.join("link"), root.join("link-alias")).unwrap();
    });
    build::build("FROM local AS first\nENV VALUE=first\nFROM first AS second\nENV VALUE=second\nFROM second\nLABEL done=yes\n", &o, never_cancel).unwrap();
    let intermediate = stages(t.path());
    for n in [0, 1] {
        assert!(!intermediate.join(format!("stage-{n}-work/rootfs")).exists());
        assert!(
            intermediate
                .join(format!("stage-{n}-image/index.json"))
                .is_file()
        );
    }
    let root = o.work.join("rootfs");
    let file = fs::symlink_metadata(root.join("file")).unwrap();
    assert_eq!(
        file.ino(),
        fs::symlink_metadata(root.join("alias")).unwrap().ino()
    );
    assert_eq!(
        (file.uid(), file.gid(), file.mode() & 0o777),
        (123, 456, 0o450)
    );
    let link = fs::symlink_metadata(root.join("link")).unwrap();
    assert_eq!(
        link.ino(),
        fs::symlink_metadata(root.join("link-alias")).unwrap().ino()
    );
    let output = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
    let layout = o.bases["local"].layout.clone();
    let base = image::load_layout(&layout, None, o.limits.image, never_cancel).unwrap();
    assert!(output.layers.starts_with(&base.layers));
    assert_eq!(output.layers.len(), base.layers.len() + 3);
    for layer in &output.layers[base.layers.len()..] {
        let archive = fs::File::open(
            o.output
                .join("blobs/sha256")
                .join(layer.digest.split(':').nth(1).unwrap()),
        )
        .unwrap();
        let names: Vec<_> = tar::Archive::new(archive)
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![PathBuf::from(".")],
            "metadata-only children must not re-emit untouched files"
        );
    }
    assert_eq!(
        output.config["config"]["Env"],
        serde_json::json!(["VALUE=second"])
    );
}

#[test]
fn copied_parents_and_flattened_builds_keep_separate_roots() {
    for (mode, no_cache, copy) in [
        (build::ExportMode::Layered, true, true),
        (build::ExportMode::Flattened, true, false),
        (build::ExportMode::Layered, false, true),
    ] {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        o.no_cache = no_cache;
        o.export_mode = mode;
        write(&o.context.join("payload"), "original");
        let source = format!(
            "FROM scratch AS parent\nCOPY payload /payload\nFROM parent\n{}",
            if copy {
                "COPY --from=parent /payload /copy\n"
            } else {
                "LABEL child=yes\n"
            }
        );
        build::build(&source, &o, never_cancel).unwrap();
        assert!(
            stages(t.path())
                .join("stage-0-work/rootfs/payload")
                .is_file()
        );
        assert_eq!(
            fs::read(o.work.join("rootfs/payload")).unwrap(),
            b"original"
        );
    }
}

#[test]
fn handoff_cancellation_retains_owned_child_root_without_publishing() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.no_cache = true;
    o.export_mode = build::ExportMode::Layered;
    write(&o.context.join("payload"), "original");
    let cancelled: &dyn Fn() -> bool = &|| o.work.join("rootfs").exists();
    let error = build::build(
        "FROM scratch AS parent\nCOPY payload /payload\nFROM parent\nLABEL child=yes\n",
        &o,
        cancelled,
    )
    .unwrap_err();
    assert!(
        error.to_string().to_lowercase().contains("cancel"),
        "{error}"
    );
    assert!(!o.output.exists());
    assert_eq!(
        fs::read(o.work.join("rootfs/payload")).unwrap(),
        b"original"
    );
    let intermediate = stages(t.path());
    assert!(!intermediate.join("stage-0-work/rootfs").exists());
    assert!(intermediate.join("stage-0-image/index.json").is_file());
}

#[test]
fn no_cache_copy_only_stages_keep_filesystems_without_images() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    for mode in [build::ExportMode::Layered, build::ExportMode::Flattened] {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        o.no_cache = true;
        o.export_mode = mode;
        fs::create_dir(o.context.join("tree")).unwrap();
        write(&o.context.join("tree/file"), "stage payload");
        fs::set_permissions(
            o.context.join("tree/file"),
            fs::Permissions::from_mode(0o440),
        )
        .unwrap();
        fs::hard_link(o.context.join("tree/file"), o.context.join("tree/alias")).unwrap();
        symlink("file", o.context.join("tree/link")).unwrap();
        let source = "FROM scratch AS producer\nCOPY --chown=123:456 tree /tree\nENV PRIVATE=yes\nFROM producer AS unused\nCOPY missing /missing\nFROM scratch AS relay\nCOPY --from=producer /tree /relay\nFROM scratch\nCOPY --from=producer /tree /direct\nCOPY --from=relay /relay /indirect\n";
        build::build(source, &o, never_cancel).unwrap();
        let intermediate = stages(t.path());
        for n in [0, 2] {
            assert!(intermediate.join(format!("stage-{n}-work/rootfs")).is_dir());
            assert!(
                !intermediate.join(format!("stage-{n}-image")).exists(),
                "COPY-only stage was exported"
            );
        }
        assert!(!intermediate.join("stage-1-work").exists());
        assert!(o.output.join("index.json").is_file());
        assert_eq!(fs::read_dir(o.cache.as_ref().unwrap()).unwrap().count(), 0);
        for prefix in ["direct", "indirect"] {
            let root = o.work.join("rootfs").join(prefix);
            let meta = fs::metadata(root.join("file")).unwrap();
            assert_eq!(
                (meta.uid(), meta.gid(), meta.mode() & 0o777),
                (123, 456, 0o440)
            );
            // COPY currently materializes hardlink aliases independently in both paths.
            let alias = fs::metadata(root.join("alias")).unwrap();
            assert_eq!(
                (alias.uid(), alias.gid(), alias.mode() & 0o777),
                (123, 456, 0o440)
            );
            assert_eq!(
                (alias.mtime(), alias.mtime_nsec()),
                (meta.mtime(), meta.mtime_nsec())
            );
            assert_eq!((meta.atime(), meta.atime_nsec()), (2_000_000_000, 0));
            assert_eq!(fs::read(root.join("alias")).unwrap(), b"stage payload");
            assert_eq!(fs::read(root.join("file")).unwrap(), b"stage payload");
            assert_eq!(fs::read_link(root.join("link")).unwrap(), Path::new("file"));
        }
        let result = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
        assert_eq!(result.config["config"]["Env"], serde_json::json!([]));
    }
}

#[test]
fn no_cache_copy_only_cancellation_and_budget_failure_publish_nothing() {
    let source = "FROM scratch AS producer\nCOPY payload /payload\nFROM scratch\nCOPY --from=producer /payload /payload\n";
    for cancel in [false, true] {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        o.no_cache = true;
        o.export_mode = build::ExportMode::Layered;
        write(&o.context.join("payload"), "payload");
        if !cancel {
            o.limits.max_rootfs_bytes = 1;
        }
        let cancelled: &dyn Fn() -> bool = &|| cancel && o.work.join("rootfs").exists();
        let error = build::build(source, &o, cancelled).unwrap_err().to_string();
        assert!(
            error
                .to_lowercase()
                .contains(if cancel { "cancel" } else { "limit" }),
            "{error}"
        );
        assert!(!o.output.exists());
        let intermediate = stages(t.path());
        assert!(!intermediate.join("stage-0-image").exists());
        assert_eq!(fs::read_dir(o.cache.as_ref().unwrap()).unwrap().count(), 0);
    }
}

#[test]
fn no_cache_from_dependencies_and_explicit_targets_still_export() {
    for target in [None, Some("producer".to_owned())] {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        o.no_cache = true;
        o.export_mode = build::ExportMode::Layered;
        o.target = target;
        write(&o.context.join("payload"), "inherited");
        let source = "FROM scratch AS producer\nARG VALUE=kept\nENV INHERITED=yes\nCOPY payload /payload\nFROM producer AS child\nENV ARG=$VALUE\nCOPY --from=producer /payload /copy\nFROM scratch AS unused\nCOPY absent /absent\nFROM child AS final\n";
        build::build(source, &o, never_cancel).unwrap();
        let result = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
        assert!(
            result.config["config"]["Env"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("INHERITED=yes"))
        );
        if o.target.is_none() {
            let intermediate = stages(t.path());
            assert!(intermediate.join("stage-0-image/index.json").is_file());
            assert!(intermediate.join("stage-1-image/index.json").is_file());
            assert!(!intermediate.join("stage-2-work").exists());
            assert!(
                result.config["config"]["Env"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("ARG=kept"))
            );
            assert_eq!(fs::read(o.work.join("rootfs/copy")).unwrap(), b"inherited");
        }
    }
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
        progress: true,
        managed_cache: None,
        export_mode: rpweld::build::ExportMode::Flattened,
        target: None,
        no_cache: false,
        run_mounts: Default::default(),
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
fn layered_cold_checkpoints_keep_root_and_exact_archived_metadata() {
    use std::{
        cell::Cell,
        os::unix::fs::{MetadataExt, symlink},
    };
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.export_mode = build::ExportMode::Layered;
    local_base(&mut o, t.path(), |root| {
        fs::write(root.join("payload"), vec![7; 1 << 20]).unwrap();
        symlink("/payload", root.join("link")).unwrap();
        fs::hard_link(root.join("link"), root.join("link-alias")).unwrap();
    });
    write(&o.context.join("one"), "one");
    write(&o.context.join("two"), "two");
    let source =
        "FROM local\nWORKDIR /app\nCOPY one /app/one\nCOPY two /app/two\nLABEL suffix=yes\n";
    let original_inode = Cell::new(None);
    build::build(source, &o, || {
        if let Ok(m) = fs::symlink_metadata(o.work.join("rootfs/payload")) {
            if let Some(original) = original_inode.get() {
                assert_eq!(
                    m.ino(),
                    original,
                    "cold checkpoint replaced the working inode"
                );
            } else {
                original_inode.set(Some(m.ino()));
            }
        }
        false
    })
    .unwrap();
    assert!(original_inode.get().is_some());
    assert!(
        !fs::read_dir(&o.work).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("rootfs-")),
        "cold layered build retained reconstructed roots"
    );
    for mode in ["cold", "hit", "no-cache"] {
        if mode != "cold" {
            next(&mut o, t.path(), mode);
            o.no_cache = mode == "no-cache";
            build::build(source, &o, never_cancel).unwrap();
        }
        let image = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
        let root = t.path().join(format!("replayed-{mode}"));
        fs::create_dir(&root).unwrap();
        let store = rpweld::oci::BlobStore::open(&o.output).unwrap();
        for (d, id) in image.layers.iter().zip(&image.diff_ids) {
            let mut layer =
                layer::verify(&store, d, id, t.path(), o.limits.layer, never_cancel).unwrap();
            rpweld::rootfs::apply_layer(&root, &mut layer, never_cancel).unwrap();
        }
        for name in [
            "",
            "app",
            "app/one",
            "app/two",
            "payload",
            "link",
            "link-alias",
        ] {
            let live = fs::symlink_metadata(o.work.join("rootfs").join(name)).unwrap();
            let archived = fs::symlink_metadata(root.join(name)).unwrap();
            let attributes = |m: &fs::Metadata| {
                (
                    m.mode(),
                    m.uid(),
                    m.gid(),
                    m.atime(),
                    m.atime_nsec(),
                    m.mtime(),
                    m.mtime_nsec(),
                )
            };
            assert_eq!(attributes(&live), attributes(&archived), "{mode}: {name}");
        }
        assert_eq!(fs::read(root.join("app/two")).unwrap(), b"two");
        assert_eq!(
            fs::read_link(root.join("link")).unwrap(),
            Path::new("/payload")
        );
        assert_eq!(
            fs::symlink_metadata(root.join("link")).unwrap().ino(),
            fs::symlink_metadata(root.join("link-alias")).unwrap().ino()
        );
    }
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
    for mode in [build::ExportMode::Flattened, build::ExportMode::Layered] {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        o.export_mode = mode;
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
fn final_checkpoint_keeps_verified_root_without_second_replay() {
    use std::os::unix::fs::MetadataExt;
    for mode in [build::ExportMode::Flattened, build::ExportMode::Layered] {
        let t = tempfile::tempdir().unwrap();
        let mut o = options(t.path());
        o.export_mode = mode;
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
        let source = "FROM local\nCOPY payload /payload\n";
        for phase in ["cold", "instruction-hit"] {
            if phase == "instruction-hit" {
                // Change the whole-context key without changing selected COPY inputs.
                write(&o.context.join("unrelated"), "unrelated");
                next(&mut o, t.path(), phase);
            }
            build::build(source, &o, never_cancel).unwrap();
            assert!(
                !o.work.join("rootfs-final-export").exists(),
                "{mode:?} {phase}: redundant replay"
            );
            assert_eq!(
                fs::metadata(o.work.join("rootfs/stamp")).unwrap().atime(),
                946684800
            );
            assert_eq!(fs::read(o.work.join("rootfs/payload")).unwrap(), b"payload");
            if phase == "instruction-hit" {
                assert_eq!(
                    o.work.join("rootfs-before-2").exists(),
                    mode == build::ExportMode::Flattened,
                    "layered hits apply only their delta; flattened hits restore a full checkpoint"
                );
            }
            let output = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
            let store = rpweld::oci::BlobStore::open(&o.output).unwrap();
            let spool = tempfile::tempdir().unwrap();
            for (descriptor, diff_id) in output.layers.iter().zip(&output.diff_ids) {
                layer::verify(
                    &store,
                    descriptor,
                    diff_id,
                    spool.path(),
                    o.limits.layer,
                    never_cancel,
                )
                .unwrap();
            }
        }
        next(&mut o, t.path(), "metadata-suffix");
        build::build(
            &format!("{source}LABEL revision=changed\n"),
            &o,
            never_cancel,
        )
        .unwrap();
        assert_eq!(
            o.work.join("rootfs-final-export").exists(),
            mode == build::ExportMode::Flattened,
            "only flattened export still needs restoration"
        );
        assert_eq!(
            fs::metadata(o.work.join("rootfs/stamp")).unwrap().atime(),
            946684800
        );
    }
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
