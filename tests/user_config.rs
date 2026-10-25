#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use rpweld::{
    build::{self, BuildOptions, Limits, LocalBase},
    build_plan, export, image, layer,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

// Share the generic build instantiation so debug test binaries fit the cache identity budget.
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
        progress: true,
        managed_cache: None,
        export_mode: rpweld::build::ExportMode::Flattened,
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

fn next(o: &mut BuildOptions, root: &Path, name: &str) {
    o.work = root.join(format!("work-{name}"));
    o.output = root.join(format!("output-{name}"));
}

fn config(o: &BuildOptions) -> Value {
    image::load_layout(&o.output, None, o.limits.image, never_cancel)
        .unwrap()
        .config["config"]
        .clone()
}

fn write(path: &Path, value: &str) {
    fs::write(path, value).unwrap();
    let stamp = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    fs::File::open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_accessed(stamp).set_modified(stamp))
        .unwrap();
}

fn owner(path: &Path) -> (u32, u32) {
    let m = fs::metadata(path).unwrap();
    (m.uid(), m.gid())
}

fn root_modes(layout: &Path, limits: Limits) -> Vec<u32> {
    let metadata = image::load_layout(layout, None, limits.image, never_cancel).unwrap();
    let store = rpweld::oci::BlobStore::open(layout).unwrap();
    let spool = tempfile::tempdir().unwrap();
    let mut modes = Vec::new();
    for (descriptor, diff) in metadata.layers.iter().zip(&metadata.diff_ids) {
        let verified = layer::verify(
            &store,
            descriptor,
            diff,
            spool.path(),
            limits.layer,
            never_cancel,
        )
        .unwrap();
        modes.extend(
            verified
                .entries()
                .iter()
                .filter(|e| e.path.is_empty())
                .map(|e| e.mode),
        );
    }
    modes
}

fn private_umask_build(
    o: &BuildOptions,
    store: &Path,
    source: &str,
    base: Option<&Path>,
) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    write(&o.context.join("Dockerfile"), source);
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"));
    command
        .env("RPWELD_HOME", store)
        .args([
            "build",
            "--no-host-dns",
            "--run-timeout-seconds",
            "20",
            "-t",
            "rootmode:test",
        ])
        .arg("--work-dir")
        .arg(&o.work)
        .arg("--output")
        .arg(&o.output);
    if o.no_cache {
        command.arg("--no-cache");
    }
    if let Some(base) = base {
        command
            .arg("--base")
            .arg(format!("alpine={}", base.display()));
    }
    command.arg(&o.context);
    // Child-only: never change the umask of the parallel test harness.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
    command.output().unwrap()
}

fn assert_private_root_build(o: &BuildOptions, store: &Path, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for path in [
        o.work.clone(),
        o.work.join("state"),
        o.work.join("spool"),
        store.to_owned(),
    ] {
        assert_eq!(
            fs::metadata(&path).unwrap().mode() & 0o777,
            0o700,
            "{}",
            path.display()
        );
    }
    assert_eq!(
        fs::metadata(o.work.join("rootfs")).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(root_modes(&o.output, o.limits), vec![0o755]);
}

#[test]
fn private_umask_scratch_initial_checkpoint_and_inherited_roots() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    let store = t.path().join("store");
    let source = "FROM scratch\nWORKDIR /\nLABEL revision=one\n";
    o.no_cache = true;
    let out = private_umask_build(&o, &store, source, None);
    assert_private_root_build(&o, &store, &out);
    o.no_cache = false;
    next(&mut o, t.path(), "cold");
    let out = private_umask_build(&o, &store, source, None);
    assert_private_root_build(&o, &store, &out);
    assert!(o.work.join("rootfs-exported-2").is_dir());
    next(&mut o, t.path(), "checkpoint-hit");
    let changed = source.replace("revision=one", "revision=two");
    let out = private_umask_build(&o, &store, &changed, None);
    assert_private_root_build(&o, &store, &out);
    assert!(o.work.join("rootfs-before-2").is_dir());
    assert!(String::from_utf8_lossy(&out.stderr).contains("CACHED instruction 2 WORKDIR"));
    next(&mut o, t.path(), "whole-stage-hit");
    let out = private_umask_build(&o, &store, &changed, None);
    assert_private_root_build(&o, &store, &out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("CACHED (verified local stage)"));
    next(&mut o, t.path(), "inherited");
    let out = private_umask_build(
        &o,
        &store,
        "FROM scratch AS parent\nWORKDIR /\nFROM parent\nLABEL inherited=yes\n",
        None,
    );
    assert_private_root_build(&o, &store, &out);
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT Alpine with omitted root metadata"]
fn private_umask_nonroot_run_and_explicit_restricted_root() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    let store = t.path().join("store");
    let base = fs::canonicalize(
        std::env::var_os("RPWELD_TEST_LAYOUT").expect("local Alpine layout required"),
    )
    .unwrap();
    assert!(
        root_modes(&base, o.limits).is_empty(),
        "fixture must omit image root metadata"
    );
    let source = "FROM alpine AS parent\nUSER 12345:12345\nRUN test \"$(id -u)\" = 12345\nFROM parent\nRUN printf executed > /tmp/rootmode-marker\nLABEL revision=one\n";
    o.no_cache = true;
    let out = private_umask_build(&o, &store, source, Some(&base));
    assert_private_root_build(&o, &store, &out);
    assert_eq!(
        fs::read(o.work.join("rootfs/tmp/rootmode-marker")).unwrap(),
        b"executed"
    );
    // Export a deliberately restrictive image root; the engine must preserve it.
    let restricted = t.path().join("restricted-base");
    fs::set_permissions(o.work.join("rootfs"), fs::Permissions::from_mode(0o700)).unwrap();
    let metadata = image::load_layout(&o.output, None, o.limits.image, never_cancel).unwrap();
    export::export_layout(
        &o.work.join("rootfs"),
        &restricted,
        &metadata.config,
        o.limits.export,
        never_cancel,
    )
    .unwrap();
    assert_eq!(root_modes(&restricted, o.limits), vec![0o700]);
    next(&mut o, t.path(), "restrictive");
    let out = private_umask_build(&o, &store, "FROM alpine\nRUN true\n", Some(&restricted));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Permission denied"));
    assert_eq!(
        fs::metadata(o.work.join("rootfs")).unwrap().mode() & 0o777,
        0o700
    );
    o.no_cache = false;
    next(&mut o, t.path(), "runtime-cold");
    let out = private_umask_build(&o, &store, source, Some(&base));
    assert_private_root_build(&o, &store, &out);
    next(&mut o, t.path(), "runtime-checkpoint-hit");
    let out = private_umask_build(
        &o,
        &store,
        &source.replace("revision=one", "revision=two"),
        Some(&base),
    );
    assert_private_root_build(&o, &store, &out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("CACHED instruction 2 RUN"));
    assert_eq!(
        fs::read(o.work.join("rootfs/tmp/rootmode-marker")).unwrap(),
        b"executed"
    );
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT pointing to local Alpine OCI"]
fn real_run_defaults_to_root_for_absent_null_empty_user_and_accepts_explicit_root() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.no_cache = true;
    let layout = fs::canonicalize(
        std::env::var_os("RPWELD_TEST_LAYOUT")
            .expect("set RPWELD_TEST_LAYOUT to a local Alpine OCI layout"),
    )
    .unwrap();
    o.bases.insert(
        "alpine".into(),
        LocalBase {
            layout,
            reference: None,
        },
    );
    // Materialize the existing local image without invoking a worker in the test binary.
    build::build("FROM alpine\n", &o, never_cancel).unwrap();
    let base_config = image::load_layout(&o.output, None, o.limits.image, never_cancel)
        .unwrap()
        .config;
    for (name, user, explicit) in [
        ("absent", None, ""),
        ("null", Some(Value::Null), ""),
        ("empty", Some(json!("")), ""),
        ("explicit-root", None, "USER root\n"),
    ] {
        let mut cfg = base_config.clone();
        cfg["config"].as_object_mut().unwrap().remove("User");
        if let Some(user) = user {
            cfg["config"]["User"] = user;
        }
        let base = t.path().join(format!("base-{name}"));
        export::export_layout(
            &o.work.join("rootfs"),
            &base,
            &cfg,
            o.limits.export,
            never_cancel,
        )
        .unwrap();
        write(
            &o.context.join("Dockerfile"),
            &format!(
                "FROM alpine\n{explicit}RUN test \"$(id -u)\" = 0 && test \"$(id -g)\" = 0 && printf executed > /root-run-marker\n"
            ),
        );
        let work = t.path().join(format!("run-work-{name}"));
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .env("RPWELD_HOME", t.path().join("store"))
            .args([
                "build",
                "--no-cache",
                "--run-timeout-seconds",
                "30",
                "--base",
            ])
            .arg(format!("alpine={}", base.display()))
            .arg("--work-dir")
            .arg(&work)
            .arg("--output")
            .arg(t.path().join(format!("run-output-{name}")))
            .arg(&o.context)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(work.join("rootfs/root-run-marker")).unwrap(),
            b"executed",
            "{name}"
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("CACHED"));
    }
}

#[test]
fn all_six_user_forms_are_preserved_without_account_lookup() {
    for user in [
        "app",
        "1234",
        "app:team",
        "1234:5678",
        "app:5678",
        "1234:team",
    ] {
        let t = tempfile::tempdir().unwrap();
        let o = options(t.path());
        let source = format!("FROM scratch\nUSER {user}\n");
        build::build(&source, &o, never_cancel).unwrap();
        assert_eq!(config(&o)["User"], user);
        assert!(!o.work.join("rootfs/etc/passwd").exists());
    }
}

#[test]
fn invalid_user_syntax_is_rejected_before_mutation() {
    for user in [
        "",
        "app:",
        ":team",
        "app:team:extra",
        "app team",
        "-1",
        "1:-2",
        "2147483648",
        "a/../b",
        "'app team'",
        "[]",
    ] {
        let t = tempfile::tempdir().unwrap();
        let o = options(t.path());
        let source = format!("FROM scratch\nUSER {user}\n");
        assert!(build_plan::parse(&source).is_err(), "accepted {user:?}");
        assert!(build::build(&source, &o, never_cancel).is_err());
        assert!(!o.work.exists());
        assert!(!o.output.exists());
    }
}

#[test]
fn evaluated_user_obeys_arg_env_scope_and_rejects_invalid_expansion() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    o.args.insert("WHO".into(), "override".into());
    build::build(
        "FROM scratch\nARG WHO=default\nARG GROUP=123\nENV WHO=environment\nUSER ${WHO}:$GROUP\n",
        &o,
        never_cancel,
    )
    .unwrap();
    assert_eq!(config(&o)["User"], "environment:123");
    assert_eq!(config(&o)["Env"], json!(["WHO=environment"]));
    for (n, value) in ["", "bad:user:extra", "two words", "4294967295"]
        .iter()
        .enumerate()
    {
        next(&mut o, t.path(), &format!("invalid-{n}"));
        o.args.insert("WHO".into(), (*value).into());
        assert!(build::build("FROM scratch\nARG WHO\nUSER $WHO\n", &o, never_cancel).is_err());
        assert!(!o.work.exists());
    }
}

#[test]
fn inherited_named_user_and_workdir_do_not_require_accounts() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    let tree = t.path().join("base-tree");
    fs::create_dir(&tree).unwrap();
    let layout = t.path().join("base");
    export::export_layout(&tree, &layout,
        &json!({"os":"linux","architecture":"amd64","config":{"User":"missing:team","WorkingDir":"/inherited"}}),
        o.limits.export, never_cancel).unwrap();
    o.bases.insert(
        "local".into(),
        LocalBase {
            layout,
            reference: None,
        },
    );
    build::build("FROM local\nLABEL inherited=yes\n", &o, never_cancel).unwrap();
    assert_eq!(config(&o)["User"], "missing:team");
    assert!(o.work.join("rootfs/inherited").is_dir());
}

#[test]
fn stage_inheritance_and_cached_roundtrip_preserve_named_user() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    let source =
        "FROM scratch AS first\nARG WHO=absent\nUSER $WHO:team\nFROM first\nLABEL inherited=yes\n";
    build::build(source, &o, never_cancel).unwrap();
    assert_eq!(config(&o)["User"], "absent:team");
    next(&mut o, t.path(), "cached");
    build::build(source, &o, never_cancel).unwrap();
    assert_eq!(config(&o)["User"], "absent:team");
    next(&mut o, t.path(), "changed");
    o.args.insert("WHO".into(), "changed".into());
    build::build(source, &o, never_cancel).unwrap();
    assert_eq!(config(&o)["User"], "changed:team");
}

#[test]
fn workdir_resolves_after_copy_and_only_changes_new_directories() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "ownership tests require Linux root"
    );
    let t = tempfile::tempdir().unwrap();
    let o = options(t.path());
    write(
        &o.context.join("passwd"),
        "app:x:1234:5678::/home/app:/bin/sh\n",
    );
    let source = "FROM scratch\nWORKDIR /existing\nUSER app\nCOPY passwd /etc/passwd\nWORKDIR /existing/new/deep\n";
    build::build(source, &o, never_cancel).unwrap();
    assert_eq!(owner(&o.work.join("rootfs/existing")), (0, 0));
    assert_eq!(owner(&o.work.join("rootfs/existing/new")), (1234, 5678));
    assert_eq!(
        owner(&o.work.join("rootfs/existing/new/deep")),
        (1234, 5678)
    );
    assert_eq!(config(&o)["User"], "app");
}

#[test]
fn existing_workdir_preserves_mode_and_allows_missing_metadata_user() {
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    let tree = t.path().join("tree");
    fs::create_dir_all(tree.join("existing")).unwrap();
    fs::set_permissions(tree.join("existing"), fs::Permissions::from_mode(0o751)).unwrap();
    let layout = t.path().join("base");
    export::export_layout(
        &tree,
        &layout,
        &json!({"os":"linux","architecture":"amd64","config":{}}),
        o.limits.export,
        never_cancel,
    )
    .unwrap();
    o.bases.insert(
        "local".into(),
        LocalBase {
            layout,
            reference: None,
        },
    );
    build::build(
        "FROM local\nUSER missing\nWORKDIR /existing\n",
        &o,
        never_cancel,
    )
    .unwrap();
    let m = fs::metadata(o.work.join("rootfs/existing")).unwrap();
    assert_eq!(m.permissions().mode() & 0o777, 0o751);
    assert_eq!((m.uid(), m.gid()), owner(&tree.join("existing")));
    next(&mut o, t.path(), "missing");
    let error = build::build("FROM local\nUSER missing\nWORKDIR /new\n", &o, never_cancel)
        .unwrap_err()
        .to_string();
    assert!(error.contains("USER"), "{error}");
    assert!(!o.work.join("rootfs/new").exists());
}

#[test]
fn changed_user_invalidates_workdir_checkpoint_but_reuses_prior_copy() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "ownership tests require Linux root"
    );
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    write(&o.context.join("payload"), "payload");
    let source = "FROM scratch\nCOPY payload /payload\nARG WHO=1234:5678\nUSER $WHO\nWORKDIR /owned\nLABEL tail=one\n";
    build::build(source, &o, never_cancel).unwrap();
    next(&mut o, t.path(), "metadata-tail");
    build::build(&source.replace("tail=one", "tail=two"), &o, never_cancel).unwrap();
    assert!(
        o.work.join("rootfs-before-5").exists(),
        "same USER WORKDIR must hit"
    );
    assert_eq!(owner(&o.work.join("rootfs/owned")), (1234, 5678));
    next(&mut o, t.path(), "changed-user");
    o.args.insert("WHO".into(), "2345:6789".into());
    build::build(source, &o, never_cancel).unwrap();
    assert!(
        o.work.join("rootfs-before-2").exists(),
        "unaffected earlier COPY must hit"
    );
    assert!(
        !o.work.join("rootfs-before-5").exists(),
        "changed USER WORKDIR must miss"
    );
    assert_eq!(owner(&o.work.join("rootfs/owned")), (2345, 6789));
    assert_eq!(config(&o)["User"], "2345:6789");
}

#[test]
fn changed_account_file_invalidates_named_workdir_checkpoint() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "ownership tests require Linux root"
    );
    let t = tempfile::tempdir().unwrap();
    let mut o = options(t.path());
    write(
        &o.context.join("passwd"),
        "app:x:1234:5678::/home/app:/bin/sh\n",
    );
    let source = "FROM scratch\nCOPY passwd /etc/passwd\nUSER app\nWORKDIR /owned\n";
    build::build(source, &o, never_cancel).unwrap();
    next(&mut o, t.path(), "accounts-changed");
    write(
        &o.context.join("passwd"),
        "app:x:2345:6789::/home/app:/bin/sh\n",
    );
    build::build(source, &o, never_cancel).unwrap();
    assert!(!o.work.join("rootfs-before-4").exists());
    assert_eq!(owner(&o.work.join("rootfs/owned")), (2345, 6789));
}
