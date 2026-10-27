#![cfg(target_os = "linux")]

use rpweld::run_mounts::{self, MountGuard, Options};
use std::{
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    options: Options,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&state).unwrap();
        let options = Options {
            cache_dir: Some(temp.path().join("packages")),
            ..Options::default()
        };
        Self {
            temp,
            root,
            state,
            options,
        }
    }
    fn secret(&mut self) {
        let file = self.temp.path().join("source");
        fs::write(&file, b"private-input-123").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        self.options.secrets.insert("token".into(), file);
    }
    fn prepare(&self, flags: &str) -> MountGuard {
        let flags = format!(
            "{flags},uid={},gid={} true",
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() }
        );
        let (mounts, _) = run_mounts::parse(&flags).unwrap();
        MountGuard::prepare(
            &self.root,
            &self.state,
            &mounts,
            &self.options,
            None,
            &|| false,
        )
        .unwrap()
    }
}

#[test]
fn parser_supports_defaults_multiple_locked_shared_and_rejects_unsafe_profiles() {
    for sharing in ["", ",sharing=shared", ",sharing=locked"] {
        assert!(run_mounts::parse(&format!("--mount=type=cache,target=/a{sharing} true")).is_ok());
    }
    assert!(
        run_mounts::parse("--mount=type=cache,target=/a --mount=type=cache,target=/b true").is_ok()
    );
    for flags in [
        "--mount=type=cache,target=/a,sharing=private",
        "--mount=type=cache,target=/",
        "--mount=type=cache,target=/a/../b",
        "--mount=type=cache,target=/a//b",
        "--mount=type=cache,target=/proc/x",
        "--mount=type=cache,target=/a --mount=type=cache,target=/a/b",
        "--mount=type=secret,id=x --mount=type=cache,target=/a",
        "--mount=type=secret,id=x,env=X",
        "--mount=type=secret,id=x,uid=-1",
        "--mount=type=secret,id=x,mode=7777",
        "--mount=type=cache,target=/a,mode=2775",
        "--mount=type=secret,id=x,required=maybe",
    ] {
        assert!(
            run_mounts::parse(&format!("{flags} true")).is_err(),
            "{flags}"
        );
    }
    assert!(run_mounts::parse_secret("id=x,env=TOKEN").is_err());
    assert!(run_mounts::parse_secret("id=x,src=/tmp/a,src=/tmp/b").is_err());
}

#[test]
fn secret_read_modify_failure_and_cancel_remove_only_materialized_paths() {
    for (success, cancel, modify) in [
        (true, false, false),
        (true, false, true),
        (false, false, true),
        (false, true, true),
    ] {
        let mut f = Fixture::new();
        f.secret();
        let before = fs::metadata(&f.root).unwrap();
        let guard = f.prepare("--mount=type=secret,id=token,required=true");
        assert_eq!(
            fs::read(f.root.join("run/secrets/token")).unwrap(),
            b"private-input-123"
        );
        if modify {
            fs::write(f.root.join("run/secrets/token"), b"modified").unwrap();
        }
        guard.finish(success, None, &|| cancel).unwrap();
        assert!(!f.root.join("run").exists());
        assert_eq!(
            fs::read(&f.options.secrets["token"]).unwrap(),
            b"private-input-123"
        );
        let after = fs::metadata(&f.root).unwrap();
        assert_eq!(
            (
                before.mode(),
                before.uid(),
                before.gid(),
                before.mtime(),
                before.mtime_nsec()
            ),
            (
                after.mode(),
                after.uid(),
                after.gid(),
                after.mtime(),
                after.mtime_nsec()
            )
        );
        assert_eq!(fs::read_dir(&f.state).unwrap().count(), 0);
    }
}

#[test]
fn optional_secret_never_consumes_inherited_file_or_symlink() {
    let f = Fixture::new();
    let mounts = run_mounts::parse("--mount=type=secret,id=token true")
        .unwrap()
        .0;
    for path in ["run", "run/secrets", "run/secrets/token"] {
        if let Some(parent) = f.root.join(path).parent() {
            fs::create_dir_all(parent).unwrap();
        }
        symlink(f.temp.path(), f.root.join(path)).unwrap();
        assert!(run_mounts::validate_targets(&f.root, &mounts, &f.options).is_err());
        fs::remove_file(f.root.join(path)).unwrap();
    }
    fs::write(f.root.join("run/secrets/token"), b"inherited").unwrap();
    assert!(run_mounts::validate_targets(&f.root, &mounts, &f.options).is_err());
    assert_eq!(
        fs::read(f.root.join("run/secrets/token")).unwrap(),
        b"inherited"
    );
}

#[test]
fn cache_reuses_changes_restores_readonly_inherited_tree_and_rolls_back_failures() {
    let f = Fixture::new();
    fs::create_dir_all(f.root.join("cache")).unwrap();
    fs::write(f.root.join("cache/inherited"), b"original").unwrap();
    fs::set_permissions(f.root.join("cache"), fs::Permissions::from_mode(0o555)).unwrap();
    let original = fs::metadata(f.root.join("cache")).unwrap();
    let guard = f.prepare("--mount=type=cache,id=packages,target=/cache");
    assert!(!f.root.join("cache/inherited").exists());
    fs::write(f.root.join("cache/package"), b"first").unwrap();
    guard.finish(true, None, &|| false).unwrap();
    assert_eq!(
        fs::read(f.root.join("cache/inherited")).unwrap(),
        b"original"
    );
    assert!(!f.root.join("cache/package").exists());
    let restored = fs::metadata(f.root.join("cache")).unwrap();
    assert_eq!(
        (
            original.ino(),
            original.mode(),
            original.mtime(),
            original.mtime_nsec()
        ),
        (
            restored.ino(),
            restored.mode(),
            restored.mtime(),
            restored.mtime_nsec()
        )
    );
    for failure in ["run", "cancel", "admission", "symlink"] {
        let guard = f.prepare("--mount=type=cache,id=packages,target=/cache");
        assert_eq!(fs::read(f.root.join("cache/package")).unwrap(), b"first");
        fs::write(f.root.join("cache/package"), b"second").unwrap();
        if failure == "symlink" {
            symlink(f.temp.path(), f.root.join("cache/escape")).unwrap();
        }
        let deny = |_: &Path, _: u64, _: u64| Err(io::Error::other("admission denied"));
        let result = guard.finish(
            failure != "run",
            if failure == "admission" {
                Some(&deny)
            } else {
                None
            },
            &|| failure == "cancel",
        );
        assert_eq!(result.is_ok(), failure == "run");
        assert_eq!(
            fs::read(f.root.join("cache/inherited")).unwrap(),
            b"original"
        );
    }
    let guard = f.prepare("--mount=type=cache,id=packages,target=/cache");
    assert_eq!(fs::read(f.root.join("cache/package")).unwrap(), b"first");
    fs::write(f.root.join("cache/package"), b"last").unwrap();
    guard.finish(true, None, &|| false).unwrap();
    let guard = f.prepare("--mount=type=cache,id=packages,target=/cache");
    assert_eq!(fs::read(f.root.join("cache/package")).unwrap(), b"last");
    guard.finish(false, None, &|| false).unwrap();
}

#[test]
fn cache_lock_serializes_waiters_and_wait_cancellation_does_not_mutate() {
    let f = Fixture::new();
    let guard = f.prepare("--mount=type=cache,target=/cache");
    let other_root = f.temp.path().join("other");
    let other_state = f.temp.path().join("other-state");
    fs::create_dir(&other_root).unwrap();
    fs::create_dir(&other_state).unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));
    let (e, c, options) = (entered.clone(), cancel.clone(), f.options.clone());
    let waiter = std::thread::spawn(move || {
        let mounts = run_mounts::parse("--mount=type=cache,target=/cache true")
            .unwrap()
            .0;
        let result =
            MountGuard::prepare(&other_root, &other_state, &mounts, &options, None, &|| {
                c.load(Ordering::SeqCst)
            });
        e.store(true, Ordering::SeqCst);
        assert!(result.is_err());
        assert!(!other_root.join("cache").exists());
    });
    std::thread::sleep(Duration::from_millis(100));
    assert!(!entered.load(Ordering::SeqCst));
    cancel.store(true, Ordering::SeqCst);
    waiter.join().unwrap();
    guard.finish(false, None, &|| false).unwrap();
}

#[test]
fn cache_refuses_unowned_roots_replaced_entries_hardlinks_and_byte_overflow() {
    let mut f = Fixture::new();
    fs::create_dir(f.options.cache_dir.as_ref().unwrap()).unwrap();
    fs::set_permissions(
        f.options.cache_dir.as_ref().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let mounts = run_mounts::parse("--mount=type=cache,target=/cache true")
        .unwrap()
        .0;
    assert!(MountGuard::prepare(&f.root, &f.state, &mounts, &f.options, None, &|| false).is_err());
    fs::remove_dir(f.options.cache_dir.as_ref().unwrap()).unwrap();
    f.options.limits.max_bytes = 10;
    let guard = f.prepare("--mount=type=cache,target=/cache");
    fs::write(f.root.join("cache/big"), b"more-than-ten-bytes").unwrap();
    assert!(guard.check_limits().is_err());
    assert!(guard.finish(true, None, &|| false).is_err());
    assert!(!f.root.join("cache").exists());
    let guard = f.prepare("--mount=type=cache,target=/cache");
    fs::write(f.root.join("cache/a"), b"a").unwrap();
    fs::hard_link(f.root.join("cache/a"), f.root.join("cache/b")).unwrap();
    assert!(guard.finish(true, None, &|| false).is_err());
    let guard = f.prepare("--mount=type=cache,target=/cache");
    fs::write(f.root.join("cache/a"), b"a").unwrap();
    guard.finish(true, None, &|| false).unwrap();
    let entry = fs::read_dir(f.options.cache_dir.as_ref().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap();
    fs::write(entry.join("unowned-extra"), b"keep me").unwrap();
    assert!(MountGuard::prepare(&f.root, &f.state, &mounts, &f.options, None, &|| false).is_err());
    assert_eq!(fs::read(entry.join("unowned-extra")).unwrap(), b"keep me");
    fs::remove_file(entry.join("unowned-extra")).unwrap();
    fs::remove_file(entry.join("owner.json")).unwrap();
    assert!(MountGuard::prepare(&f.root, &f.state, &mounts, &f.options, None, &|| false).is_err());
    assert_eq!(fs::read(entry.join("data/a")).unwrap(), b"a");
}

#[test]
fn sources_cannot_be_context_cache_alias_or_public_file() {
    let mut f = Fixture::new();
    f.secret();
    run_mounts::validate_inputs(&f.options, &[&f.root, &f.state], None).unwrap();
    assert!(run_mounts::validate_inputs(&f.options, &[f.temp.path()], None).is_err());
    fs::set_permissions(
        &f.options.secrets["token"],
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(run_mounts::validate_inputs(&f.options, &[&f.root], None).is_err());
}

#[test]
fn admission_and_metadata_limits_restore_root_before_reporting_failure() {
    let mut f = Fixture::new();
    let guard = f.prepare("--mount=type=cache,id=one,target=/cache");
    fs::write(f.root.join("cache/entry"), b"old").unwrap();
    guard.finish(true, None, &|| false).unwrap();
    let mounts = run_mounts::parse("--mount=type=cache,id=one,target=/cache true")
        .unwrap()
        .0;
    let deny = |_: &Path, _: u64, _: u64| Err(io::Error::other("no allocation available"));
    assert!(
        MountGuard::prepare(&f.root, &f.state, &mounts, &f.options, Some(&deny), &|| {
            false
        })
        .is_err()
    );
    assert!(!f.root.join("cache").exists());
    f.options.limits.max_metadata_bytes = 16_384;
    let guard = f.prepare("--mount=type=cache,id=one,target=/cache");
    for n in 0..100 {
        fs::write(f.root.join(format!("cache/file-{n}")), b"").unwrap();
    }
    assert!(guard.check_limits().is_err());
    assert!(guard.finish(true, None, &|| false).is_err());
    assert!(!f.root.join("cache").exists());
    let guard = f.prepare("--mount=type=cache,id=one,target=/cache");
    assert_eq!(fs::read_dir(f.root.join("cache")).unwrap().count(), 1);
    guard.finish(false, None, &|| false).unwrap();
}

#[test]
fn secret_hardlinks_and_renamed_mount_ancestors_cannot_publish() {
    let mut f = Fixture::new();
    f.secret();
    let guard = f.prepare("--mount=type=secret,id=token");
    fs::hard_link(f.root.join("run/secrets/token"), f.root.join("link")).unwrap();
    assert!(guard.finish(true, None, &|| false).is_err());
    assert!(!f.root.join("run").exists());
    fs::remove_file(f.root.join("link")).unwrap();
    let guard = f.prepare("--mount=type=secret,id=token");
    fs::rename(f.root.join("run"), f.root.join("moved")).unwrap();
    assert!(guard.finish(true, None, &|| false).is_err());
    assert!(!f.root.join("moved/secrets/token").exists());
}

#[test]
fn concurrent_writer_reads_the_previous_complete_publication() {
    let f = Fixture::new();
    let guard = f.prepare("--mount=type=cache,id=serial,target=/cache");
    fs::write(f.root.join("cache/value"), b"first").unwrap();
    let root = f.temp.path().join("writer-root");
    let state = f.temp.path().join("writer-state");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&state).unwrap();
    let options = f.options.clone();
    let entered = Arc::new(AtomicBool::new(false));
    let signal = entered.clone();
    let writer = std::thread::spawn(move || {
        signal.store(true, Ordering::SeqCst);
        let mounts = run_mounts::parse("--mount=type=cache,id=serial,target=/cache true")
            .unwrap()
            .0;
        let guard = MountGuard::prepare(&root, &state, &mounts, &options, None, &|| false).unwrap();
        assert_eq!(fs::read(root.join("cache/value")).unwrap(), b"first");
        fs::write(root.join("cache/value"), b"second").unwrap();
        guard.finish(true, None, &|| false).unwrap();
    });
    while !entered.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    guard.finish(true, None, &|| false).unwrap();
    writer.join().unwrap();
    let guard = f.prepare("--mount=type=cache,id=serial,target=/cache");
    assert_eq!(fs::read(f.root.join("cache/value")).unwrap(), b"second");
    guard.finish(false, None, &|| false).unwrap();
}

#[test]
fn namespace_stays_protected_from_cleanup_and_requires_its_store_lease() {
    let store = tempfile::tempdir().unwrap();
    fs::set_permissions(store.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(store.path(), &|| false).unwrap();
    let cache = store.path().join("run-cache-v1");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(cache.join("unknown"), b"not owned").unwrap();
    assert!(rpweld::store_access::validate_path(&cache, None).is_err());
    rpweld::store_access::validate_path(&cache, Some(&lease)).unwrap();
    let inventory =
        rpweld::store_inventory::inspect(store.path(), Default::default(), || false).unwrap();
    assert!(
        inventory
            .protected_entries
            .iter()
            .any(|e| e.path == Path::new("run-cache-v1"))
    );
    let plan = rpweld::cleanup_plan::inspect(
        store.path(),
        rpweld::cleanup_plan::Request::CachePrune,
        Default::default(),
        || false,
    )
    .unwrap();
    assert!(
        plan.candidates
            .iter()
            .all(|e| !e.path.starts_with("run-cache-v1"))
    );
    assert_eq!(fs::read(cache.join("unknown")).unwrap(), b"not owned");
}

#[test]
fn persistent_cache_locations_keep_store_boundaries_and_reject_future_cleanup_areas() {
    let store = tempfile::tempdir().unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(store.path(), &|| false).unwrap();
    let mut options = Options::default();
    for relative in [
        "build-current/work/packages",
        "build-older/work/nested/packages",
        "build-older/stages/stage-0-work/packages",
        "build-older/stages/stage-0-image/packages",
        "build-older/image/packages",
        "cache-v1/stage-one/packages",
        "cache-v2/staging-one/packages",
        "base-cache-v1/staging-one/packages",
        ".cleanup-txn-one/payload/packages",
    ] {
        // Reject even before a future build/retirement records these components.
        let cache = store.path().join(relative);
        fs::create_dir_all(cache.parent().unwrap()).unwrap();
        options.cache_dir = Some(cache);
        let error = run_mounts::validate_inputs(&options, &[], Some(&lease)).unwrap_err();
        assert!(
            error.to_string().contains("cleanup-owned"),
            "{relative}: {error}"
        );
    }
    let outside = tempfile::tempdir().unwrap();
    let alias = outside.path().join("stage-alias");
    symlink(store.path().join("build-older/stages"), &alias).unwrap();
    options.cache_dir = Some(alias.join("stage-0-work/new-cache"));
    assert!(
        run_mounts::validate_inputs(&options, &[], Some(&lease))
            .unwrap_err()
            .to_string()
            .contains("cleanup-owned")
    );
    for path in [
        store.path().join("run-cache-v1"),
        store.path().join("custom-packages"),
    ] {
        options.cache_dir = Some(path);
        run_mounts::validate_inputs(&options, &[], Some(&lease)).unwrap();
        assert!(run_mounts::validate_inputs(&options, &[], None).is_err());
    }
    let other = tempfile::tempdir().unwrap();
    let other_lease = rpweld::store_lease::StoreLease::shared(other.path(), &|| false).unwrap();
    options.cache_dir = Some(other.path().join("run-cache-v1"));
    assert!(
        run_mounts::validate_inputs(&options, &[], Some(&lease))
            .unwrap_err()
            .to_string()
            .contains("cross-store")
    );
    run_mounts::validate_inputs(&options, &[], Some(&other_lease)).unwrap();
    options.cache_dir = Some(outside.path().join("packages"));
    run_mounts::validate_inputs(&options, &[], None).unwrap();
}

#[test]
fn cache_copy_preserves_root_directory_and_file_special_mode_bits() {
    let f = Fixture::new();
    let guard = f.prepare("--mount=type=cache,id=modes,target=/cache");
    fs::create_dir(f.root.join("cache/sticky")).unwrap();
    fs::write(f.root.join("cache/executable"), b"contents").unwrap();
    let modes = [
        ("cache", 0o2775),
        ("cache/sticky", 0o1777),
        ("cache/executable", 0o6755),
    ];
    for (path, mode) in modes {
        fs::set_permissions(f.root.join(path), fs::Permissions::from_mode(mode)).unwrap();
    }
    guard.finish(true, None, &|| false).unwrap();
    let guard = f.prepare("--mount=type=cache,id=modes,target=/cache");
    for (path, mode) in modes {
        let meta = fs::metadata(f.root.join(path)).unwrap();
        assert_eq!(meta.mode() & 0o7777, mode, "{path}");
        assert_eq!(meta.uid(), unsafe { libc::geteuid() });
        assert_eq!(meta.gid(), unsafe { libc::getegid() });
    }
    guard.finish(false, None, &|| false).unwrap();
}

#[test]
fn cancellation_during_copy_out_preserves_old_generation_and_restores_image() {
    let f = Fixture::new();
    let guard = f.prepare("--mount=type=cache,id=rollback,target=/cache");
    fs::write(f.root.join("cache/value"), b"old").unwrap();
    guard.finish(true, None, &|| false).unwrap();
    let guard = f.prepare("--mount=type=cache,id=rollback,target=/cache");
    fs::write(f.root.join("cache/value"), vec![b'x'; 2 * 1024 * 1024]).unwrap();
    let polls = std::cell::Cell::new(0);
    let result = guard.finish(true, None, &|| {
        polls.set(polls.get() + 1);
        polls.get() >= 20
    });
    assert!(result.is_err());
    assert_eq!(polls.get(), 20);
    assert!(!f.root.join("cache").exists());
    assert_eq!(fs::read_dir(&f.state).unwrap().count(), 0);
    let guard = f.prepare("--mount=type=cache,id=rollback,target=/cache");
    assert_eq!(fs::read(f.root.join("cache/value")).unwrap(), b"old");
    guard.finish(false, None, &|| false).unwrap();
}
