#![cfg(target_os = "linux")]
use rpweld::{
    build_record::{BuildRecord, Component, Owned, Phase, Record, identity},
    cleanup_apply::{self, Selection},
    cleanup_plan::{self, BuildId, TagId},
    store_inventory::Limits,
    store_lease::StoreLease,
};
use std::{
    fs,
    os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
};

// Forked CLI tests must not inherit another test's lease, even briefly.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn store() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    drop(StoreLease::shared(t.path(), &|| false).unwrap());
    t
}
fn build(store: &Path, components: &[&str]) -> PathBuf {
    let lease = StoreLease::shared(store, &|| false).unwrap();
    let mut b = BuildRecord::allocate(store, &lease, None, None, vec![], false).unwrap();
    for part in components {
        let path = b.path.join(part);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        b.update(&lease, |r| {
            r.phase = Phase::Failed;
            r.owned.push(Owned {
                components: part
                    .split('/')
                    .map(|s| Component::try_from(s.to_owned()).unwrap())
                    .collect(),
                identity: identity(&fs::metadata(path).unwrap()),
            });
        })
        .unwrap();
    }
    b.path
}
fn apply(store: &Path, selection: Selection) -> cleanup_apply::Report {
    cleanup_apply::apply(store, selection, Limits::default(), || false).unwrap()
}
fn tx(store: &Path) -> Option<PathBuf> {
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
fn tag(store: &Path, target: &Path) {
    let l = StoreLease::shared(store, &|| false).unwrap();
    rpweld::registry::save_tag(store, &l, "docker.io/example/test:latest", target).unwrap();
}

#[test]
fn deletes_only_selected_components_preserving_unknowns_external_links_and_lock() {
    let _s = SERIAL.lock().unwrap();
    let t = store();
    let outside = tempfile::tempdir().unwrap();
    let canary = outside.path().join("canary");
    fs::write(&canary, b"external contents").unwrap();
    let before = fs::metadata(&canary).unwrap();
    let run = build(
        t.path(),
        &["work", "image", "stages", "stages/stage-0-work"],
    );
    let other = build(t.path(), &["work"]);
    fs::write(run.join("work/a"), b"payload").unwrap();
    fs::hard_link(&canary, run.join("work/hardlink")).unwrap();
    symlink(outside.path(), run.join("work/symlink")).unwrap();
    fs::write(
        run.join("work")
            .join(std::ffi::OsString::from_vec(b"nonutf-\xff".to_vec())),
        b"native",
    )
    .unwrap();
    fs::write(run.join("stages/unknown"), b"keep").unwrap();
    fs::write(run.join("unknown"), b"keep").unwrap();
    fs::write(t.path().join("auth.json"), b"keep").unwrap();
    let weird = std::ffi::OsString::from_vec(b"unknown-\xff".to_vec());
    fs::write(t.path().join(&weird), b"keep").unwrap();
    let lock = identity(&fs::metadata(t.path().join("store.lock")).unwrap());
    let root = identity(&fs::metadata(t.path()).unwrap());
    let result = apply(
        t.path(),
        Selection::BuildRemove(BuildId::parse(run.file_name().unwrap().to_str().unwrap()).unwrap()),
    );
    assert_eq!(result.status, "complete", "{result:#?}");
    assert_eq!(result.removed.len(), 3);
    assert!(!run.join("work").exists());
    assert!(!run.join("image").exists());
    assert!(!run.join("stages/stage-0-work").exists());
    for path in [
        run.join("unknown"),
        run.join("stages/unknown"),
        t.path().join("auth.json"),
        t.path().join(weird),
    ] {
        assert_eq!(fs::read(path).unwrap(), b"keep");
    }
    assert!(other.join("work").exists());
    assert_eq!(identity(&fs::metadata(t.path()).unwrap()), root);
    assert_eq!(
        identity(&fs::metadata(t.path().join("store.lock")).unwrap()),
        lock
    );
    assert_eq!(fs::read(&canary).unwrap(), b"external contents");
    let after = fs::metadata(canary).unwrap();
    assert_eq!(
        (before.ino(), before.mode(), before.len(), before.mtime()),
        (after.ino(), after.mode(), after.len(), after.mtime())
    );
    let record: Record =
        serde_json::from_slice(&fs::read(run.join("build-record.json")).unwrap()).unwrap();
    assert_eq!(record.version, 2);
    assert_eq!(record.removed.len(), 3);
    let p = cleanup_plan::inspect(t.path(), Selection::BuildsPrune, Limits::default(), || {
        false
    })
    .unwrap();
    assert!(p.consistent, "{p:#?}");
    assert_eq!(p.candidates.len(), 1);
    assert!(
        serde_json::to_string(&result)
            .unwrap()
            .contains("unix_bytes")
    );
}

#[test]
fn tag_removal_preserves_target_and_build_references_scope_selection() {
    let _s = SERIAL.lock().unwrap();
    let t = store();
    let run = build(t.path(), &["work", "image"]);
    fs::write(run.join("image/canary"), b"keep image").unwrap();
    tag(t.path(), &run.join("image"));
    let r = apply(t.path(), Selection::BuildsPrune);
    assert_eq!(r.status, "complete", "{r:#?}");
    assert_eq!(r.removed.len(), 1);
    assert!(run.join("image").exists());
    let r = apply(
        t.path(),
        Selection::ImageRemove(TagId::parse("example/test:latest").unwrap()),
    );
    assert_eq!(r.status, "complete", "{r:#?}");
    assert_eq!(r.removed.len(), 1);
    assert_eq!(fs::read(run.join("image/canary")).unwrap(), b"keep image");
    let r = apply(t.path(), Selection::BuildsPrune);
    assert_eq!(r.status, "complete", "{r:#?}");
    assert!(!run.join("image").exists());
}

#[test]
fn busy_guard_and_cache_noop() {
    let _s = SERIAL.lock().unwrap();
    let t = store();
    let run = build(t.path(), &["work"]);
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let r = apply(t.path(), Selection::BuildsPrune);
    assert_eq!(r.status, "store_busy");
    assert!(r.removed.is_empty());
    assert!(tx(t.path()).is_none());
    drop(lease);
    let r = apply(t.path(), Selection::CachePrune);
    assert_eq!(r.status, "no_candidates_protected");
    assert!(run.join("work").exists());
}

#[test]
fn nested_store_lease_boundary_is_never_removed() {
    let _s = SERIAL.lock().unwrap();
    let t = store();
    let run = build(t.path(), &["work"]);
    let nested = run.join("work/another-store");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let _lease = StoreLease::shared(&nested, &|| false).unwrap();
    let lock = identity(&fs::metadata(nested.join("store.lock")).unwrap());
    fs::write(nested.join("canary"), b"another store").unwrap();
    let r = apply(t.path(), Selection::BuildsPrune);
    assert_eq!(r.status, "failed", "{r:#?}");
    assert!(r.removed.is_empty());
    assert_eq!(
        identity(&fs::metadata(nested.join("store.lock")).unwrap()),
        lock
    );
    assert_eq!(fs::read(nested.join("canary")).unwrap(), b"another store");
}

#[test]
fn journal_rename_partial_unlink_and_complete_unlink_interruptions_recover() {
    let _s = SERIAL.lock().unwrap();
    for phase in 0..4 {
        let t = store();
        let run = build(t.path(), &["work", "image"]);
        fs::write(run.join("work/a"), b"a").unwrap();
        fs::write(run.join("work/z"), b"z").unwrap();
        // Select the first component explicitly by protecting image.
        tag(t.path(), &run.join("image"));
        let r = cleanup_apply::apply(t.path(), Selection::BuildsPrune, Limits::default(), || {
            let Some(tx) = tx(t.path()) else {
                return false;
            };
            let payload = tx.join("payload");
            let j: serde_json::Value =
                serde_json::from_slice(&fs::read(tx.join("journal.json")).unwrap()).unwrap();
            match phase {
                0 => true,
                1 => payload.exists(),
                2 => payload.exists() && !payload.join("a").exists() && payload.join("z").exists(),
                _ => j["deleting"] == true && !payload.exists(),
            }
        })
        .unwrap();
        assert_eq!(r.status, "failed", "phase {phase}: {r:#?}");
        assert!(r.failure.is_some());
        assert_eq!(r.removed.len(), usize::from(phase == 3));
        if phase == 3 {
            assert_eq!(r.removed[0].reason, "cleanup_finalization_pending");
        }
        assert!(tx(t.path()).is_some());
        // A dry run never restores or deletes trash.
        let before = fs::read(tx(t.path()).unwrap().join("journal.json")).unwrap();
        let _ = cleanup_plan::inspect(t.path(), Selection::BuildsPrune, Limits::default(), || {
            false
        })
        .unwrap();
        assert_eq!(
            before,
            fs::read(tx(t.path()).unwrap().join("journal.json")).unwrap()
        );
        let r = apply(t.path(), Selection::BuildsPrune);
        assert_eq!(r.status, "complete", "phase {phase}: {r:#?}");
        assert_eq!(r.recovered.len(), 1);
        assert!(!run.join("work").exists());
        assert!(run.join("image").exists());
        assert!(tx(t.path()).is_none());
        assert_eq!(
            apply(t.path(), Selection::BuildsPrune).status,
            "no_candidates_protected"
        );
    }
}

#[test]
fn retained_build_handle_cannot_overwrite_cleanup_tombstones() {
    let _s = SERIAL.lock().unwrap();
    let t = store();
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let mut b = BuildRecord::allocate(t.path(), &lease, None, None, vec![], false).unwrap();
    fs::create_dir(b.path.join("work")).unwrap();
    let work_identity = identity(&fs::metadata(b.path.join("work")).unwrap());
    b.update(&lease, |r| {
        r.phase = Phase::Failed;
        r.owned.push(Owned {
            components: vec![Component::try_from("work".to_owned()).unwrap()],
            identity: work_identity,
        });
    })
    .unwrap();
    drop(lease);
    assert_eq!(apply(t.path(), Selection::BuildsPrune).status, "complete");
    let before = fs::read(b.path.join("build-record.json")).unwrap();
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    assert!(b.update(&lease, |r| r.phase = Phase::Building).is_err());
    assert_eq!(fs::read(b.path.join("build-record.json")).unwrap(), before);
    assert!(!b.path.join("work").exists());
}

#[test]
fn tombstone_write_failure_counts_payload_and_preserves_recovery() {
    let _s = SERIAL.lock().unwrap();
    const CHILD: &str = "RPWELD_TEST_TOMBSTONE_FAILURE";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tombstone_write_failure_counts_payload_and_preserves_recovery",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let t = store();
    let run = build(t.path(), &["work"]);
    let before = fs::read(run.join("build-record.json")).unwrap();
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit), 0);
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
    }
    let injected = std::cell::Cell::new(false);
    let result = cleanup_apply::apply(t.path(), Selection::BuildsPrune, Limits::default(), || {
        if tx(t.path()).is_some_and(|tx| {
            let j: serde_json::Value =
                serde_json::from_slice(&fs::read(tx.join("journal.json")).unwrap()).unwrap();
            j["deleting"] == true && !tx.join("payload").exists()
        }) {
            let small = libc::rlimit {
                rlim_cur: 1,
                rlim_max: limit.rlim_max,
            };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &small) }, 0);
            injected.set(true);
        }
        false
    })
    .unwrap();
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) }, 0);
    assert!(injected.get());
    assert_eq!(result.status, "failed", "{result:#?}");
    assert_eq!(result.removed.len(), 1);
    assert_eq!(result.removed[0].reason, "cleanup_finalization_pending");
    assert!(result.failure.is_some());
    assert!(!run.join("work").exists());
    assert_eq!(fs::read(run.join("build-record.json")).unwrap(), before);
    assert!(tx(t.path()).is_some());
    let recovered = apply(t.path(), Selection::BuildsPrune);
    assert_eq!(recovered.status, "complete", "{recovered:#?}");
    assert_eq!(recovered.removed.len(), 1);
    assert_eq!(recovered.removed[0].reason, "completed_interrupted_removal");
    assert!(tx(t.path()).is_none());
}

#[test]
fn malformed_and_wrong_identity_journals_fail_closed_unknown_trash_is_preserved() {
    let _s = SERIAL.lock().unwrap();
    for wrong_identity in [false, true] {
        let t = store();
        let run = build(t.path(), &["work"]);
        let r = cleanup_apply::apply(t.path(), Selection::BuildsPrune, Limits::default(), || {
            tx(t.path()).is_some()
        })
        .unwrap();
        assert_eq!(r.status, "failed");
        let path = tx(t.path()).unwrap().join("journal.json");
        if wrong_identity {
            let mut j: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            j["object"]["inode"] = serde_json::json!(0);
            fs::write(&path, serde_json::to_vec(&j).unwrap()).unwrap();
        } else {
            fs::write(&path, b"{}").unwrap();
        }
        let r = apply(t.path(), Selection::BuildsPrune);
        assert_eq!(r.status, "failed");
        assert!(r.removed.is_empty());
        assert!(run.join("work").exists());
        assert!(path.exists());
    }
    let t = store();
    build(t.path(), &["work"]);
    let unknown = t.path().join(".cleanup-txn-unknown");
    fs::create_dir(&unknown).unwrap();
    fs::set_permissions(&unknown, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(unknown.join("keep"), b"unknown").unwrap();
    assert_eq!(apply(t.path(), Selection::BuildsPrune).status, "complete");
    assert_eq!(fs::read(unknown.join("keep")).unwrap(), b"unknown");
}

#[test]
fn malformed_ownership_and_incomplete_inventory_never_delete() {
    let _s = SERIAL.lock().unwrap();
    let t = store();
    let run = build(t.path(), &["work"]);
    let r = cleanup_apply::apply(
        t.path(),
        Selection::BuildsPrune,
        Limits {
            max_entries: 1,
            ..Limits::default()
        },
        || false,
    )
    .unwrap();
    assert_eq!(r.status, "failed");
    assert!(run.join("work").exists());
    fs::write(run.join("build-record.json"), b"{}").unwrap();
    let r = apply(t.path(), Selection::BuildsPrune);
    assert_eq!(r.status, "failed");
    assert!(r.removed.is_empty());
    assert!(tx(t.path()).is_none());
}

#[test]
fn exclusive_lease_is_continuous_and_replacement_at_tombstone_is_protected() {
    let _s = SERIAL.lock().unwrap();
    let t = store();
    let run = build(t.path(), &["work"]);
    fs::write(run.join("work/data"), b"owned").unwrap();
    let calls = std::cell::Cell::new(0);
    let r = cleanup_apply::apply(t.path(), Selection::BuildsPrune, Limits::default(), || {
        calls.set(calls.get() + 1);
        assert!(
            StoreLease::try_exclusive_existing(t.path())
                .unwrap()
                .is_none()
        );
        false
    })
    .unwrap();
    assert_eq!(r.status, "complete", "{r:#?}");
    assert!(calls.get() > 10);
    assert!(
        StoreLease::try_exclusive_existing(t.path())
            .unwrap()
            .is_some()
    );
    fs::create_dir(run.join("work")).unwrap();
    fs::write(run.join("work/replacement"), b"unknown").unwrap();
    let r = apply(t.path(), Selection::BuildsPrune);
    assert_eq!(r.status, "failed");
    assert_eq!(fs::read(run.join("work/replacement")).unwrap(), b"unknown");
}

#[test]
fn tag_transaction_recovers_without_touching_target_and_refuses_retag_overwrite() {
    let _s = SERIAL.lock().unwrap();
    for replace in [false, true] {
        let t = store();
        let external = tempfile::tempdir().unwrap();
        fs::write(external.path().join("canary"), b"keep").unwrap();
        tag(t.path(), external.path());
        let selection = Selection::ImageRemove(TagId::parse("example/test:latest").unwrap());
        let r = cleanup_apply::apply(t.path(), selection.clone(), Limits::default(), || {
            tx(t.path()).is_some_and(|p| p.join("payload").exists())
        })
        .unwrap();
        assert_eq!(r.status, "failed");
        if replace {
            tag(t.path(), external.path());
        }
        let r = apply(t.path(), selection);
        assert_eq!(
            r.status,
            if replace { "failed" } else { "complete" },
            "{r:#?}"
        );
        assert_eq!(fs::read(external.path().join("canary")).unwrap(), b"keep");
        if replace {
            assert!(tx(t.path()).unwrap().join("payload").exists());
        }
    }
}

#[test]
fn cli_apply_and_dry_run_use_disposable_store() {
    let _s = SERIAL.lock().unwrap();
    let t = store();
    let run = build(t.path(), &["work"]);
    for dry in [true, false] {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"));
        c.args(["builds", "prune", "--json"])
            .env("RPWELD_HOME", t.path());
        if dry {
            c.arg("--dry-run");
        }
        let out = c.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["dry_run"], dry);
        assert_eq!(run.join("work").exists(), dry);
    }
}

#[test]
#[ignore = "requires isolated user/mount namespace with CAP_SYS_ADMIN"]
fn same_device_nested_bind_mount_refuses_actual_apply() {
    let _s = SERIAL.lock().unwrap();
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
    let t = store();
    let run = build(t.path(), &["work"]);
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("canary"), b"external").unwrap();
    fs::create_dir(run.join("work/mount")).unwrap();
    let source = CString::new(external.path().as_os_str().as_bytes()).unwrap();
    let target = CString::new(run.join("work/mount").as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        0
    );
    struct Mount(CString);
    impl Drop for Mount {
        fn drop(&mut self) {
            unsafe {
                libc::umount2(self.0.as_ptr(), libc::MNT_DETACH);
            }
        }
    }
    let _mount = Mount(target);
    let r = apply(t.path(), Selection::BuildsPrune);
    assert_eq!(r.status, "failed", "{r:#?}");
    assert!(r.removed.is_empty());
    assert_eq!(
        fs::read(external.path().join("canary")).unwrap(),
        b"external"
    );
    assert!(run.join("work").exists());
}
