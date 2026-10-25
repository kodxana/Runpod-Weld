#![cfg(target_os = "linux")]
use rpweld::{
    build_record::{BuildRecord, Component, Owned, Phase, identity},
    cleanup_plan::{self, BuildId, Request, TagId},
    store_inventory::Limits,
    store_lease::StoreLease,
};
use std::{
    fs,
    os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, PermissionsExt, symlink},
    },
    path::Path,
};

// CLI forks can briefly inherit other tests' live leases before exec closes them.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn plan(store: &Path, request: Request) -> cleanup_plan::Plan {
    cleanup_plan::inspect(store, request, Limits::default(), || false).unwrap()
}
fn store() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    drop(StoreLease::shared(t.path(), &|| false).unwrap());
    t
}
fn build(store: &Path) -> std::path::PathBuf {
    let lease = StoreLease::shared(store, &|| false).unwrap();
    let mut record = BuildRecord::allocate(store, &lease, None, None, vec![], false).unwrap();
    let work = record.path.join("work");
    fs::create_dir(&work).unwrap();
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    record
        .update(&lease, |r| {
            r.phase = Phase::Failed;
            r.owned.push(Owned {
                components: vec![Component::try_from("work".to_owned()).unwrap()],
                identity: identity(&fs::metadata(&work).unwrap()),
            });
        })
        .unwrap();
    record.path
}
fn tag(store: &Path, target: &Path) {
    let lease = StoreLease::shared(store, &|| false).unwrap();
    rpweld::registry::save_tag(store, &lease, "docker.io/example/test:latest", target).unwrap();
}

#[test]
fn missing_and_legacy_store_are_unchanged() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let absent = t.path().join("missing");
    let p = plan(&absent, Request::CachePrune);
    assert_eq!(p.status, "missing");
    assert!(!absent.exists());
    fs::write(t.path().join("unknown"), b"canary").unwrap();
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.status, "legacy_unleased");
    assert!(p.candidates.is_empty());
    assert!(!t.path().join("store.lock").exists());
    assert_eq!(fs::read(t.path().join("unknown")).unwrap(), b"canary");
}

#[test]
fn busy_worker_duplicate_selects_nothing_without_scanning() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let worker = lease.duplicate_for_supervisor().unwrap();
    drop(lease);
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.status, "store_busy");
    assert!(p.candidates.is_empty() && p.inventory.is_none());
    drop(worker);
    assert_eq!(plan(t.path(), Request::BuildsPrune).status, "planned");
}

#[test]
fn validated_components_do_not_authorize_run_or_unknown_children() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    fs::write(run.join("unknown"), b"keep").unwrap();
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.candidates.len(), 1, "{p:#?}");
    assert_eq!(
        p.candidates[0].path,
        run.strip_prefix(t.path()).unwrap().join("work")
    );
    assert!(
        p.protected
            .iter()
            .any(|e| e.reason == "run_record_and_unlisted_children_protected")
    );
    assert_eq!(p.estimate.unique_logical_bytes, 0);
    assert_eq!(p.estimate.reclaim_upper_bytes, None);
    fs::write(run.join("work/unknown"), b"keep too").unwrap();
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.candidates.len(), 1, "{p:#?}");
    assert_eq!(p.estimate.unique_logical_bytes, 8);
    assert_eq!(p.estimate.selected_entries, 2);
    assert_eq!(fs::read(run.join("unknown")).unwrap(), b"keep");
}

#[test]
fn non_utf8_unknowns_and_shared_blobs_are_lossless_and_not_reclaimable() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    let weird = std::ffi::OsString::from_vec(b"unknown-\xff".to_vec());
    fs::write(t.path().join(&weird), b"secret").unwrap();
    fs::write(run.join("work/a"), b"shared bytes").unwrap();
    fs::hard_link(run.join("work/a"), run.join("work/b")).unwrap();
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.candidates.len(), 1, "{p:#?}");
    assert_eq!(p.estimate.reclaim_upper_bytes, None);
    assert_eq!(p.estimate.shared_inode_count, 1);
    assert_eq!(p.estimate.unique_logical_bytes, 12);
    assert_eq!(
        p.estimate.reclaimable_file_allocated_bytes,
        fs::metadata(run.join("work/a")).unwrap().blocks() * 512
    );
    assert_eq!(p.inventory.as_ref().unwrap().usage.shared_hardlink_paths, 1);
    let v = serde_json::to_value(&p).unwrap();
    assert!(
        v["protected"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"]["unix_bytes"] == serde_json::json!(b"unknown-\xff".as_slice()))
    );
    assert!(!v.to_string().contains("secret"));
}

#[test]
fn tag_alias_subtree_external_and_retag_never_select_build_or_target() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("canary"), b"keep").unwrap();
    let alias = external.path().join("alias");
    symlink(run.join("work"), &alias).unwrap();
    for target in [run.join("work"), alias, external.path().to_owned()] {
        tag(t.path(), &target);
        assert!(plan(t.path(), Request::BuildsPrune).candidates.is_empty());
        let p = plan(
            t.path(),
            Request::ImageRemove(TagId::parse("example/test:latest").unwrap()),
        );
        assert_eq!(p.candidates.len(), 1, "{p:#?}");
        assert_eq!(p.candidates[0].reason, "tag_record_only_target_unchanged");
        assert!(p.candidates[0].path.to_str().unwrap().starts_with("tag-"));
        let meta = fs::metadata(t.path().join(&p.candidates[0].path)).unwrap();
        assert_eq!(p.estimate.unique_logical_bytes, meta.len());
        assert_eq!(p.estimate.reclaim_upper_bytes, Some(meta.blocks() * 512));
        assert_eq!(p.estimate.reclaim_lower_bytes, 0);
    }
    assert_eq!(fs::read(external.path().join("canary")).unwrap(), b"keep");
    assert!(run.join("work").exists());
}

#[test]
fn malformed_records_and_cache_names_do_not_prove_ownership() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    fs::write(run.join("build-record.json"), b"{}").unwrap();
    fs::create_dir_all(t.path().join("cache-v1").join("a".repeat(64))).unwrap();
    fs::create_dir(t.path().join("build-legacy")).unwrap();
    let p = plan(t.path(), Request::BuildsPrune);
    assert!(p.candidates.is_empty());
    assert!(!p.consistent);
    let p = plan(t.path(), Request::CachePrune);
    assert!(p.candidates.is_empty());
    assert!(
        p.protected
            .iter()
            .any(|e| e.reason.contains("provenance_unavailable"))
    );
}

#[test]
fn explicit_paths_inside_an_owned_component_are_protected() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let _other = BuildRecord::allocate(
        t.path(),
        &lease,
        Some(&run.join("work")),
        None,
        vec![],
        false,
    )
    .unwrap();
    drop(lease);
    let p = plan(t.path(), Request::BuildsPrune);
    assert!(p.candidates.is_empty());
    assert!(
        p.protected
            .iter()
            .any(|e| e.reason == "reference_intersects_owned_component")
    );
    assert!(run.join("work").exists());
}

#[test]
fn cli_json_missing_store_and_busy_store_are_usable() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let missing = t.path().join("missing");
    for args in [
        vec!["cache", "prune", "--dry-run", "--json"],
        vec!["builds", "prune", "--dry-run", "--json"],
        vec!["builds", "rm", "build-a", "--dry-run", "--json"],
        vec!["image", "rm", "example/test:latest", "--dry-run", "--json"],
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .args(args)
            .env("RPWELD_HOME", &missing)
            .output()
            .unwrap();
        assert!(out.status.success());
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(value["status"], "missing");
        assert_eq!(value["candidates"], serde_json::json!([]));
        assert!(!missing.exists());
    }
    let _lease = StoreLease::shared(t.path(), &|| false).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
        .args(["builds", "prune", "--dry-run", "--json"])
        .env("RPWELD_HOME", t.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["status"], "store_busy");
    assert_eq!(value["candidates"], serde_json::json!([]));
}

#[test]
fn cli_requires_dry_run_rejects_paths_force_and_duplicate_flags() {
    let _serial = TEST_LOCK.lock().unwrap();
    for args in [
        vec!["cache", "prune"],
        vec!["builds", "prune"],
        vec!["builds", "rm", "build-a"],
        vec!["image", "rm", "test"],
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .args(args)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("mutation is not implemented"));
    }
    for value in ["../build-a", "build-a/x", "build-a\\x", "build-", "x"] {
        assert!(BuildId::parse(value).is_err());
    }
    for args in [
        vec!["cache", "prune", "--dry-run", "--force"],
        vec!["cache", "prune", "--dry-run", "--dry-run"],
    ] {
        assert!(
            !std::process::Command::new(env!("CARGO_BIN_EXE_rpweld"))
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
}

#[test]
fn tag_protects_only_intersecting_component() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let first = build(t.path());
    let second = build(t.path());
    fs::write(first.join("work/data"), b"first").unwrap();
    fs::write(second.join("work/data"), b"second").unwrap();
    tag(t.path(), &first.join("work"));
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.candidates.len(), 1, "{p:#?}");
    assert_eq!(
        p.candidates[0].path,
        second.strip_prefix(t.path()).unwrap().join("work")
    );
    assert_eq!(p.estimate.unique_logical_bytes, 6);
}

#[test]
fn external_hardlink_and_symlink_are_not_reclaim_or_target_reads() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    let outside = tempfile::tempdir().unwrap();
    let canary = outside.path().join("canary");
    fs::write(&canary, b"SECRET_CANARY").unwrap();
    fs::hard_link(&canary, run.join("work/shared")).unwrap();
    symlink(outside.path(), run.join("work/link")).unwrap();
    let before = fs::metadata(&canary).unwrap();
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.candidates.len(), 1, "{p:#?}");
    assert_eq!(p.estimate.selected_entries, 3);
    assert_eq!(p.estimate.unique_logical_bytes, 13);
    assert_eq!(p.estimate.shared_inode_count, 1);
    assert_eq!(p.estimate.reclaimable_file_allocated_bytes, 0);
    assert_eq!(p.estimate.reclaim_lower_bytes, 0);
    assert!(!serde_json::to_string(&p).unwrap().contains("SECRET_CANARY"));
    let after = fs::metadata(&canary).unwrap();
    assert_eq!(
        (
            before.ino(),
            before.nlink(),
            before.mtime(),
            before.ctime(),
            before.atime()
        ),
        (
            after.ino(),
            after.nlink(),
            after.mtime(),
            after.ctime(),
            after.atime()
        )
    );
    assert_eq!(fs::read(&canary).unwrap(), b"SECRET_CANARY");
}

#[test]
fn partial_and_cancelled_plans_select_nothing_and_estimate_unknown() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    fs::create_dir_all(run.join("work/deep/child")).unwrap();
    fs::write(run.join("work/deep/child/data"), b"payload").unwrap();
    for limits in [
        Limits {
            max_entries: 2,
            ..Limits::default()
        },
        Limits {
            max_depth: 2,
            ..Limits::default()
        },
        Limits {
            max_metadata_bytes: 1,
            ..Limits::default()
        },
    ] {
        let p = cleanup_plan::inspect(t.path(), Request::BuildsPrune, limits, || false).unwrap();
        assert_eq!(p.status, "partial");
        assert!(!p.consistent);
        assert!(p.candidates.is_empty());
        assert_eq!(p.estimate.reclaim_upper_bytes, None);
    }
    let p =
        cleanup_plan::inspect(t.path(), Request::BuildsPrune, Limits::default(), || true).unwrap();
    assert_eq!(p.status, "partial");
    assert!(p.candidates.is_empty());
    assert_eq!(p.estimate.reclaim_upper_bytes, None);
}

#[test]
#[ignore = "run in an isolated user/mount namespace with CAP_SYS_ADMIN"]
fn same_device_bind_mount_is_not_traversed() {
    let _serial = TEST_LOCK.lock().unwrap();
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    // Never mount into the invoking process's namespace, even when root.
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
    let owned = build(t.path());
    let outside = store();
    fs::write(outside.path().join("canary"), b"secret").unwrap();
    fs::create_dir_all(owned.join("work/mounted")).unwrap();
    let source = CString::new(outside.path().as_os_str().as_bytes()).unwrap();
    let target = CString::new(owned.join("work/mounted").as_os_str().as_bytes()).unwrap();
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
    assert_eq!(
        fs::metadata(outside.path()).unwrap().dev(),
        fs::metadata(t.path()).unwrap().dev()
    );
    let p = plan(t.path(), Request::BuildsPrune);
    assert!(p.candidates.is_empty());
    assert!(!p.consistent);
    assert_eq!(p.estimate.reclaim_upper_bytes, None);
    assert_eq!(fs::read(outside.path().join("canary")).unwrap(), b"secret");
}

#[test]
fn malformed_tag_blocks_all_components_without_content_leaks() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    fs::write(run.join("work/payload"), b"PRIVATE_PAYLOAD").unwrap();
    tag(t.path(), &run.join("work"));
    let path = fs::read_dir(t.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("tag-"))
        .unwrap();
    fs::write(path, b"{PRIVATE_BROKEN_RECORD").unwrap();
    let p = plan(t.path(), Request::BuildsPrune);
    assert!(p.candidates.is_empty());
    assert!(p.protected.iter().any(
        |e| e.reason == "reference_alias_scope_uncertain" || e.reason == "incomplete_inventory"
    ));
    assert!(!serde_json::to_string(&p).unwrap().contains("PRIVATE_"));
}

#[test]
fn dry_run_preserves_tree_content_identity_and_write_metadata() {
    let _serial = TEST_LOCK.lock().unwrap();
    type SnapshotEntry = (std::path::PathBuf, u64, u64, u32, i64, i64, Vec<u8>);
    fn snapshot(path: &Path) -> Vec<SnapshotEntry> {
        fn walk(root: &Path, path: &Path, out: &mut Vec<SnapshotEntry>) {
            let m = fs::symlink_metadata(path).unwrap();
            let bytes = if m.is_file() {
                fs::read(path).unwrap()
            } else {
                vec![]
            };
            out.push((
                path.strip_prefix(root).unwrap().into(),
                m.ino(),
                m.nlink(),
                m.mode(),
                m.mtime_nsec(),
                m.ctime_nsec(),
                bytes,
            ));
            if m.is_dir() {
                for e in fs::read_dir(path).unwrap() {
                    walk(root, &e.unwrap().path(), out);
                }
            }
        }
        let mut out = vec![];
        walk(path, path, &mut out);
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
    let t = store();
    let run = build(t.path());
    fs::write(run.join("work/payload"), b"retained").unwrap();
    fs::write(run.join("unknown"), b"retained sibling").unwrap();
    let before = snapshot(t.path());
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.candidates.len(), 1);
    assert_eq!(before, snapshot(t.path()));
}

#[test]
fn unrelated_external_regular_file_does_not_block_owned_component() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    fs::write(run.join("work/data"), b"eligible").unwrap();
    let external = tempfile::NamedTempFile::new().unwrap();
    let lease = StoreLease::shared(t.path(), &|| false).unwrap();
    BuildRecord::allocate(t.path(), &lease, Some(external.path()), None, vec![], false).unwrap();
    drop(lease);
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.candidates.len(), 1);
    assert_eq!(p.estimate.unique_logical_bytes, 8);
}

#[test]
fn cancellation_during_component_scan_discards_prior_selections() {
    let _serial = TEST_LOCK.lock().unwrap();
    use std::cell::Cell;
    let t = store();
    for _ in 0..2 {
        let run = build(t.path());
        for n in 0..4 {
            fs::write(run.join(format!("work/file-{n}")), b"data").unwrap();
        }
    }
    let mut component_interrupted = false;
    for stop in 1..200 {
        let calls = Cell::new(0);
        let p = cleanup_plan::inspect(t.path(), Request::BuildsPrune, Limits::default(), || {
            calls.set(calls.get() + 1);
            calls.get() >= stop
        })
        .unwrap();
        if p.status == "planned" {
            break;
        }
        assert!(p.candidates.is_empty());
        assert_eq!(p.estimate.unique_logical_bytes, 0);
        assert_eq!(p.estimate.reclaim_upper_bytes, None);
        component_interrupted |= p
            .protected
            .iter()
            .any(|e| e.reason == "incomplete_component_scan_selection_unknown");
    }
    assert!(component_interrupted);
}

#[test]
fn diagnostic_cap_boundary_is_not_itself_truncation() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    for n in 0..1025 {
        symlink("missing", run.join(format!("work/link-{n:04}"))).unwrap();
        if n >= 1022 {
            let p = plan(t.path(), Request::BuildsPrune);
            let inventory = p.inventory.as_ref().unwrap();
            assert!(inventory.partial);
            assert!(inventory.scan_complete);
            assert_eq!(inventory.issues.len(), (n + 1).min(1024));
            assert_eq!(inventory.issues_truncated, n == 1024);
            assert_eq!(p.consistent, n < 1024);
            assert_eq!(p.candidates.len(), usize::from(n < 1024));
            if n == 1024 {
                assert_eq!(p.estimate.reclaim_upper_bytes, None);
            }
        }
    }
}

#[test]
fn capped_payload_diagnostics_cannot_hide_budget_failure_and_protecting_tag() {
    let _serial = TEST_LOCK.lock().unwrap();
    let t = store();
    let run = build(t.path());
    for n in 0..1024 {
        symlink("missing", run.join(format!("work/link-{n:04}"))).unwrap();
    }
    // This area sorts after the build and before the protecting tag. Its names
    // exhaust the inventory budget after all 1024 payload skips were recorded.
    let cache = t.path().join("cache-v1");
    fs::create_dir(&cache).unwrap();
    for n in 0..1024 {
        fs::write(cache.join(format!("{n:04}{}", "x".repeat(196))), b"").unwrap();
    }
    tag(t.path(), &run.join("work"));
    for limits in [
        Limits {
            max_metadata_bytes: 250_000,
            ..Limits::default()
        },
        Limits {
            max_entries: 1500,
            ..Limits::default()
        },
    ] {
        let p = cleanup_plan::inspect(t.path(), Request::BuildsPrune, limits, || false).unwrap();
        let inventory = p.inventory.as_ref().unwrap();
        assert_eq!(inventory.issues.len(), 1024);
        assert!(
            inventory
                .issues
                .iter()
                .all(|i| i.code == "symlink_or_special_file_skipped")
        );
        assert!(inventory.tags.is_empty());
        assert!(!inventory.scan_complete);
        assert!(inventory.issues_truncated);
        assert!(!p.consistent);
        assert!(p.candidates.is_empty());
        assert_eq!(p.estimate.reclaim_upper_bytes, None);
    }
    // With sufficient budget the tag is observed and protects the component.
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.inventory.as_ref().unwrap().tags.len(), 1);
    assert!(p.candidates.is_empty());
}
