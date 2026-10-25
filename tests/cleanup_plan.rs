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
    let t = store();
    let run = build(t.path());
    fs::write(run.join("unknown"), b"keep").unwrap();
    let p = plan(t.path(), Request::BuildsPrune);
    assert_eq!(p.candidates.len(), 1);
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
    assert!(p.candidates.is_empty());
    assert!(
        p.protected
            .iter()
            .any(|e| e.reason == "populated_component_child_ownership_not_proven")
    );
    assert_eq!(fs::read(run.join("unknown")).unwrap(), b"keep");
}

#[test]
fn non_utf8_unknowns_and_shared_blobs_are_lossless_and_not_reclaimable() {
    let t = store();
    let run = build(t.path());
    let weird = std::ffi::OsString::from_vec(b"unknown-\xff".to_vec());
    fs::write(t.path().join(&weird), b"secret").unwrap();
    fs::write(run.join("work/a"), b"shared bytes").unwrap();
    fs::hard_link(run.join("work/a"), run.join("work/b")).unwrap();
    let p = plan(t.path(), Request::BuildsPrune);
    assert!(p.candidates.is_empty());
    assert_eq!(p.estimate.reclaim_upper_bytes, Some(0));
    assert_eq!(p.estimate.shared_inode_count, 0); // No selected inodes.
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
        assert_eq!(p.candidates.len(), 1);
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
            .any(|e| e.reason == "explicit_external_path_or_alias_may_reference_build")
    );
    assert!(run.join("work").exists());
}

#[test]
fn cli_json_missing_store_and_busy_store_are_usable() {
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
