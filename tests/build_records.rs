#![cfg(target_os = "linux")]
use rpweld::{
    build_record::{BuildRecord, Component, FILE, Phase, PushResult, Record},
    store_inventory::{self, Limits, Ownership},
    store_lease::StoreLease,
};
use std::{
    fs,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture {
    _temp: tempfile::TempDir,
    store: PathBuf,
    context: PathBuf,
}
impl Fixture {
    fn new(source: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let context = temp.path().join("context");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&context).unwrap();
        fs::write(context.join("Dockerfile"), source).unwrap();
        Self {
            _temp: temp,
            store,
            context,
        }
    }
    fn build(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .env("HOME", self._temp.path())
            .env("RPWELD_HOME", &self.store)
            .arg("build")
            .args(args)
            .arg(&self.context)
            .output()
            .unwrap()
    }
    fn record(&self) -> (PathBuf, Record) {
        let run = fs::read_dir(&self.store)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.file_name().unwrap().as_bytes().starts_with(b"build-"))
            .unwrap();
        let record = serde_json::from_slice(&fs::read(run.join(FILE)).unwrap()).unwrap();
        (run, record)
    }
    fn inventory(&self) -> store_inventory::Inventory {
        store_inventory::inspect(&self.store, Limits::default(), || false).unwrap()
    }
}
#[test]
fn normal_build_records_identity_manifest_and_owned_stages() {
    let f = Fixture::new("FROM scratch AS first\nWORKDIR /one\nFROM first\nWORKDIR /two\n");
    let result = f.build(&["--no-cache"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let (run, record) = f.record();
    assert_eq!(record.phase, Phase::Complete);
    assert!(record.manifest.is_some());
    let paths: Vec<PathBuf> = record
        .owned
        .iter()
        .map(|o| o.components.iter().map(Component::as_str).collect())
        .collect();
    for p in [
        "work",
        "image",
        "stages",
        "stages/stage-0-work",
        "stages/stage-0-image",
    ] {
        assert!(paths.contains(&PathBuf::from(p)), "{paths:?}");
    }
    assert_eq!(
        fs::metadata(run.join(FILE)).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let i = f.inventory();
    assert_eq!(i.builds[0].ownership, Ownership::Managed);
    assert!(i.builds[0].protected);
    assert!(
        i.protected_entries
            .iter()
            .any(|e| e.path == Path::new("store.lock") && e.protected)
    );
}
#[test]
fn export_failure_retains_owned_output_and_work() {
    let f = Fixture::new("FROM scratch\n");
    let result = f.build(&["--no-cache", "--max-layer-bytes", "1"]);
    assert!(!result.status.success());
    let (run, r) = f.record();
    assert_eq!(r.phase, Phase::Failed);
    assert!(r.manifest.is_none());
    for p in ["work", "image"] {
        assert!(run.join(p).is_dir());
        assert!(
            r.owned
                .iter()
                .any(|o| o.components.len() == 1 && o.components[0].as_str() == p)
        );
    }
    assert_eq!(f.inventory().builds[0].ownership, Ownership::Managed);
}
#[test]
fn build_failure_and_push_failure_have_distinct_states() {
    let f = Fixture::new("FROM scratch\nRUN false\n");
    assert!(!f.build(&["--no-cache"]).status.success());
    assert_eq!(f.record().1.phase, Phase::Failed);
    let f = Fixture::new("FROM scratch\n");
    // Closed loopback endpoint; no credentials or cloud service involved.
    assert!(
        !f.build(&[
            "--no-cache",
            "-t",
            "127.0.0.1:1/test/image:latest",
            "--push"
        ])
        .status
        .success()
    );
    let (run, r) = f.record();
    assert_eq!(r.phase, Phase::ImageReady);
    assert_eq!(r.push, PushResult::Failed);
    assert!(r.manifest.is_some());
    assert!(run.join("image/index.json").is_file());
    assert_eq!(f.inventory().builds[0].ownership, Ownership::Managed);
}
#[test]
fn explicit_paths_are_external_even_inside_store_and_canaries_survive() {
    for inside in [false, true] {
        let f = Fixture::new("FROM scratch AS first\nWORKDIR /one\nFROM first\n");
        let parent = if inside { &f.store } else { f._temp.path() };
        let work = parent.join("user-work");
        let output = parent.join("user-image");
        fs::write(parent.join("canary"), b"\x00\xffunchanged").unwrap();
        let result = f.build(&[
            "--no-cache",
            "-t",
            "example/test:latest",
            "--work-dir",
            work.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let (run, r) = f.record();
        assert_eq!(r.external.len(), 2);
        assert!(r.owned.iter().all(|o| o.components[0].as_str() == "stages"));
        assert!(run.join("stages").is_dir());
        assert_eq!(
            fs::read(parent.join("canary")).unwrap(),
            b"\x00\xffunchanged"
        );
        assert_eq!(f.inventory().builds[0].ownership, Ownership::Managed);
    }
}
#[test]
fn legacy_malformed_traversal_and_identity_mismatch_remain_protected() {
    let f = Fixture::new("FROM scratch\n");
    assert!(f.build(&["--no-cache"]).status.success());
    let (run, r) = f.record();
    let original = serde_json::to_value(&r).unwrap();
    for case in [
        "malformed",
        "traversal",
        "identity",
        "child_identity",
        "phase",
        "role",
        "duplicate",
        "symlink",
        "missing",
    ] {
        let mut value = original.clone();
        match case {
            "traversal" => value["owned"][0]["components"][0] = "..".into(),
            "identity" => value["run"]["inode"] = 0.into(),
            "child_identity" => value["owned"][0]["identity"]["inode"] = 0.into(),
            "phase" => value["phase"] = "preparing".into(),
            "role" => value["external"] = serde_json::json!([{"role":"other", "unix_bytes":[47]}]),
            "duplicate" => {
                let o = value["owned"][0].clone();
                value["owned"].as_array_mut().unwrap().push(o);
            }
            _ => (),
        }
        let file = run.join(FILE);
        let _ = fs::remove_file(&file);
        if case == "symlink" {
            symlink("/dev/null", &file).unwrap();
        } else if case != "missing" {
            fs::write(
                &file,
                if case == "malformed" {
                    b"{".to_vec()
                } else {
                    serde_json::to_vec(&value).unwrap()
                },
            )
            .unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let i = f.inventory();
        assert_eq!(i.builds[0].ownership, Ownership::Unknown, "{case}");
        assert!(i.builds[0].protected);
        assert!(i.builds[0].build_record.is_none());
    }
    fs::create_dir(f.store.join("build-legacy")).unwrap();
    assert!(
        f.inventory()
            .builds
            .iter()
            .all(|b| b.protected && b.ownership == Ownership::Unknown)
    );
}
#[test]
fn native_paths_atomic_failed_update_and_lease_identity() {
    let f = Fixture::new("FROM scratch\n");
    let lease = StoreLease::shared(&f.store, &|| false).unwrap();
    let external = PathBuf::from(std::ffi::OsString::from_vec(b"/unread/\xff".to_vec()));
    let mut r =
        BuildRecord::allocate(&f.store, &lease, Some(&external), None, vec![], false).unwrap();
    let bytes = fs::read(r.path.join(FILE)).unwrap();
    let decoded: Record = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        decoded.external[0].unix_bytes,
        external.as_os_str().as_bytes()
    );
    assert!(
        r.update(&lease, |r| r.references = vec!["a".repeat(100_000)])
            .is_err()
    );
    assert_eq!(fs::read(r.path.join(FILE)).unwrap(), bytes);
    assert_eq!(r.record.phase, Phase::Preparing);
    let other = tempfile::tempdir().unwrap();
    let other = StoreLease::shared(other.path(), &|| false).unwrap();
    assert!(r.update(&other, |r| r.phase = Phase::Building).is_err());
    assert_eq!(fs::read(r.path.join(FILE)).unwrap(), bytes);
    // Force a real rename failure; the existing record at its retained name is unchanged.
    fs::rename(r.path.join(FILE), r.path.join("original.json")).unwrap();
    fs::create_dir(r.path.join(FILE)).unwrap();
    assert!(r.update(&lease, |r| r.phase = Phase::Building).is_err());
    assert_eq!(fs::read(r.path.join("original.json")).unwrap(), bytes);
}

#[test]
fn preparation_and_unrecorded_children_are_not_blanket_ownership() {
    let f = Fixture::new("FROM scratch\n");
    let lease = StoreLease::shared(&f.store, &|| false).unwrap();
    let r = BuildRecord::allocate(&f.store, &lease, None, None, vec![], false).unwrap();
    fs::create_dir(r.path.join("unrecorded")).unwrap();
    fs::write(r.path.join("unrecorded/canary"), b"retain").unwrap();
    let i = f.inventory();
    let record = i.builds[0].build_record.as_ref().unwrap();
    assert_eq!(record.phase, Phase::Preparing);
    assert!(record.owned.is_empty());
    assert!(i.builds[0].protected);
    assert_eq!(
        fs::read(r.path.join("unrecorded/canary")).unwrap(),
        b"retain"
    );
}

#[test]
fn record_limits_permissions_links_and_child_replacement_fail_closed() {
    let f = Fixture::new("FROM scratch\n");
    assert!(f.build(&["--no-cache"]).status.success());
    let (run, _) = f.record();
    let file = run.join(FILE);
    let original = fs::read(&file).unwrap();
    for case in ["oversized", "public", "hardlink", "child_symlink"] {
        match case {
            "oversized" => fs::write(&file, vec![b' '; 65537]).unwrap(),
            "public" => fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap(),
            "hardlink" => fs::hard_link(&file, run.join("alias")).unwrap(),
            "child_symlink" => {
                fs::rename(run.join("work"), run.join("kept-work")).unwrap();
                symlink("kept-work", run.join("work")).unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            f.inventory().builds[0].ownership,
            Ownership::Unknown,
            "{case}"
        );
        if case == "hardlink" {
            fs::remove_file(run.join("alias")).unwrap();
        }
        fs::write(&file, &original).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn failed_file_write_preserves_previous_atomic_record() {
    const CHILD: &str = "RPWELD_RECORD_WRITE_FAILURE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "failed_file_write_preserves_previous_atomic_record",
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
    let f = Fixture::new("FROM scratch\n");
    let lease = StoreLease::shared(&f.store, &|| false).unwrap();
    let mut r = BuildRecord::allocate(&f.store, &lease, None, None, vec![], false).unwrap();
    let before = fs::read(r.path.join(FILE)).unwrap();
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        let limit = libc::rlimit {
            rlim_cur: 8,
            rlim_max: 8,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
    }
    assert!(r.update(&lease, |r| r.phase = Phase::Building).is_err());
    assert_eq!(fs::read(r.path.join(FILE)).unwrap(), before);
    assert_eq!(r.record.phase, Phase::Preparing);
}

#[test]
fn pull_preparation_failure_is_recorded_before_building() {
    let f = Fixture::new("FROM 127.0.0.1:1/test/base:latest\n");
    assert!(!f.build(&[]).status.success());
    let (_, r) = f.record();
    assert_eq!(r.phase, Phase::Failed);
    assert!(r.owned.is_empty());
    assert!(r.manifest.is_none());
}

#[test]
fn inventory_owned_validation_respects_depth_and_entry_limits() {
    let f = Fixture::new("FROM scratch AS a\nWORKDIR /a\nFROM a\n");
    assert!(f.build(&["--no-cache"]).status.success());
    for limits in [
        Limits {
            max_depth: 2,
            ..Limits::default()
        },
        Limits {
            max_entries: 2,
            ..Limits::default()
        },
    ] {
        let i = store_inventory::inspect(&f.store, limits, || false).unwrap();
        assert!(i.partial);
        assert!(
            i.builds
                .iter()
                .all(|b| b.protected && b.build_record.is_none())
        );
    }
}
