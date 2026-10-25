#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
struct Fixture {
    _temp: tempfile::TempDir,
    context: PathBuf,
    home: PathBuf,
    number: usize,
}
impl Fixture {
    fn new(source: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let context = temp.path().join("context");
        let home = temp.path().join("home");
        fs::create_dir(&context).unwrap();
        fs::create_dir(&home).unwrap();
        fs::write(context.join("Dockerfile"), source).unwrap();
        fs::write(context.join("payload"), "original").unwrap();
        Self {
            _temp: temp,
            context,
            home,
            number: 0,
        }
    }
    fn build(&mut self, extra: &[&str]) -> (Output, PathBuf, PathBuf) {
        self.number += 1;
        let output = self.home.join(format!("output-{}", self.number));
        let work = self.home.join(format!("work-{}", self.number));
        let r = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .env("HOME", &self.home)
            .env("RPWELD_HOME", self.home.join("store"))
            .args([
                "build",
                "-t",
                "test/multistage:latest",
                "--platform",
                "linux/amd64",
                "--output",
            ])
            .arg(&output)
            .arg("--work-dir")
            .arg(&work)
            .args(extra)
            .arg(&self.context)
            .output()
            .unwrap();
        (r, output, work.join("rootfs"))
    }
}
fn success(r: &Output) {
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
}
fn cached(r: &Output) -> usize {
    String::from_utf8_lossy(&r.stderr)
        .matches("CACHED (")
        .count()
}
fn config(layout: &Path) -> serde_json::Value {
    let read =
        |path| serde_json::from_slice::<serde_json::Value>(&fs::read(path).unwrap()).unwrap();
    let index = read(layout.join("index.json"));
    let blob = |digest: &str| layout.join("blobs").join(digest.replace(':', "/"));
    let manifest = read(blob(index["manifests"][0]["digest"].as_str().unwrap()));
    read(blob(manifest["config"]["digest"].as_str().unwrap()))
}

fn not_cancelled() -> bool {
    false
}

fn cache_external(f: &Fixture, layout: &Path, reference: &str, refresh: bool) -> PathBuf {
    let store = f.home.join("store");
    fs::create_dir_all(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let lease = rpweld::store_lease::StoreLease::shared(&store, &not_cancelled).unwrap();
    rpweld::registry::cached_base(
        &store,
        &lease,
        reference,
        refresh,
        rpweld::image::Limits {
            max_metadata_bytes: 1048576,
            max_total_metadata_bytes: 4194304,
            max_descriptors: 100,
            max_layer_bytes: 10485760,
            max_total_layer_bytes: 10485760,
        },
        not_cancelled,
        |_, destination| {
            fs::create_dir_all(destination.join("blobs/sha256")).unwrap();
            for file in ["index.json", "oci-layout"] {
                fs::copy(layout.join(file), destination.join(file)).unwrap();
            }
            for file in fs::read_dir(layout.join("blobs/sha256")).unwrap() {
                let file = file.unwrap();
                fs::copy(
                    file.path(),
                    destination.join("blobs/sha256").join(file.file_name()),
                )
                .unwrap();
            }
            Ok(())
        },
    )
    .unwrap()
}

#[test]
fn external_copy_offline_refresh_config_ownership_and_target_selection() {
    let mut source = Fixture::new(
        "FROM scratch\nCOPY --chown=123:456 payload /payload\nENV SOURCE=secret\nUSER 234:567\nWORKDIR /elsewhere\nLABEL source=hidden\nCMD [\"source-command\"]\n",
    );
    let (r, original, _) = source.build(&[]);
    success(&r);
    let mut f = Fixture::new(
        "FROM scratch AS unused\nCOPY --from=unreachable.invalid/absent /x /x\nFROM scratch AS final\nUSER 42:43\nCOPY --from=fixture.invalid/source:v1 /payload /result\nCOPY --from=fixture.invalid/source:v1 --chmod=0600 --chown=12:34 /payload /override\n",
    );
    cache_external(&f, &original, "fixture.invalid/source:v1", false);
    let (r, out, root) = f.build(&[]);
    success(&r);
    assert_eq!(fs::read(root.join("result")).unwrap(), b"original");
    assert_eq!(fs::metadata(root.join("result")).unwrap().uid(), 123);
    let meta = fs::metadata(root.join("override")).unwrap();
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o777),
        (12, 34, 0o600)
    );
    let cfg = config(&out);
    assert_eq!(cfg["config"]["User"], "42:43");
    assert_eq!(cfg["config"]["Env"], serde_json::json!([]));
    assert_ne!(cfg["config"]["WorkingDir"], "/elsewhere");
    assert!(cfg["config"]["Labels"]["source"].is_null());
    assert_ne!(cfg["config"]["Cmd"], serde_json::json!(["source-command"]));
    let (r, _, _) = f.build(&[]);
    success(&r);
    assert_eq!(cached(&r), 1);

    for flag in ["--max-rootfs-bytes", "--max-layer-bytes"] {
        let (r, out, _) = f.build(&[flag, "1"]);
        assert!(!r.status.success());
        assert!(!out.exists());
    }

    fs::write(source.context.join("payload"), "refreshed").unwrap();
    let (r, updated, _) = source.build(&[]);
    success(&r);
    cache_external(&f, &updated, "fixture.invalid/source:v1", true);
    let (r, _, root) = f.build(&[]);
    success(&r);
    assert_eq!(cached(&r), 0);
    assert_eq!(fs::read(root.join("result")).unwrap(), b"refreshed");
    let (r, _, root) = f.build(&["--no-cache"]);
    success(&r);
    assert_eq!(fs::read(root.join("result")).unwrap(), b"refreshed");

    fs::write(f.context.join("Dockerfile"), "FROM scratch AS chosen\nCOPY payload /ok\nFROM scratch\nCOPY --from=unreachable.invalid/missing /x /x\n").unwrap();
    let (r, _, root) = f.build(&["--target", "chosen"]);
    success(&r);
    assert!(root.join("ok").exists());
}

#[test]
fn external_copy_local_binding_precedence_and_safe_sources() {
    let mut source = Fixture::new("FROM scratch\nCOPY payload /payload\n");
    let (r, image, _) = source.build(&[]);
    success(&r);
    let binding = format!("source={}", image.display());
    let mut f = Fixture::new(
        "FROM scratch AS source\nCOPY payload /stage\nFROM scratch\nCOPY --from=source /stage /result\n",
    );
    let (r, _, _) = f.build(&["--base", &binding]);
    success(&r);
    fs::write(
        f.context.join("Dockerfile"),
        "FROM scratch\nCOPY --from=source /payload /result\n",
    )
    .unwrap();
    let (r, _, root) = f.build(&["--base", &binding]);
    success(&r);
    assert_eq!(fs::read(root.join("result")).unwrap(), b"original");
    let relocated_blobs = source.home.join("relocated-blobs");
    let blobs = image.join("blobs/sha256");
    fs::rename(&blobs, &relocated_blobs).unwrap();
    symlink(&relocated_blobs, &blobs).unwrap();
    let (r, out, _) = f.build(&["--base", &binding]);
    assert!(!r.status.success());
    assert!(!out.exists());
    fs::remove_file(&blobs).unwrap();
    fs::rename(&relocated_blobs, &blobs).unwrap();
    for from in ["$IMAGE", "99", "https://invalid/image"] {
        fs::write(
            f.context.join("Dockerfile"),
            format!("FROM scratch\nCOPY --from={from} /payload /result\n"),
        )
        .unwrap();
        let (r, out, _) = f.build(&[]);
        assert!(!r.status.success());
        assert!(!out.exists());
    }
    fs::write(
        f.context.join("Dockerfile"),
        "FROM scratch\nCOPY --from=source /../payload /result\n",
    )
    .unwrap();
    let (r, out, _) = f.build(&["--base", &binding]);
    assert!(!r.status.success());
    assert!(!out.exists());

    let outside = source.home.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("canary"), "private").unwrap();
    fs::create_dir(source.context.join("tree")).unwrap();
    symlink(&outside, source.context.join("tree/escape")).unwrap();
    fs::write(
        source.context.join("Dockerfile"),
        "FROM scratch\nCOPY tree /tree\n",
    )
    .unwrap();
    let (r, image, _) = source.build(&[]);
    success(&r);
    fs::write(
        f.context.join("Dockerfile"),
        "FROM scratch\nCOPY --from=source /tree/escape/canary /result\n",
    )
    .unwrap();
    let binding = format!("source={}", image.display());
    let (r, out, _) = f.build(&["--base", &binding]);
    assert!(!r.status.success());
    assert!(!out.exists());
    assert_eq!(fs::read(outside.join("canary")).unwrap(), b"private");
}

#[test]
fn external_copy_rejects_corrupt_warm_source() {
    let mut source = Fixture::new("FROM scratch\nCOPY payload /payload\n");
    let (r, image, _) = source.build(&[]);
    success(&r);
    let mut f = Fixture::new("FROM scratch\nCOPY --from=fixture.invalid/source /payload /result\n");
    let cache = cache_external(&f, &image, "fixture.invalid/source", false);
    let (r, _, _) = f.build(&[]);
    success(&r);
    for entry in fs::read_dir(cache.join("blobs/sha256")).unwrap() {
        fs::write(entry.unwrap().path(), b"corrupt").unwrap();
    }
    let (r, out, _) = f.build(&[]);
    assert!(!r.status.success());
    assert!(!out.exists());
}
#[test]
fn stage_copy_inheritance_target_and_unreachable_stage() {
    let mut f = Fixture::new(
        "FROM scratch AS build\nARG MESSAGE=hello\nENV BUILDER=yes\nCOPY payload /out/payload\nCOPY payload /.dockerignore\nFROM build AS inherited\nENV INHERITED=$MESSAGE\nCOPY --from=0 /out/payload /copy\nFROM nonexistent.invalid/unused AS unused\nRUN false\nFROM scratch AS final\nCOPY --from=inherited /copy /app/payload\nCMD [\"/app/payload\"]\n",
    );
    let (r, out, root) = f.build(&[]);
    success(&r);
    assert_eq!(fs::read(root.join("app/payload")).unwrap(), b"original");
    assert!(!root.join("out").exists());
    assert_eq!(config(&out)["config"]["Env"], serde_json::json!([]));
    assert_eq!(
        config(&out)["config"]["Cmd"],
        serde_json::json!(["/app/payload"])
    );
    let (r, out, _) = f.build(&["--target", "inherited"]);
    success(&r);
    assert!(
        config(&out)["config"]["Env"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("INHERITED=hello"))
    );
    let (r, out, _) = f.build(&["--target", "missing"]);
    assert!(!r.status.success());
    assert!(!out.exists());
    let (r, out, _) = f.build(&["--platform", "linux/arm64"]);
    assert!(!r.status.success());
    assert!(!out.exists());
}
#[test]
fn cache_reuse_content_mode_invalidation_and_bypass() {
    let mut f = Fixture::new(
        "FROM scratch AS build\nCOPY payload /payload\nFROM scratch\nCOPY --from=build /payload /result\n",
    );
    let (r, _, _) = f.build(&[]);
    success(&r);
    assert_eq!(cached(&r), 0);
    let (r, _, _) = f.build(&[]);
    success(&r);
    assert_eq!(cached(&r), 2);
    let payload = f.context.join("payload");
    let modified = fs::metadata(&payload).unwrap().modified().unwrap();
    fs::write(&payload, "modified").unwrap();
    fs::File::options()
        .write(true)
        .open(&payload)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let (r, _, root) = f.build(&[]);
    success(&r);
    assert_eq!(cached(&r), 0);
    assert_eq!(fs::read(root.join("result")).unwrap(), b"modified");
    fs::set_permissions(&payload, fs::Permissions::from_mode(0o755)).unwrap();
    let (r, _, root) = f.build(&[]);
    success(&r);
    assert_eq!(cached(&r), 0);
    assert_eq!(
        fs::metadata(root.join("result"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    let (r, _, _) = f.build(&["--no-cache"]);
    success(&r);
    assert_eq!(cached(&r), 0);
}
#[test]
fn cache_corruption_fails_closed_and_stage_copy_cannot_escape() {
    let mut f = Fixture::new("FROM scratch\nCOPY payload /payload\n");
    let (r, _, _) = f.build(&[]);
    success(&r);
    let mut caches: Vec<_> = fs::read_dir(f.home.join("store/cache-v2/entries"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|entry| entry.join("index.json").is_file())
        .collect();
    caches.sort();
    assert!(!caches.is_empty(), "build did not publish a cache layout");
    // Both instruction and whole-stage entries exist. Corrupt each selected
    // manifest so iteration order cannot choose an unused checkpoint.
    for cache in caches {
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(cache.join("index.json")).unwrap()).unwrap();
        let digest = index["manifests"][0]["digest"]
            .as_str()
            .unwrap()
            .strip_prefix("sha256:")
            .unwrap();
        fs::write(cache.join("blobs/sha256").join(digest), "corrupt").unwrap();
    }
    let (r, out, _) = f.build(&[]);
    assert!(!r.status.success());
    assert!(!out.exists());
    let (r, _, _) = f.build(&["--no-cache"]);
    success(&r);
    let mut f = Fixture::new(
        "FROM scratch AS build\nCOPY tree /tree\nFROM scratch\nCOPY --from=build /tree/escape/canary /stolen\n",
    );
    fs::create_dir(f.context.join("tree")).unwrap();
    fs::write(f.home.join("canary"), "never copied").unwrap();
    symlink(&f.home, f.context.join("tree/escape")).unwrap();
    let (r, out, _) = f.build(&[]);
    assert!(!r.status.success());
    assert!(!out.exists());
    assert_eq!(fs::read(f.home.join("canary")).unwrap(), b"never copied");
}

// Fix fixture atimes in the future so exporting two ARG-only parents really
// yields identical image digests, independent of relatime and wall-clock time.
fn stable_base(f: &mut Fixture, extra: &[&str]) -> String {
    let (r, out, root) = f.build(extra);
    success(&r);
    let mut pending = vec![root.clone()];
    while let Some(path) = pending.pop() {
        let m = fs::symlink_metadata(&path).unwrap();
        if m.is_dir() {
            pending.extend(fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
        }
        set_atime(&path, 100);
    }
    let base = f.home.join("stable-base");
    rpweld::export::export_layout(
        &root,
        &base,
        &config(&out),
        rpweld::export::Limits {
            max_layer_bytes: 512 * 1024 * 1024,
            max_entries: 100_000,
            max_metadata_bytes: 32 * 1024 * 1024,
        },
        || false,
    )
    .unwrap();
    format!("local={}", base.display())
}

#[test]
fn cache_keys_inherited_args_before_later_overwrite() {
    let mut f = Fixture::new("FROM scratch\n");
    let binding = stable_base(&mut f, &[]);
    let mut parent_digest = None;
    for (i, value) in ["first", "second", "second"].into_iter().enumerate() {
        fs::write(
            f.context.join("Dockerfile"),
            format!("FROM local AS parent\nARG X={value}\nFROM parent\nWORKDIR /$X\nARG X=fixed\nWORKDIR /\n"),
        )
        .unwrap();
        let (r, parent, _) = f.build(&["--base", &binding, "--target", "parent"]);
        success(&r);
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(parent.join("index.json")).unwrap()).unwrap();
        let digest = index["manifests"][0]["digest"].clone();
        assert_eq!(parent_digest.get_or_insert(digest.clone()), &digest);
        let (r, _, root) = f.build(&["--base", &binding]);
        success(&r);
        assert!(root.join(value).is_dir());
        assert!(
            !root
                .join(if value == "first" { "second" } else { "first" })
                .exists()
        );
        assert_eq!(cached(&r), if i == 2 { 2 } else { 1 });
    }
}

#[test]
#[ignore = "requires root and RPWELD_TEST_LAYOUT with /bin/sh"]
fn cache_keys_inherited_run_args_before_later_overwrite() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let layout = fs::canonicalize(std::env::var_os("RPWELD_TEST_LAYOUT").unwrap()).unwrap();
    let binding = format!("local={}", layout.display());
    let mut f = Fixture::new("FROM local\n");
    let binding = stable_base(&mut f, &["--base", &binding]);
    let mut parent_digest = None;
    for (i, value) in ["first", "second", "second"].into_iter().enumerate() {
        fs::write(
            f.context.join("Dockerfile"),
            format!("FROM local AS parent\nARG X={value}\nFROM parent\nRUN echo \"$X\" > /result\nARG X=fixed\n"),
        )
        .unwrap();
        let (r, parent, _) = f.build(&["--base", &binding, "--target", "parent"]);
        success(&r);
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(parent.join("index.json")).unwrap()).unwrap();
        let digest = index["manifests"][0]["digest"].clone();
        assert_eq!(parent_digest.get_or_insert(digest.clone()), &digest);
        let (r, _, root) = f.build(&["--base", &binding]);
        success(&r);
        assert_eq!(
            fs::read_to_string(root.join("result")).unwrap(),
            format!("{value}\n")
        );
        assert_eq!(cached(&r), if i == 2 { 2 } else { 1 });
    }
}

fn set_atime(path: &Path, nanos: i64) {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: 2_000_000_000,
            tv_nsec: nanos,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    ];
    assert_eq!(
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                path.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        },
        0
    );
}

#[test]
fn cache_invalidates_preserved_atimes_for_files_directories_and_symlinks() {
    let mut f = Fixture::new("FROM scratch\nCOPY tree /out\n");
    fs::create_dir_all(f.context.join("tree/nested")).unwrap();
    fs::write(f.context.join("tree/nested/file"), "unchanged").unwrap();
    symlink("file", f.context.join("tree/nested/link")).unwrap();
    for name in [
        "",
        "tree",
        "tree/nested",
        "tree/nested/file",
        "tree/nested/link",
        "Dockerfile",
        "payload",
    ] {
        set_atime(&f.context.join(name), 100);
    }
    let (r, _, _) = f.build(&[]);
    success(&r);
    assert_eq!(cached(&r), 0);
    for name in ["nested/file", "nested", "nested/link"] {
        let source = f.context.join("tree").join(name);
        let before = fs::symlink_metadata(&source).unwrap();
        set_atime(&source, 200);
        let (r, _, root) = f.build(&[]);
        success(&r);
        assert_eq!(cached(&r), 0, "{name}");
        let copied = fs::symlink_metadata(root.join("out").join(name)).unwrap();
        assert_eq!(
            (copied.atime(), copied.atime_nsec()),
            (2_000_000_000, 200),
            "{name}"
        );
        assert_eq!(
            (copied.mtime(), copied.mtime_nsec()),
            (before.mtime(), before.mtime_nsec())
        );
        let (r, _, root) = f.build(&[]);
        success(&r);
        assert_eq!(cached(&r), 1, "{name}");
        let replayed = fs::symlink_metadata(root.join("out").join(name)).unwrap();
        assert_eq!(
            (replayed.atime(), replayed.atime_nsec()),
            (2_000_000_000, 200)
        );
    }
}
