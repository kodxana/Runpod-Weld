//! Scratch-only CLI regressions. Linux/root is required for faithful OCI replay.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, symlink},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    temp: tempfile::TempDir,
    context: PathBuf,
    dockerfile: PathBuf,
    number: usize,
}
impl Fixture {
    fn new(source: &str, policy: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let context = temp.path().join("context");
        fs::create_dir(&context).unwrap();
        let dockerfile = context.join("Dockerfile");
        fs::write(&dockerfile, source).unwrap();
        fs::write(context.join(".dockerignore"), policy).unwrap();
        Self {
            temp,
            context,
            dockerfile,
            number: 0,
        }
    }
    fn put(&self, name: &str) {
        let path = self.context.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, name).unwrap();
    }
    fn build(&mut self) -> (Output, PathBuf, PathBuf) {
        self.number += 1;
        let out = self.temp.path().join(format!("output-{}", self.number));
        let work = self.temp.path().join(format!("work-{}", self.number));
        let log = self.temp.path().join(format!("stderr-{}", self.number));
        let mut child = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .env("RPWELD_HOME", self.temp.path().join("store"))
            .current_dir(self.temp.path())
            .args([
                "build",
                "-t",
                "test/dockerignore:latest",
                "--platform",
                "linux/amd64",
                "-f",
            ])
            .arg(self.dockerfile.strip_prefix(self.temp.path()).unwrap())
            .arg("--output")
            .arg(&out)
            .arg("--work-dir")
            .arg(&work)
            .arg("context")
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if start.elapsed() > Duration::from_secs(20) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "scratch build blocked (possibly opened an ignored FIFO): {}",
                    fs::read_to_string(log).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut result = child.wait_with_output().unwrap();
        result.stderr = fs::read(log).unwrap();
        (result, out, work)
    }
}
fn success(result: &Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
fn cached(result: &Output) -> usize {
    String::from_utf8_lossy(&result.stderr)
        .matches("CACHED (")
        .count()
}
fn replay(out: &Path) -> PathBuf {
    use rpweld::{image, layer, oci::BlobStore, rootfs};
    let metadata = image::load_layout(
        out,
        None,
        image::Limits {
            max_metadata_bytes: 1 << 20,
            max_total_metadata_bytes: 4 << 20,
            max_descriptors: 100,
            max_layer_bytes: 16 << 20,
            max_total_layer_bytes: 32 << 20,
        },
        || false,
    )
    .unwrap();
    let store = BlobStore::open(out).unwrap();
    let root = out.with_extension("replay");
    fs::create_dir(&root).unwrap();
    for (descriptor, diff_id) in metadata.layers.iter().zip(&metadata.diff_ids) {
        let mut verified = layer::verify(
            &store,
            descriptor,
            diff_id,
            out.parent().unwrap(),
            layer::Limits {
                max_blob_bytes: 16 << 20,
                max_uncompressed_bytes: 16 << 20,
                max_entries: 1000,
                max_metadata_bytes: 1 << 20,
                max_gzip_header_bytes: 1024,
            },
            || false,
        )
        .unwrap();
        rootfs::apply_layer(&root, &mut verified, || false).unwrap();
    }
    root
}

#[test]
fn ordered_negation_reincludes_descendants_of_excluded_directories() {
    let mut f = Fixture::new(
        "FROM scratch\nCOPY . /out/\n",
        "tree\n!tree/deep/keep\n!tree/deep/again\ntree/deep/again\n",
    );
    for p in ["tree/deep/keep", "tree/deep/again", "tree/other", "visible"] {
        f.put(p);
    }
    let (r, out, _) = f.build();
    success(&r);
    let root = replay(&out).join("out");
    assert_eq!(
        fs::read(root.join("tree/deep/keep")).unwrap(),
        b"tree/deep/keep"
    );
    assert!(root.join("visible").is_file());
    for p in ["tree/deep/again", "tree/other"] {
        assert!(!root.join(p).exists(), "{p}");
    }
}

#[test]
fn moby_pattern_matrix() {
    fn directories(root: &Path, path: &Path, found: &mut Vec<String>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                found.push(
                    entry
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                );
                directories(root, &entry.path(), found);
            }
        }
    }
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/dockerignore/patterns.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let mut f = Fixture::new(
            "FROM scratch\nCOPY . /out/\n",
            case["policy"].as_str().unwrap(),
        );
        for p in case["paths"].as_array().unwrap() {
            f.put(p[0].as_str().unwrap());
        }
        let (r, out, _) = f.build();
        success(&r);
        let root = replay(&out).join("out");
        let mut actual_dirs = Vec::new();
        directories(&root, &root, &mut actual_dirs);
        actual_dirs.sort();
        let expected_dirs: Vec<_> = case["directories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(actual_dirs, expected_dirs, "{}", case["policy"]);
        for p in case["paths"].as_array().unwrap() {
            let name = p[0].as_str().unwrap();
            assert_eq!(
                root.join(name).exists(),
                !p[1].as_bool().unwrap(),
                "{}: {name}",
                case["policy"]
            );
            if !p[1].as_bool().unwrap() {
                assert_eq!(fs::read(root.join(name)).unwrap(), name.as_bytes());
            }
        }
    }
}

#[test]
fn dockerfile_specific_policy_replaces_root_including_empty_override() {
    for policy in ["", "specific-only\n"] {
        let mut f = Fixture::new("FROM scratch\nCOPY . /out/\n", "root-only\n");
        f.put("root-only");
        f.put("specific-only");
        fs::write(f.context.join("Dockerfile.dockerignore"), policy).unwrap();
        let (r, out, _) = f.build();
        success(&r);
        let root = replay(&out).join("out");
        assert!(root.join("root-only").exists());
        assert_eq!(root.join("specific-only").exists(), policy.is_empty());
    }
}

#[test]
fn nested_and_external_dockerfile_policies_are_context_relative() {
    for external in [false, true] {
        for policy in ["", "target\n"] {
            let mut f = Fixture::new("FROM scratch\nCOPY . /out/\n", "root-only\n");
            let parent = if external {
                f.temp.path().join("recipes")
            } else {
                f.context.join("recipes")
            };
            fs::create_dir(&parent).unwrap();
            f.dockerfile = parent.join("custom.Dockerfile");
            fs::write(&f.dockerfile, "FROM scratch\nCOPY . /out/\n").unwrap();
            fs::write(parent.join("custom.Dockerfile.dockerignore"), policy).unwrap();
            for p in ["target", "recipes/target", "root-only"] {
                f.put(p);
            }
            let (r, out, _) = f.build();
            success(&r);
            let root = replay(&out).join("out");
            assert_eq!(root.join("target").exists(), policy.is_empty());
            assert!(root.join("recipes/target").exists());
            assert!(root.join("root-only").exists());
        }
    }
}

#[test]
fn excluded_explicit_source_is_rejected_before_even_earlier_copy_mutates() {
    for source in ["secret", "excluded/child"] {
        let mut f = Fixture::new(
            &format!("FROM scratch\nCOPY good /first\nCOPY {source} /second\n"),
            "secret\nexcluded\n",
        );
        for p in ["good", "secret", "excluded/child"] {
            f.put(p);
        }
        let (r, out, work) = f.build();
        assert!(!r.status.success());
        assert!(!out.exists());
        assert!(!work.exists(), "{}", String::from_utf8_lossy(&r.stderr));
    }
}

#[test]
fn ignored_fifo_is_not_opened_or_rejected_as_payload() {
    let mut f = Fixture::new("FROM scratch\nCOPY . /out/\n", "blocked\n");
    f.put("good");
    let fifo = std::ffi::CString::new(f.context.join("blocked").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let (r, out, _) = f.build();
    success(&r);
    let root = replay(&out).join("out");
    assert!(root.join("good").exists());
    assert!(!root.join("blocked").exists());
}

#[test]
fn excluded_control_files_remain_readable_to_builder() {
    let mut f = Fixture::new(
        "FROM scratch\nCOPY . /out/\n",
        "Dockerfile\n.dockerignore\nsecret\n",
    );
    f.put("good");
    f.put("secret");
    let (r, out, _) = f.build();
    success(&r);
    let root = replay(&out).join("out");
    assert!(root.join("good").exists());
    for p in ["Dockerfile", ".dockerignore", "secret"] {
        assert!(!root.join(p).exists());
    }
}

#[test]
fn regexp_tab_escape_excludes_tab_filename_and_invalid_escape_fails_closed() {
    let mut f = Fixture::new("FROM scratch\nCOPY . /out/\n", "secret\\tkey\n");
    f.put("secret\tkey");
    f.put("secrettkey");
    let (r, out, _) = f.build();
    success(&r);
    let root = replay(&out).join("out");
    assert!(!root.join("secret\tkey").exists());
    assert!(root.join("secrettkey").is_file());
    fs::write(f.context.join(".dockerignore"), "secret\\qkey\n").unwrap();
    let (r, out, work) = f.build();
    assert!(!r.status.success());
    assert!(!out.exists());
    assert!(!work.exists());
}

#[test]
fn policy_does_not_allow_symlink_ancestor_escape() {
    let mut f = Fixture::new(
        "FROM scratch\nCOPY good /first\nCOPY escape/canary /stolen\n",
        "# active but nonexcluding policy\n",
    );
    f.put("good");
    fs::write(f.temp.path().join("canary"), "private").unwrap();
    symlink(f.temp.path(), f.context.join("escape")).unwrap();
    let (r, out, work) = f.build();
    assert!(!r.status.success());
    assert!(!out.exists());
    assert!(!work.exists());
}

// A future atime avoids relatime reads changing the metadata under test.
fn stable_times(path: &Path) {
    let time = std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    fs::File::open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_accessed(time).set_modified(time))
        .unwrap();
}
#[test]
fn cache_tracks_selected_content_and_semantic_policy_not_excluded_text() {
    let policy = "Dockerfile\n.dockerignore\nignored\n";
    let mut f = Fixture::new("FROM scratch\nCOPY . /out/\n", policy);
    f.put("included");
    f.put("ignored");
    for p in ["", "Dockerfile", ".dockerignore", "included", "ignored"] {
        stable_times(&f.context.join(p));
    }
    let (r, _, _) = f.build();
    success(&r);
    assert_eq!(cached(&r), 0);
    let (r, _, _) = f.build();
    success(&r);
    assert_eq!(cached(&r), 1);
    fs::write(f.context.join("ignored"), "ignored content changed").unwrap();
    let (r, _, _) = f.build();
    success(&r);
    assert_eq!(cached(&r), 1);
    fs::write(f.context.join("included"), "new data").unwrap();
    stable_times(&f.context.join("included"));
    let (r, out, _) = f.build();
    success(&r);
    assert_eq!(cached(&r), 0);
    assert_eq!(
        fs::read(replay(&out).join("out/included")).unwrap(),
        b"new data"
    );
    fs::write(
        f.context.join(".dockerignore"),
        format!("# changed comment\n{policy}"),
    )
    .unwrap();
    stable_times(&f.context.join(".dockerignore"));
    let (r, _, _) = f.build();
    success(&r);
    assert_eq!(cached(&r), 1);
    fs::write(
        f.context.join(".dockerignore"),
        "Dockerfile\n.dockerignore\nincluded\n",
    )
    .unwrap();
    stable_times(&f.context.join(".dockerignore"));
    let (r, out, _) = f.build();
    success(&r);
    assert_eq!(cached(&r), 0);
    let root = replay(&out).join("out");
    assert!(!root.join("included").exists());
    assert!(root.join("ignored").exists());
}

#[test]
fn selected_directory_timestamps_are_preserved_and_invalidate_cache() {
    let mut f = Fixture::new("FROM scratch\nCOPY tree /out/\n", "tree/ignored\n");
    f.put("tree/keep");
    f.put("tree/ignored");
    for p in [
        "",
        "tree",
        "tree/keep",
        "tree/ignored",
        "Dockerfile",
        ".dockerignore",
    ] {
        stable_times(&f.context.join(p));
    }
    let (r, out, _) = f.build();
    success(&r);
    let before = fs::metadata(f.context.join("tree")).unwrap();
    let copied = fs::metadata(replay(&out).join("out")).unwrap();
    assert_eq!(
        (copied.mtime(), copied.atime()),
        (before.mtime(), before.atime())
    );
    let time = std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_001);
    fs::File::open(f.context.join("tree"))
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(time))
        .unwrap();
    let (r, out, _) = f.build();
    success(&r);
    assert_eq!(cached(&r), 0);
    assert_eq!(
        fs::metadata(replay(&out).join("out")).unwrap().mtime(),
        2_000_000_001
    );
}

#[test]
fn adding_and_removing_ignored_entries_preserves_changed_parent_metadata() {
    let mut f = Fixture::new("FROM scratch\nCOPY tree /out/\n", "tree/ignored*\n");
    f.put("tree/keep");
    for p in ["", "tree", "tree/keep", "Dockerfile", ".dockerignore"] {
        stable_times(&f.context.join(p));
    }
    let (r, _, _) = f.build();
    success(&r);
    let (r, _, _) = f.build();
    success(&r);
    assert_eq!(cached(&r), 1);
    for add in [true, false] {
        let before = fs::metadata(f.context.join("tree")).unwrap();
        if add {
            f.put("tree/ignored-new");
        } else {
            // Ensure the removal is observably later on coarse timestamp filesystems.
            std::thread::sleep(Duration::from_millis(1100));
            fs::remove_file(f.context.join("tree/ignored-new")).unwrap();
        }
        let after = fs::metadata(f.context.join("tree")).unwrap();
        assert_ne!(
            (before.mtime(), before.mtime_nsec()),
            (after.mtime(), after.mtime_nsec())
        );
        let (r, out, _) = f.build();
        success(&r);
        assert_eq!(cached(&r), 0);
        let root = replay(&out).join("out");
        let copied = fs::metadata(&root).unwrap();
        assert_eq!(
            (copied.mtime(), copied.mtime_nsec()),
            (after.mtime(), after.mtime_nsec())
        );
        assert_eq!(fs::read(root.join("keep")).unwrap(), b"tree/keep");
        assert!(!root.join("ignored-new").exists());
    }
}
