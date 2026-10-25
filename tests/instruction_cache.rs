#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

// These acceptance tests deliberately use the CLI, not cache keys or receipts.
// Install commands are offline stand-ins: lockfile first, application source last.
struct Project {
    temp: tempfile::TempDir,
    context: PathBuf,
    base: PathBuf,
    serial: usize,
}

struct Build {
    success: bool,
    log: String,
    root: PathBuf,
    image: PathBuf,
}

impl Build {
    fn ok(&self) {
        assert!(self.success, "{}", self.log);
    }

    fn read(&self, path: &str) -> Vec<u8> {
        fs::read(self.root.join(path)).unwrap()
    }

    fn executed(&self, marker: &str) -> bool {
        // The Dockerfile splits the token across printf arguments; printing the
        // instruction text cannot masquerade as actual process output.
        self.log
            .lines()
            .any(|line| line.trim() == format!("IC_EXEC_{marker}"))
    }

    fn cached(&self, ordinal: usize, op: &str) {
        assert!(
            self.log.lines().any(|line| line
                .trim()
                .starts_with(&format!("CACHED instruction {ordinal} {op} [stage "))),
            "missing instruction hit {ordinal} {op}: {}",
            self.log
        );
    }

    fn config(&self) -> serde_json::Value {
        let limits = rpweld::image::Limits {
            max_metadata_bytes: 16 * 1024 * 1024,
            max_total_metadata_bytes: 64 * 1024 * 1024,
            max_descriptors: 1024,
            max_layer_bytes: 256 * 1024 * 1024,
            max_total_layer_bytes: 512 * 1024 * 1024,
        };
        rpweld::image::load_layout(&self.image, None, limits, || false)
            .unwrap()
            .config["config"]
            .clone()
    }
}

impl Project {
    fn scratch() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let context = temp.path().join("context");
        fs::create_dir(&context).unwrap();
        Self {
            temp,
            context,
            base: PathBuf::new(),
            serial: 0,
        }
    }

    fn new(fixture: &str) -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "RUN acceptance tests require Linux root"
        );
        let base = fs::canonicalize(
            std::env::var_os("RPWELD_TEST_LAYOUT")
                .expect("set RPWELD_TEST_LAYOUT to a local Alpine OCI layout"),
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let context = temp.path().join("context");
        fs::create_dir(&context).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/instruction-cache")
            .join(fixture);
        for file in fs::read_dir(source).unwrap() {
            let file = file.unwrap();
            fs::copy(file.path(), context.join(file.file_name())).unwrap();
        }
        Self {
            temp,
            context,
            base,
            serial: 0,
        }
    }

    fn write(&self, name: &str, value: &str) {
        fs::write(self.context.join(name), value).unwrap();
    }

    fn build(&mut self, args: &[&str]) -> Build {
        self.build_inner(args, false)
    }

    fn build_inner(&mut self, args: &[&str], cancel_on_marker: bool) -> Build {
        self.serial += 1;
        self.build_at(
            self.serial,
            args,
            cancel_on_marker,
            "instruction-cache:test",
        )
    }

    fn build_at(&self, serial: usize, args: &[&str], cancel_on_marker: bool, tag: &str) -> Build {
        let work = self.temp.path().join(format!("work-{serial}"));
        let image = self.temp.path().join(format!("image-{serial}"));
        let stdout = self.temp.path().join(format!("stdout-{serial}"));
        let stderr = self.temp.path().join(format!("stderr-{serial}"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        if !self.base.as_os_str().is_empty() {
            command
                .arg("build")
                .arg("--base")
                .arg(format!("alpine={}", self.base.display()));
        } else {
            command.arg("build");
        }
        let mut child = command
            .env("RPWELD_HOME", self.temp.path().join("store"))
            .env("HOME", self.temp.path())
            .args(["--no-host-dns", "-t", tag])
            .arg("--work-dir")
            .arg(&work)
            .arg("--output")
            .arg(&image)
            .args(args)
            .arg(&self.context)
            .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        let start = Instant::now();
        let mut cancelled = false;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if cancel_on_marker && !cancelled && work.join("rootfs/cancel-ready").exists() {
                assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
                cancelled = true;
            }
            if start.elapsed() > Duration::from_secs(90) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "cache build timed out: {}",
                    fs::read_to_string(&stderr).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if cancel_on_marker {
            assert!(cancelled, "RUN did not reach cancellation marker");
        }
        Build {
            success: status.success(),
            log: format!(
                "{}\n{}",
                fs::read_to_string(stdout).unwrap(),
                fs::read_to_string(stderr).unwrap()
            ),
            root: work.join("rootfs"),
            image,
        }
    }

    fn tag(&self) -> Vec<u8> {
        let path = fs::read_dir(self.temp.path().join("store"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name().unwrap().to_string_lossy().starts_with("tag-")
                    && p.extension().is_some_and(|s| s == "json")
            })
            .unwrap();
        fs::read(path).unwrap()
    }
}

#[test]
fn cached_copy_prefix_still_charges_cumulative_bytes() {
    let mut p = Project::scratch();
    p.write(".dockerignore", "Dockerfile\n.dockerignore\n");
    p.write("payload", "123456");
    p.write("Dockerfile", "FROM scratch\nCOPY payload /payload\n");
    let prefix = p.build(&["--max-rootfs-bytes", "10"]);
    prefix.ok();
    p.write(
        "Dockerfile",
        "FROM scratch\nCOPY payload /payload\nCOPY payload /payload\n",
    );
    let warm = p.build(&["--max-rootfs-bytes", "10"]);
    assert!(
        !warm.success,
        "cumulative COPY bytes were reset by a hit: {}",
        warm.log
    );
    warm.cached(2, "COPY");
    assert!(!warm.image.exists());
    let reference = p.build(&["--max-rootfs-bytes", "10", "--no-cache"]);
    assert!(!reference.success, "{}", reference.log);
    assert!(!reference.image.exists());
    assert_eq!(warm.read("payload"), reference.read("payload"));
}

#[test]
fn excluded_tree_growth_is_charged_on_instruction_hits() {
    let mut p = Project::scratch();
    p.write(
        ".dockerignore",
        "Dockerfile\n.dockerignore\nignored\n!never\n",
    );
    p.write("keep", "keep");
    fs::create_dir(p.context.join("ignored")).unwrap();
    let prefix = "FROM scratch\nCOPY . /one/\nCOPY . /two/\n";
    p.write("Dockerfile", &format!("{prefix}LABEL version=one\n"));
    let future = std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    for name in ["", "keep", "Dockerfile", ".dockerignore"] {
        fs::File::open(p.context.join(name))
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_accessed(future)
                    .set_modified(future),
            )
            .unwrap();
    }
    let cold = p.build(&["--metadata-budget", "32768"]);
    cold.ok();
    let warm = p.build(&["--metadata-budget", "32768"]);
    warm.ok();
    assert!(warm.log.contains("CACHED"), "{}", warm.log);
    for index in 0..40 {
        fs::write(p.context.join(format!("ignored/{index}")), "excluded").unwrap();
    }
    p.write("Dockerfile", &format!("{prefix}LABEL version=two\n"));
    let exhausted = p.build(&["--metadata-budget", "32768"]);
    assert!(
        !exhausted.success,
        "ignored traversal bypassed cumulative budget: {}",
        exhausted.log
    );
    exhausted.cached(2, "COPY");
    assert!(!exhausted.image.exists());
    let reference = p.build(&["--metadata-budget", "32768", "--no-cache"]);
    assert!(!reference.success, "{}", reference.log);
    assert!(!reference.image.exists());
}

#[test]
fn unknown_named_owner_with_nondirectory_etc_matches_uncached_behavior() {
    use std::os::unix::fs::MetadataExt;
    let mut p = Project::scratch();
    p.write("etc-file", "not a directory\n");
    p.write("payload", "owned payload\n");
    let prefix =
        "FROM scratch\nCOPY etc-file /etc\nCOPY --chown=builder:builders payload /payload\n";
    p.write("Dockerfile", &format!("{prefix}LABEL version=one\n"));
    let cold = p.build(&[]);
    cold.ok();
    p.write("Dockerfile", &format!("{prefix}LABEL version=two\n"));
    let warm = p.build(&[]);
    warm.ok();
    warm.cached(2, "COPY");
    warm.cached(3, "COPY");
    let reference = p.build(&["--no-cache"]);
    reference.ok();
    for built in [&cold, &warm, &reference] {
        assert_eq!(built.read("etc"), b"not a directory\n");
        assert_eq!(built.read("payload"), b"owned payload\n");
        let metadata = fs::metadata(built.root.join("payload")).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (0, 0));
    }
    assert_eq!(warm.config(), reference.config());
}

#[test]
fn empty_and_excluded_copies_remain_empty_on_prefix_hits() {
    let mut p = Project::scratch();
    p.write(".dockerignore", "excluded\n");
    fs::create_dir(p.context.join("excluded")).unwrap();
    fs::write(p.context.join("excluded/secret"), "hidden").unwrap();
    p.write("payload", "visible");
    let prefix =
        "FROM scratch\nCOPY missing* /missing/\nCOPY excluded* /excluded/\nCOPY payload /payload\n";
    p.write("Dockerfile", &format!("{prefix}LABEL version=one\n"));
    let cold = p.build(&[]);
    cold.ok();
    p.write("Dockerfile", &format!("{prefix}LABEL version=two\n"));
    let warm = p.build(&[]);
    warm.ok();
    warm.cached(2, "COPY");
    warm.cached(3, "COPY");
    assert!(!warm.root.join("missing").exists());
    assert!(!warm.root.join("excluded").exists());
    assert_eq!(warm.read("payload"), b"visible");
    // A formerly empty wildcard must stop hitting when a match appears.
    p.write("missing-now", "new input");
    let changed = p.build(&[]);
    changed.ok();
    assert_eq!(changed.read("missing/missing-now"), b"new input");
}

#[test]
fn corrupt_checkpoint_fails_closed_before_tag_replacement() {
    for corruption in ["index", "layer"] {
        let mut p = Project::scratch();
        p.write("payload", "known-good");
        p.write(
            "Dockerfile",
            "FROM scratch\nCOPY payload /payload\nLABEL version=one\n",
        );
        p.build(&[]).ok();
        let tag = p.tag();
        let cache = p.temp.path().join("store/cache-v2/entries");
        let mut damaged = 0;
        for entry in fs::read_dir(cache).unwrap() {
            let entry = entry.unwrap().path();
            if !entry.join("index.json").is_file() {
                continue;
            }
            if corruption == "index" {
                fs::write(entry.join("index.json"), b"{").unwrap();
            } else {
                let index: serde_json::Value =
                    serde_json::from_slice(&fs::read(entry.join("index.json")).unwrap()).unwrap();
                let manifest_path = entry.join("blobs/sha256").join(
                    index["manifests"][0]["digest"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("sha256:")
                        .unwrap(),
                );
                let manifest: serde_json::Value =
                    serde_json::from_slice(&fs::read(manifest_path).unwrap()).unwrap();
                let layer = entry.join("blobs/sha256").join(
                    manifest["layers"][0]["digest"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("sha256:")
                        .unwrap(),
                );
                fs::write(layer, b"corrupted layer").unwrap();
            }
            damaged += 1;
        }
        assert!(damaged > 0);
        // Different final metadata bypasses the old whole-stage key, forcing
        // verification of an instruction checkpoint from the unchanged prefix.
        p.write(
            "Dockerfile",
            "FROM scratch\nCOPY payload /payload\nLABEL version=two\n",
        );
        let failed = p.build(&[]);
        assert!(
            !failed.success,
            "corrupt {corruption} accepted: {}",
            failed.log
        );
        assert!(!failed.image.exists());
        assert_eq!(p.tag(), tag);
        let uncached = p.build(&["--no-cache"]);
        uncached.ok();
        assert_eq!(uncached.read("payload"), b"known-good");
    }
}

#[test]
fn concurrent_cold_publication_is_bounded_and_reusable() {
    let mut p = Project::scratch();
    p.write("payload", "parallel payload");
    p.write(
        "Dockerfile",
        "FROM scratch\nCOPY payload /one\nCOPY payload /two\nLABEL version=one\n",
    );
    let barrier = std::sync::Barrier::new(4);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|index| {
                let (p, barrier) = (&p, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    p.build_at(
                        100 + index,
                        &[],
                        false,
                        &format!("instruction-cache:parallel-{index}"),
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    for result in &results {
        result.ok();
        assert_eq!(result.read("one"), b"parallel payload");
        assert_eq!(result.read("two"), b"parallel payload");
    }
    let entries = || {
        fs::read_dir(p.temp.path().join("store/cache-v2/entries"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>()
    };
    let published = entries();
    assert!(
        !published.is_empty() && published.len() <= 16,
        "unbounded publication: {published:?}"
    );
    assert!(published.iter().all(|e| {
        !e.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".publish-")
    }));
    let before = published.len();
    let cache = p.temp.path().join("store/cache-v2/entries");
    let warm = p.build(&[]);
    warm.ok();
    assert!(warm.log.contains("CACHED"), "{}", warm.log);
    assert_eq!(fs::read_dir(cache).unwrap().count(), before);
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT (local Alpine OCI)"]
fn dependency_ordering_reuses_only_the_unchanged_prefix() {
    for (fixture, source, dependencies, changed_source, changed_dependencies) in [
        (
            "python",
            "app.py",
            "requirements.txt",
            "print('application-v2')\n",
            "offline-example==2\n",
        ),
        (
            "node",
            "index.js",
            "package-lock.json",
            "console.log('application-v2');\n",
            "{\"name\":\"offline-cache-example-v2\",\"lockfileVersion\":3,\"packages\":{}}\n",
        ),
    ] {
        let mut p = Project::new(fixture);
        let cold = p.build(&[]);
        cold.ok();
        assert!(
            cold.executed("dependencies") && cold.executed("application"),
            "{}",
            cold.log
        );
        let warm = p.build(&[]);
        warm.ok();
        assert!(
            !warm.executed("dependencies") && !warm.executed("application"),
            "{}",
            warm.log
        );
        assert!(warm.log.contains("CACHED"), "{}", warm.log);
        assert_eq!(
            cold.read("app/dependency-nonce"),
            warm.read("app/dependency-nonce")
        );
        assert_eq!(
            cold.read("app/application-nonce"),
            warm.read("app/application-nonce")
        );

        p.write(source, changed_source);
        let app = p.build(&[]);
        app.ok();
        app.cached(3, "COPY");
        app.cached(4, "RUN");
        assert!(
            !app.executed("dependencies") && app.executed("application"),
            "{}",
            app.log
        );
        assert_eq!(
            cold.read("app/dependency-nonce"),
            app.read("app/dependency-nonce")
        );
        assert_ne!(
            cold.read("app/application-nonce"),
            app.read("app/application-nonce")
        );
        assert!(
            String::from_utf8(app.read("app/result"))
                .unwrap()
                .contains(changed_source.trim())
        );

        p.write("unrelated.txt", "not selected by any COPY\n");
        let unrelated = p.build(&[]);
        unrelated.ok();
        assert!(
            !unrelated.executed("dependencies") && !unrelated.executed("application"),
            "{}",
            unrelated.log
        );
        assert_eq!(
            app.read("app/application-nonce"),
            unrelated.read("app/application-nonce")
        );

        p.write(dependencies, changed_dependencies);
        let deps = p.build(&[]);
        deps.ok();
        assert!(
            deps.executed("dependencies") && deps.executed("application"),
            "{}",
            deps.log
        );
        assert_ne!(
            app.read("app/dependency-nonce"),
            deps.read("app/dependency-nonce")
        );
        assert!(
            String::from_utf8(deps.read("app/result"))
                .unwrap()
                .contains(changed_dependencies.trim())
        );

        let uncached = p.build(&["--no-cache"]);
        uncached.ok();
        assert!(
            uncached.executed("dependencies") && uncached.executed("application"),
            "{}",
            uncached.log
        );
        assert!(
            !uncached.log.contains("CACHED instruction"),
            "{}",
            uncached.log
        );
        assert_ne!(
            deps.read("app/dependency-nonce"),
            uncached.read("app/dependency-nonce")
        );
        // RUN generates intentional nondeterminism; compare application output and
        // image configuration, not whole-image digest or random probe files.
        assert_eq!(deps.read("app/result"), uncached.read("app/result"));
        assert_eq!(deps.config(), uncached.config());
        let after = p.build(&[]);
        after.ok();
        assert_eq!(
            deps.read("app/dependency-nonce"),
            after.read("app/dependency-nonce"),
            "--no-cache must not publish replacement checkpoints"
        );
    }
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT (local Alpine OCI)"]
fn args_environment_shell_workdir_and_copy_flags_invalidate() {
    for (before, after, flags_before, flags_after) in [
        (
            "ARG VALUE=one\n",
            "ARG VALUE=one\n",
            vec!["--build-arg", "VALUE=one"],
            vec!["--build-arg", "VALUE=two"],
        ),
        ("ENV VALUE=one\n", "ENV VALUE=two\n", vec![], vec![]),
        (
            "SHELL [\"/bin/sh\",\"-c\"]\n",
            "SHELL [\"/bin/sh\",\"-ec\"]\n",
            vec![],
            vec![],
        ),
        ("WORKDIR /one\n", "WORKDIR /two\n", vec![], vec![]),
        (
            "COPY --chmod=0644 app.py /source\n",
            "COPY --chmod=0600 app.py /source\n",
            vec![],
            vec![],
        ),
        (
            "COPY --chown=0:0 app.py /source\n",
            "COPY --chown=123:456 app.py /source\n",
            vec![],
            vec![],
        ),
    ] {
        let mut p = Project::new("python");
        let dockerfile = |prefix: &str| {
            format!(
                "FROM alpine\n{prefix}RUN printf 'IC_EXEC_%s\\n' probe; printf '%s' \"$VALUE\" > /value; pwd > /cwd; head -c 32 /dev/urandom | od -An -tx1 > /nonce\n"
            )
        };
        p.write("Dockerfile", &dockerfile(before));
        let cold = p.build(&flags_before);
        cold.ok();
        let warm = p.build(&flags_before);
        warm.ok();
        assert!(!warm.executed("probe"), "{}", warm.log);
        p.write("Dockerfile", &dockerfile(after));
        let changed = p.build(&flags_after);
        changed.ok();
        assert!(
            changed.executed("probe"),
            "prefix {before:?} -> {after:?}: {}",
            changed.log
        );
        assert_ne!(cold.read("nonce"), changed.read("nonce"));
        let reference = p.build(&[flags_after.as_slice(), &["--no-cache"]].concat());
        reference.ok();
        assert_eq!(changed.read("value"), reference.read("value"));
        assert_eq!(changed.read("cwd"), reference.read("cwd"));
        assert_eq!(changed.config(), reference.config());
        if after.starts_with("COPY") {
            use std::os::unix::fs::MetadataExt;
            let a = fs::metadata(changed.root.join("source")).unwrap();
            let b = fs::metadata(reference.root.join("source")).unwrap();
            assert_eq!((a.mode(), a.uid(), a.gid()), (b.mode(), b.uid(), b.gid()));
        }
    }
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT (local Alpine OCI)"]
fn changed_stage_dependency_invalidates_consumers() {
    let mut p = Project::new("python");
    p.write("Dockerfile", "FROM alpine AS dependencies\nCOPY requirements.txt /requirements\nRUN printf 'IC_EXEC_%s\\n' dependencies; cp /requirements /installed\nFROM alpine\nCOPY --from=dependencies /installed /installed\nRUN printf 'IC_EXEC_%s\\n' consumer; cat /installed > /result; head -c 32 /dev/urandom | od -An -tx1 > /nonce\n");
    let cold = p.build(&[]);
    cold.ok();
    let warm = p.build(&[]);
    warm.ok();
    assert!(!warm.executed("consumer"), "{}", warm.log);
    p.write("requirements.txt", "changed-stage-input\n");
    let changed = p.build(&[]);
    changed.ok();
    assert!(
        changed.executed("dependencies") && changed.executed("consumer"),
        "{}",
        changed.log
    );
    assert_eq!(changed.read("result"), b"changed-stage-input\n");
    assert_ne!(cold.read("nonce"), changed.read("nonce"));
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT (local Alpine OCI)"]
fn changed_base_digest_invalidates_same_dockerfile() {
    let mut p = Project::new("python");
    p.write("Dockerfile", "FROM alpine\nENV BASE_VERSION=one\n");
    let base_one = p.build(&[]);
    base_one.ok();
    p.write("Dockerfile", "FROM alpine\nENV BASE_VERSION=two\n");
    let base_two = p.build(&[]);
    base_two.ok();
    p.write("Dockerfile", "FROM alpine\nRUN printf 'IC_EXEC_%s\\n' base; printf '%s' \"$BASE_VERSION\" > /version; head -c 32 /dev/urandom | od -An -tx1 > /nonce\n");
    p.base = base_one.image;
    let first = p.build(&[]);
    first.ok();
    let warm = p.build(&[]);
    warm.ok();
    assert!(!warm.executed("base"), "{}", warm.log);
    p.base = base_two.image;
    let changed = p.build(&[]);
    changed.ok();
    assert!(changed.executed("base"), "{}", changed.log);
    assert_eq!(first.read("version"), b"one");
    assert_eq!(changed.read("version"), b"two");
    assert_ne!(first.read("nonce"), changed.read("nonce"));
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT (local Alpine OCI)"]
fn failed_and_cancelled_runs_do_not_publish_success_or_replace_tag() {
    for cancel in [false, true] {
        let mut p = Project::new("python");
        let good = p.build(&[]);
        good.ok();
        let tag = p.tag();
        let prefix = "FROM alpine\nCOPY requirements.txt /requirements\nRUN printf 'IC_EXEC_%s\\n' prefix; cp /requirements /installed\n";
        let failing = if cancel {
            "RUN printf 'IC_EXEC_%s\\n' incomplete; touch /cancel-ready; sleep 30\n"
        } else {
            "RUN printf 'IC_EXEC_%s\\n' incomplete; exit 7\n"
        };
        p.write("Dockerfile", &format!("{prefix}{failing}"));
        let failed = p.build_inner(&[], cancel);
        assert!(!failed.success, "{}", failed.log);
        assert!(!failed.image.exists(), "failed build exported an image");
        assert_eq!(tag, p.tag(), "failure replaced the previous tag");
        assert!(!failed.log.contains("Tagged "), "{}", failed.log);
        let again = p.build_inner(&[], cancel);
        assert!(!again.success, "{}", again.log);
        assert!(
            again.executed("incomplete"),
            "failed instruction was reused: {}",
            again.log
        );
        again.cached(3, "RUN");
        assert!(
            !again.executed("prefix"),
            "successful prefix was lost: {}",
            again.log
        );
        assert_eq!(tag, p.tag());
        p.write(
            "Dockerfile",
            &format!("{prefix}RUN printf 'IC_EXEC_%s\\n' recovery; cp /installed /result\n"),
        );
        let recovered = p.build(&[]);
        recovered.ok();
        recovered.cached(3, "RUN");
        assert!(recovered.executed("recovery"), "{}", recovered.log);
        assert_eq!(recovered.read("result"), b"offline-example==1\n");
    }
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT (local Alpine OCI)"]
fn checkpoint_export_preserves_directory_access_time_seen_by_later_runs() {
    let mut p = Project::new("python");
    let dockerfile = |version: &str| {
        format!(
            "FROM alpine\nRUN mkdir /timed && TZ=UTC touch -a -t 200001010000.00 /timed\nRUN printf 'IC_EXEC_%s\\n' observe; stat -c %X /timed > /observed; printf '%s' {version} > /version\n"
        )
    };
    p.write("Dockerfile", &dockerfile("one"));
    let cold = p.build(&[]);
    cold.ok();
    p.write("Dockerfile", &dockerfile("two"));
    let prefix_hit = p.build(&[]);
    prefix_hit.ok();
    prefix_hit.cached(2, "RUN");
    assert!(prefix_hit.executed("observe"), "{}", prefix_hit.log);
    let reference = p.build(&["--no-cache"]);
    reference.ok();
    assert_eq!(reference.read("observed"), b"946684800\n");
    assert_eq!(
        cold.read("observed"),
        reference.read("observed"),
        "cold checkpoint export changed observable directory atime"
    );
    assert_eq!(
        prefix_hit.read("observed"),
        reference.read("observed"),
        "prefix replay changed observable directory atime"
    );
    assert_eq!(prefix_hit.read("version"), b"two");
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT (local Alpine OCI)"]
fn copy_through_destination_directory_symlink_keeps_supported_semantics() {
    let mut p = Project::new("python");
    p.write("payload", "first payload\n");
    p.write("Dockerfile", "FROM alpine\nRUN mkdir /real && ln -s /real /link\nCOPY payload /link/payload\nRUN printf 'IC_EXEC_%s\\n' consume; cat /real/payload > /result; head -c 32 /dev/urandom | od -An -tx1 > /nonce\n");
    let cold = p.build(&[]);
    cold.ok();
    assert_eq!(cold.read("result"), b"first payload\n");
    assert_eq!(
        fs::read_link(cold.root.join("link")).unwrap(),
        Path::new("/real")
    );
    let warm = p.build(&[]);
    warm.ok();
    assert!(!warm.executed("consume"), "{}", warm.log);
    assert_eq!(cold.read("nonce"), warm.read("nonce"));
    p.write("payload", "second payload\n");
    let changed = p.build(&[]);
    changed.ok();
    assert!(changed.executed("consume"), "{}", changed.log);
    assert_eq!(changed.read("result"), b"second payload\n");
    assert_ne!(cold.read("nonce"), changed.read("nonce"));
    let reference = p.build(&["--no-cache"]);
    reference.ok();
    assert_eq!(changed.read("result"), reference.read("result"));
    assert_eq!(changed.config(), reference.config());
    assert_eq!(
        fs::read_link(reference.root.join("link")).unwrap(),
        Path::new("/real")
    );
    let again = p.build(&[]);
    again.ok();
    assert!(!again.executed("consume"), "{}", again.log);
    assert_eq!(changed.read("nonce"), again.read("nonce"));
}

#[test]
#[ignore = "requires Linux root and RPWELD_TEST_LAYOUT (local Alpine OCI)"]
fn stage_copy_preserves_exported_directory_atime_with_and_without_cache() {
    // Inspect the delivered OCI layer, not a disposable work tree that export
    // itself may read. The consumer must receive the producer's old atime.
    fn stamp_atime(build: &Build) -> String {
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(build.image.join("index.json")).unwrap()).unwrap();
        let blob = |descriptor: &serde_json::Value| {
            let digest = descriptor["digest"].as_str().unwrap();
            build
                .image
                .join("blobs/sha256")
                .join(digest.strip_prefix("sha256:").unwrap())
        };
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(blob(&index["manifests"][0])).unwrap()).unwrap();
        let layers = manifest["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 1, "expected flattened output");
        let bytes = fs::read(blob(&layers[0])).unwrap();
        let reader: Box<dyn std::io::Read> = if bytes.starts_with(&[0x1f, 0x8b]) {
            Box::new(flate2::read::GzDecoder::new(std::io::Cursor::new(bytes)))
        } else {
            Box::new(std::io::Cursor::new(bytes))
        };
        let mut archive = tar::Archive::new(reader);
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().as_ref() != Path::new("stamp") {
                continue;
            }
            assert!(entry.header().entry_type().is_dir());
            for extension in entry
                .pax_extensions()
                .unwrap()
                .expect("directory PAX metadata")
            {
                let extension = extension.unwrap();
                if extension.key().unwrap() == "atime" {
                    return extension.value().unwrap().to_owned();
                }
            }
            panic!("stamp has no exported atime");
        }
        panic!("stamp missing from exported image");
    }

    let mut p = Project::new("python");
    p.write("Dockerfile", "FROM alpine AS producer\nRUN printf 'IC_EXEC_%s\\n' producer; mkdir /stamp && TZ=UTC touch -a -t 200001010000.00 /stamp\nFROM scratch\nCOPY --from=producer /stamp /stamp\n");
    let cold = p.build(&[]);
    cold.ok();
    assert!(cold.executed("producer"), "{}", cold.log);
    let warm = p.build(&[]);
    warm.ok();
    assert!(!warm.executed("producer"), "{}", warm.log);
    assert!(warm.log.contains("CACHED"), "{}", warm.log);
    let reference = p.build(&["--no-cache"]);
    reference.ok();
    assert!(reference.executed("producer"), "{}", reference.log);
    assert!(!reference.log.contains("CACHED"), "{}", reference.log);
    let cold_atime = stamp_atime(&cold);
    assert_eq!(cold_atime.parse::<f64>().unwrap(), 946684800.0);
    assert_eq!(
        stamp_atime(&warm),
        cold_atime,
        "warm export metadata differs"
    );
    assert_eq!(
        stamp_atime(&reference),
        cold_atime,
        "uncached stage COPY observed producer export's directory read"
    );
}
