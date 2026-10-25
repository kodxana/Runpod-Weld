#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::os::unix::{fs::MetadataExt, process::CommandExt};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    temp: tempfile::TempDir,
    context: PathBuf,
    number: usize,
    child_umask: Option<libc::mode_t>,
    cache: bool,
}

impl Fixture {
    fn new(source: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let context = temp.path().join("context");
        fs::create_dir(&context).unwrap();
        for name in ["passwd", "group", "payload"] {
            fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/user")
                    .join(name),
                context.join(name),
            )
            .unwrap();
        }
        fs::write(context.join("Dockerfile"), source).unwrap();
        Self {
            temp,
            context,
            number: 0,
            child_umask: None,
            cache: false,
        }
    }

    fn source(&self, source: &str) {
        fs::write(self.context.join("Dockerfile"), source).unwrap();
    }

    fn build(&mut self, base: Option<&Path>, drop_cap: Option<u32>) -> (Output, PathBuf, PathBuf) {
        self.number += 1;
        let out = self.temp.path().join(format!("out-{}", self.number));
        let work = self.temp.path().join(format!("work-{}", self.number));
        let mut command = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        command
            .env("RPWELD_HOME", self.temp.path().join("store"))
            .env("HOME", self.temp.path())
            .args([
                "build",
                "--platform",
                "linux/amd64",
                "--run-timeout-seconds",
                "20",
            ])
            .arg("--output")
            .arg(&out)
            .arg("--work-dir")
            .arg(&work);
        if let Some(base) = base {
            command
                .arg("--base")
                .arg(format!("alpine={}", base.display()));
        }
        if self.cache {
            command.args(["-t", "test/user-qa:latest", "--no-host-dns"]);
        }
        command.arg(&self.context);
        let child_umask = self.child_umask;
        // Drop only in the child. Bounding-set removal prevents exec restoring this capability.
        unsafe {
            command.pre_exec(move || {
                if let Some(mask) = child_umask {
                    libc::umask(mask);
                }
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(cap) = drop_cap
                    && libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let stdout = tempfile::tempfile().unwrap();
        let stderr = tempfile::tempfile().unwrap();
        command
            .stdout(Stdio::from(stdout.try_clone().unwrap()))
            .stderr(Stdio::from(stderr.try_clone().unwrap()));
        let mut child = command.spawn().unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > Duration::from_secs(120) {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                child.wait().unwrap();
                panic!("USER build exceeded 120-second process-group deadline");
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        use std::io::{Read, Seek};
        let read = |mut file: fs::File| {
            file.rewind().unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            bytes
        };
        (
            Output {
                status,
                stdout: read(stdout),
                stderr: read(stderr),
            },
            out,
            work.join("rootfs"),
        )
    }
}

// Inspect the emitted OCI tar independently of Weld's filesystem/replay APIs.
fn root_header_modes(layout: &Path) -> Vec<u32> {
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(layout.join("index.json")).unwrap()).unwrap();
    let blob = |digest: &str| layout.join("blobs").join(digest.replace(':', "/"));
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(blob(index["manifests"][0]["digest"].as_str().unwrap())).unwrap(),
    )
    .unwrap();
    let mut modes = Vec::new();
    for layer in manifest["layers"].as_array().unwrap() {
        let bytes = fs::read(blob(layer["digest"].as_str().unwrap())).unwrap();
        let input: Box<dyn std::io::Read> = if bytes.starts_with(&[0x1f, 0x8b]) {
            Box::new(flate2::read::GzDecoder::new(&bytes[..]))
        } else {
            Box::new(&bytes[..])
        };
        for entry in tar::Archive::new(input).entries().unwrap() {
            let entry = entry.unwrap();
            let path = entry.path().unwrap();
            if entry.header().entry_type().is_dir()
                && (path == Path::new(".") || path == Path::new("/") || path.as_os_str().is_empty())
            {
                modes.push(entry.header().mode().unwrap() & 0o7777);
            }
        }
    }
    modes
}

// Append an independent OCI layer containing only an explicit root directory.
fn with_root_mode(base: &Path, destination: &Path, mode: u32) {
    use sha2::{Digest, Sha256};
    let blobs = destination.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    for entry in fs::read_dir(base.join("blobs/sha256")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), blobs.join(entry.file_name())).unwrap();
    }
    fs::copy(base.join("oci-layout"), destination.join("oci-layout")).unwrap();
    let write_blob = |bytes: &[u8]| {
        let hash = format!("{:x}", Sha256::digest(bytes));
        fs::write(blobs.join(&hash), bytes).unwrap();
        (format!("sha256:{hash}"), bytes.len())
    };
    let mut index: serde_json::Value =
        serde_json::from_slice(&fs::read(base.join("index.json")).unwrap()).unwrap();
    let read_blob =
        |digest: &str| fs::read(base.join("blobs").join(digest.replace(':', "/"))).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_slice(&read_blob(
        index["manifests"][0]["digest"].as_str().unwrap(),
    ))
    .unwrap();
    let mut config: serde_json::Value =
        serde_json::from_slice(&read_blob(manifest["config"]["digest"].as_str().unwrap())).unwrap();
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_path(".").unwrap();
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_size(0);
    header.set_mtime(0);
    header.set_cksum();
    let mut archive = tar::Builder::new(Vec::new());
    archive.append(&header, std::io::empty()).unwrap();
    let layer = archive.into_inner().unwrap();
    let (digest, size) = write_blob(&layer);
    config["rootfs"]["diff_ids"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(digest));
    if let Some(history) = config["history"].as_array_mut() {
        history.push(serde_json::json!({"created_by":"independent QA explicit root directory"}));
    }
    manifest["layers"].as_array_mut().unwrap().push(serde_json::json!({"mediaType":"application/vnd.oci.image.layer.v1.tar", "digest":digest, "size":size}));
    let (digest, size) = write_blob(&serde_json::to_vec(&config).unwrap());
    manifest["config"]["digest"] = digest.into();
    manifest["config"]["size"] = size.into();
    let (digest, size) = write_blob(&serde_json::to_vec(&manifest).unwrap());
    index["manifests"][0]["digest"] = digest.into();
    index["manifests"][0]["size"] = size.into();
    fs::write(
        destination.join("index.json"),
        serde_json::to_vec(&index).unwrap(),
    )
    .unwrap();
}

#[test]
fn root_mode_export_cache_and_inheritance_do_not_depend_on_child_umask() {
    for mask in [0o022, 0o077] {
        let mut f = Fixture::new(
            "FROM scratch AS first\nCOPY payload /payload\nFROM first\nCOPY payload /second\n",
        );
        f.child_umask = Some(mask);
        f.cache = true;
        for attempt in 0..2 {
            let (r, out, root) = f.build(None, None);
            success(&r);
            if attempt == 1 {
                assert!(
                    String::from_utf8_lossy(&r.stderr).contains("CACHED (verified local stage)"),
                    "repeat must exercise stage-cache replay: {}",
                    String::from_utf8_lossy(&r.stderr)
                );
            }
            assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o755);
            assert_eq!(root_header_modes(&out).last(), Some(&0o755));
            if mask == 0o077 {
                assert_eq!(
                    fs::metadata(root.parent().unwrap()).unwrap().mode() & 0o777,
                    0o700
                );
            }
        }
        let checkpoints: Vec<_> = fs::read_dir(f.temp.path().join("store/cache-v1"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.join("index.json").is_file())
            .collect();
        assert!(
            !checkpoints.is_empty(),
            "cache must actually publish OCI checkpoints"
        );
        for checkpoint in checkpoints {
            assert_eq!(root_header_modes(&checkpoint).last(), Some(&0o755));
        }
    }
}

#[test]
#[ignore = "requires root, native Linux filesystem and Alpine OCI without a root header"]
fn real_user_under_umask_022_and_077_respects_missing_and_explicit_root_modes() {
    let base = alpine();
    assert!(
        root_header_modes(&base).is_empty(),
        "this regression needs an OCI base that omits the root header"
    );
    for mask in [0o022, 0o077] {
        let mut f = Fixture::new(include_str!("fixtures/user/Dockerfile.runtime"));
        f.child_umask = Some(mask);
        f.cache = true;
        let (r, out, root) = f.build(Some(&base), None);
        success(&r);
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o755);
        assert_eq!(root_header_modes(&out).last(), Some(&0o755));
        assert_eq!(
            fs::metadata(root.join("qa/inherited")).unwrap().uid(),
            12001
        );
        f.source("FROM alpine\nRUN test \"$(id -u)\" = 12001 && test \"$(stat -c %a /)\" = 755 && touch /qa/umask-roundtrip\n");
        let (r, _, _) = f.build(Some(&out), None);
        success(&r);
        for mode in [0o755, 0o700] {
            let explicit = f.temp.path().join(format!("explicit-{mode:o}"));
            with_root_mode(&base, &explicit, mode);
            f.source("FROM alpine\nUSER 23456:23457\n");
            let (r, exported, root) = f.build(Some(&explicit), None);
            success(&r);
            assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, mode);
            assert_eq!(root_header_modes(&exported).last(), Some(&mode));
            f.source(
                "FROM alpine\nRUN test \"$(id -u)\" = 23456 && touch /tmp/root-mode-application\n",
            );
            let (r, _, root) = f.build(Some(&exported), None);
            if mode == 0o755 {
                success(&r);
                assert_eq!(
                    fs::metadata(root.join("tmp/root-mode-application"))
                        .unwrap()
                        .uid(),
                    23456
                );
            } else {
                assert!(
                    !r.status.success(),
                    "explicit restrictive root mode must not be widened"
                );
                assert!(!root.join("tmp/root-mode-application").exists());
            }
        }
    }
}

fn success(result: &Output) {
    assert!(
        result.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

fn config(layout: &Path) -> serde_json::Value {
    let read =
        |path| serde_json::from_slice::<serde_json::Value>(&fs::read(path).unwrap()).unwrap();
    let blob = |digest: &str| layout.join("blobs").join(digest.replace(':', "/"));
    let index = read(layout.join("index.json"));
    let manifest = read(blob(index["manifests"][0]["digest"].as_str().unwrap()));
    read(blob(manifest["config"]["digest"].as_str().unwrap()))
}

fn alpine() -> PathBuf {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "real RUN suite requires Linux root"
    );
    let path = PathBuf::from(
        std::env::var_os("RPWELD_TEST_LAYOUT")
            .expect("set RPWELD_TEST_LAYOUT to an existing local Alpine OCI layout"),
    );
    assert!(path.join("index.json").is_file());
    path
}

#[test]
fn user_metadata_unknown_names_stage_and_oci_roundtrip() {
    let mut f = Fixture::new(
        "FROM scratch AS first\nUSER absent:missing\nFROM first AS final\nCMD [\"/bin/true\"]\n",
    );
    let (r, out, _) = f.build(None, None);
    success(&r);
    assert_eq!(config(&out)["config"]["User"], "absent:missing");
    f.source("FROM alpine\nCMD [\"/bin/false\"]\n");
    let (r, inherited, _) = f.build(Some(&out), None);
    success(&r);
    assert_eq!(config(&inherited)["config"]["User"], "absent:missing");
    f.source("FROM alpine AS first\nFROM scratch\nCMD [\"/bin/true\"]\n");
    let (r, reset, _) = f.build(Some(&out), None);
    success(&r);
    assert!(
        config(&reset)["config"]["User"]
            .as_str()
            .unwrap_or("")
            .is_empty()
    );
}

#[test]
#[ignore = "requires root, real Linux credentials and RPWELD_TEST_LAYOUT"]
fn real_user_groups_home_workdir_denial_and_separate_run_restoration() {
    let base = alpine();
    let mut f = Fixture::new(include_str!("fixtures/user/Dockerfile.runtime"));
    let (r, out, root) = f.build(Some(&base), None);
    success(&r);
    assert_eq!(config(&out)["config"]["User"], "alice:chosen");
    for (file, uid, gid) in [
        ("qa/alice", 12001, 12002),
        ("qa/explicit", 12001, 12006),
        ("qa/numeric", 23456, 0),
        ("qa/copied", 23456, 23456),
        ("qa/bob", 12003, 12004),
        ("qa/inherited", 12001, 12006),
        ("root-only/after", 0, 0),
    ] {
        let metadata = fs::metadata(root.join(file)).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (uid, gid), "{file}");
    }
    assert!(!root.join("root-only/forbidden").exists());
    // Reimport the emitted OCI image and execute, proving config and filesystem roundtrip.
    f.source("FROM alpine\nRUN test \"$(id -u)\" = 12001 && test \"$(id -g)\" = 12006 && test \"$HOME\" = /explicit-home && touch /qa/roundtrip\n");
    let (r, _, root) = f.build(Some(&out), None);
    success(&r);
    assert_eq!(
        fs::metadata(root.join("qa/roundtrip")).unwrap().uid(),
        12001
    );
}

#[test]
#[ignore = "requires root and RPWELD_TEST_LAYOUT"]
fn unknown_names_fail_at_run_before_application() {
    let base = alpine();
    for user in ["absent", "12001:missing"] {
        let mut f = Fixture::new(&format!("FROM alpine\nUSER {user}\n"));
        let (r, _, _) = f.build(Some(&base), None);
        success(&r);
        f.source(&format!(
            "FROM alpine\nUSER {user}\nRUN touch /application-started\n"
        ));
        let (r, out, root) = f.build(Some(&base), None);
        assert!(!r.status.success());
        assert!(!root.join("application-started").exists());
        assert!(!out.join("index.json").exists());
        let error = String::from_utf8_lossy(&r.stderr).to_lowercase();
        assert!(error.contains("user") || error.contains("group"), "{error}");
    }
}

#[test]
#[ignore = "requires root with CAP_SETPCAP/SETUID/SETGID and RPWELD_TEST_LAYOUT"]
fn missing_setuid_or_setgid_fails_before_application() {
    let base = alpine();
    let source = "FROM alpine\nUSER 23456:23457\nRUN touch /tmp/application-started\n";
    let mut control = Fixture::new(source);
    let (r, _, root) = control.build(Some(&base), None);
    success(&r);
    assert_eq!(
        fs::metadata(root.join("tmp/application-started"))
            .unwrap()
            .uid(),
        23456
    );
    for cap in [6, 7] {
        // Linux CAP_SETGID, CAP_SETUID.
        let mut f = Fixture::new(source);
        let (r, out, root) = f.build(Some(&base), Some(cap));
        assert!(
            !r.status.success(),
            "build succeeded without capability {cap}"
        );
        assert!(!root.join("tmp/application-started").exists());
        assert!(!out.join("index.json").exists());
        let error = String::from_utf8_lossy(&r.stderr).to_lowercase();
        assert!(
            error.contains("cap") || error.contains("permission") || error.contains("permitted"),
            "{error}"
        );
    }
}

#[test]
#[ignore = "requires root and RPWELD_TEST_LAYOUT"]
fn cache_user_and_account_changes_preserve_real_identity() {
    let base = alpine();
    let source = |user| {
        format!(
            "FROM alpine\nCOPY passwd /etc/passwd\nCOPY group /etc/group\nUSER {user}\nRUN id -u > /tmp/observed-uid && id -g > /tmp/observed-gid && id -G > /tmp/observed-groups\n"
        )
    };
    let mut f = Fixture::new(&source("alice"));
    f.cache = true;
    for (user, uid, gid) in [
        ("alice", "12001", "12002"),
        ("bob", "12003", "12004"),
        ("alice", "12001", "12002"),
    ] {
        f.source(&source(user));
        let (r, out, root) = f.build(Some(&base), None);
        success(&r);
        assert_eq!(config(&out)["config"]["User"], user);
        assert_eq!(
            fs::read_to_string(root.join("tmp/observed-uid"))
                .unwrap()
                .trim(),
            uid
        );
        assert_eq!(
            fs::read_to_string(root.join("tmp/observed-gid"))
                .unwrap()
                .trim(),
            gid
        );
    }
    let passwd = fs::read_to_string(f.context.join("passwd"))
        .unwrap()
        .replace("12001:12002", "12011:12012");
    fs::write(f.context.join("passwd"), passwd).unwrap();
    for attempt in 0..2 {
        let (r, _, root) = f.build(Some(&base), None);
        success(&r);
        if attempt == 1 {
            let log = String::from_utf8_lossy(&r.stderr);
            assert!(
                log.contains("CACHED (verified local stage)")
                    || log
                        .lines()
                        .any(|line| line.contains("CACHED instruction") && line.ends_with("RUN")),
                "unchanged account repeat must replay RUN or its completed stage: {log}"
            );
        }
        assert_eq!(
            fs::read_to_string(root.join("tmp/observed-uid"))
                .unwrap()
                .trim(),
            "12011"
        );
        assert_eq!(
            fs::read_to_string(root.join("tmp/observed-gid"))
                .unwrap()
                .trim(),
            "12012"
        );
    }
    let group = fs::read_to_string(f.context.join("group"))
        .unwrap()
        .replace("12005", "12015");
    fs::write(f.context.join("group"), group).unwrap();
    let (r, _, root) = f.build(Some(&base), None);
    success(&r);
    let groups = fs::read_to_string(root.join("tmp/observed-groups")).unwrap();
    assert!(groups.split_whitespace().any(|group| group == "12015"));
    assert!(!groups.split_whitespace().any(|group| group == "12005"));
    assert!(
        fs::read_dir(f.temp.path().join("store/cache-v1"))
            .unwrap()
            .any(|entry| entry.unwrap().path().join("index.json").is_file())
    );
}
