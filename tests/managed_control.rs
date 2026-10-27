#![cfg(target_os = "linux")]

#[test]
fn pre_admission_stdio_corruption_is_fully_rejected_without_publication() {
    use std::{fs, process::Command};
    for mode in ["plain", "quiet"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let base = temp.path().join("base");
        let context = temp.path().join("context");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&context).unwrap();
        fs::write(root.join("payload"), b"base bytes").unwrap();
        let manifest = rpweld::export::export_layout(
            &root,
            &base,
            &serde_json::json!({"architecture":"amd64", "os":"linux", "config":{}}),
            rpweld::export::Limits {
                max_layer_bytes: 1024 * 1024,
                max_entries: 32,
                max_metadata_bytes: 1024 * 1024,
            },
            || false,
        )
        .unwrap();
        let blob = |digest: &str| {
            base.join("blobs/sha256")
                .join(digest.strip_prefix("sha256:").unwrap())
        };
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(blob(&manifest.digest)).unwrap()).unwrap();
        let payload = blob(metadata["layers"][0]["digest"].as_str().unwrap());
        let before = fs::read(&payload).unwrap();
        let sink = fs::OpenOptions::new().append(true).open(&payload).unwrap();
        fs::write(context.join("Dockerfile"), "FROM local\n").unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .env("RPWELD_HOME", temp.path().join("store"))
            .args([
                "build",
                "-t",
                "test/pre-admission",
                "--progress",
                mode,
                "--base",
            ])
            .arg(format!("local={}", base.display()))
            .arg("--work-dir")
            .arg(temp.path().join("work"))
            .arg("--output")
            .arg(temp.path().join("image"))
            .arg(context)
            .stdout(sink.try_clone().unwrap())
            .output()
            .unwrap();
        assert!(!result.status.success());
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(
            error.contains("image blob: expected") && error.contains("observed"),
            "{error}"
        );
        // No session evidence existed when CLI preflight wrote to this caller sink.
        assert!(fs::read(payload).unwrap().len() > before.len());
        assert!(!temp.path().join("image/index.json").exists());
        assert!(!temp.path().join("store/cache-v2/entries").exists());
    }
}

#[test]
fn actual_guard_closes_payload_above_lowered_soft_limit_and_workload_closes_lease() {
    use std::{
        io,
        os::{fd::AsRawFd, unix::process::CommandExt},
        process::Command,
    };
    let lease = tempfile::NamedTempFile::new().unwrap();
    let payload = tempfile::tempfile().unwrap();
    let lease_fd = lease.as_raw_fd();
    let payload_fd = payload.as_raw_fd();
    assert_eq!(unsafe { libc::flock(lease_fd, libc::LOCK_SH) }, 0);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
    cmd.args([
        "__lease-guard",
        &lease_fd.to_string(),
        "--",
        "/bin/sh",
        "-c",
    ])
    .arg(format!(
        "test ! -e /proc/self/fd/1024 && test ! -e /proc/self/fd/{lease_fd}"
    ));
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(payload_fd, 1024) < 0 || libc::fcntl(lease_fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut limit = std::mem::MaybeUninit::uninit();
            if libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut limit = limit.assume_init();
            limit.rlim_cur = 128;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let result = cmd.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[ignore = "requires root, cc -static and child ptrace"]
fn actual_managed_build_worker_chain_closes_inherited_payload_handles() {
    use std::{
        fs, io,
        os::{
            fd::AsRawFd,
            unix::{fs::MetadataExt, process::CommandExt},
        },
        process::Command,
    };
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    let payload = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
    let identity = payload.as_file().metadata().unwrap();
    let source = temp.path().join("probe.c");
    fs::write(
        &source,
        format!(
            r#"
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
int main(void) {{
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur >= 1024) return 20;
    for (int fd = 0; fd < 4096; ++fd) {{
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_dev == {}ULL && st.st_ino == {}ULL) return 21;
    }}
    if (fcntl(1024, F_GETFD) != -1 || errno != EBADF) return 22;
    int proof = open("/fd-proof", O_WRONLY | O_CREAT, 0600);
    if (proof < 0) return 23;
    return close(proof) ? 24 : 0;
}}
"#,
            identity.dev(),
            identity.ino()
        ),
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-static", "-O2", "-o"])
            .arg(context.join("probe"))
            .arg(source)
            .status()
            .unwrap()
            .success()
    );
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY probe /bin/sh\nRUN inspect inherited descriptors\n",
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
    cmd.env("RPWELD_HOME", temp.path().join("store"))
        .args([
            "build",
            "-t",
            "test/worker-fds",
            "--no-cache",
            "--no-host-dns",
            "--work-dir",
        ])
        .arg(temp.path().join("work"))
        .arg("--output")
        .arg(temp.path().join("image"))
        .arg(context);
    let fd = payload.as_file().as_raw_fd();
    unsafe {
        cmd.pre_exec(move || {
            // Non-CLOEXEC deliberately tests guard closure, including descriptors
            // above soft NOFILE. Production session handles are also CLOEXEC.
            if libc::dup2(fd, 1024) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut limit = std::mem::MaybeUninit::uninit();
            if libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut limit = limit.assume_init();
            limit.rlim_cur = 128;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let result = cmd.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(temp.path().join("work/rootfs/fd-proof").is_file());
}

#[test]
#[ignore = "requires root, cc -static, procfs and child ptrace"]
fn cached_managed_runs_close_retained_session_payload_handles() {
    use std::{
        collections::BTreeSet,
        fs,
        io::Read,
        os::unix::{fs::MetadataExt, process::CommandExt},
        path::Path,
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    // Let the builder cancel and its detached lease guard reap before escalation.
    struct RunningBuild(Child);
    impl Drop for RunningBuild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            // SAFETY: the unreaped child owns the process group created below.
            unsafe { libc::kill(-(self.0.id() as i32), libc::SIGINT) };
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if self.0.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
            // SAFETY: the child remains unreaped, so its PID cannot be reused.
            unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn identity(path: &Path) -> (u64, u64) {
        let metadata = fs::metadata(path).unwrap();
        assert!(metadata.is_file(), "{}", path.display());
        (metadata.dev(), metadata.ino())
    }

    fn load(path: &Path) -> rpweld::image::ImageMetadata {
        rpweld::image::load_layout(
            path,
            None,
            rpweld::image::Limits {
                max_metadata_bytes: 1024 * 1024,
                max_total_metadata_bytes: 4 * 1024 * 1024,
                max_descriptors: 64,
                max_layer_bytes: 4 * 1024 * 1024,
                max_total_layer_bytes: 16 * 1024 * 1024,
            },
            || false,
        )
        .unwrap()
    }

    // SAFETY: geteuid has no preconditions.
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    let work = temp.path().join("work");
    let root = work.join("rootfs");
    let store = temp.path().join("store");
    let image = temp.path().join("image");
    let stderr = temp.path().join("stderr");
    fs::create_dir(&context).unwrap();
    let source = temp.path().join("probe.c");
    fs::write(
        &source,
        r#"#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 20;
    int step = strcmp(argv[2], "exec '/bin/sh' '-c' '1'") == 0 ? 1 :
               strcmp(argv[2], "exec '/bin/sh' '-c' '2'") == 0 ? 2 : 0;
    if (step != 1 && step != 2) return 21;
    char ready[32], release[32], proof[32];
    snprintf(ready, sizeof ready, "/ready-%d", step);
    snprintf(release, sizeof release, "/release-%d", step);
    snprintf(proof, sizeof proof, "/proof-%d", step);
    int fd = open(ready, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || close(fd)) return 22;
    int attempts = 0;
    while (access(release, F_OK)) {
        if (++attempts > 2000) return 23;
        usleep(10000);
    }
    FILE *input = fopen(release, "r");
    if (!input) return 24;
    unsigned long long dev, ino;
    int count = 0, parsed;
    while ((parsed = fscanf(input, "%llu %llu", &dev, &ino)) == 2) {
        DIR *fds = opendir("/proc/self/fd");
        if (!fds) return 25;
        struct dirent *entry;
        while ((entry = readdir(fds))) {
            char *end;
            long candidate = strtol(entry->d_name, &end, 10);
            if (*end || candidate < 0) continue;
            struct stat st;
            if (fstat((int)candidate, &st)) return 26;
            if (st.st_dev == dev && st.st_ino == ino) return 27;
        }
        if (closedir(fds)) return 28;
        ++count;
    }
    if (parsed != EOF || count < 2 || fclose(input)) return 29;
    FILE *output = fopen(proof, "wx");
    if (!output || fprintf(output, "%d\n", count) < 0 || fclose(output)) return 30;
    return 0;
}
"#,
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(context.join("probe"))
            .arg(source)
            .status()
            .unwrap()
            .success()
    );
    fs::write(context.join("later"), b"after both RUNs\n").unwrap();
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY probe /bin/sh\nRUN 1\nRUN 2\nCOPY later /later\n",
    )
    .unwrap();
    let mut child = RunningBuild(
        Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .env("RPWELD_HOME", &store)
            .args([
                "build",
                "-t",
                "test/session-fds",
                "--export-mode",
                "layered",
                "--progress",
                "quiet",
                "--no-host-dns",
                "--run-timeout-seconds",
                "30",
                "--work-dir",
            ])
            .arg(&work)
            .arg("--output")
            .arg(&image)
            .arg(&context)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&stderr).unwrap())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let error = || {
        let mut text = String::new();
        fs::File::open(&stderr)
            .unwrap()
            .take(16 * 1024)
            .read_to_string(&mut text)
            .unwrap();
        text
    };
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut earlier = BTreeSet::new();
    for step in 1..=2 {
        while !root.join(format!("ready-{step}")).is_file() {
            assert!(child.0.try_wait().unwrap().is_none(), "{}", error());
            assert!(
                Instant::now() < deadline,
                "RUN {step} never gated: {}",
                error()
            );
            thread::sleep(Duration::from_millis(20));
        }
        let checkpoint = work.join(format!("checkpoint-image-{}", step + 1));
        let metadata = load(&checkpoint);
        assert_eq!(metadata.layers.len(), step);
        let entries: Vec<_> = fs::read_dir(store.join("cache-v2/entries"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(
            entries.len(),
            step,
            "RUN must follow completed publications"
        );
        assert!(
            entries
                .iter()
                .any(|entry| load(entry).selected == metadata.selected)
        );

        let mut payloads = BTreeSet::new();
        for layer in &metadata.layers {
            let relative = Path::new("blobs").join(layer.digest.replace(':', "/"));
            let source = identity(&checkpoint.join(&relative));
            let cached = identity(&store.join("cache-v2/content").join(&relative));
            assert_ne!(
                source, cached,
                "source must not alias cache: {}",
                layer.digest
            );
            payloads.extend([source, cached]);
        }
        assert_eq!(payloads.len(), step * 2);
        assert!(
            earlier.is_subset(&payloads),
            "earlier payload identities changed"
        );
        let held: BTreeSet<_> = fs::read_dir(format!("/proc/{}/fd", child.0.id()))
            .unwrap()
            .filter_map(|entry| fs::metadata(entry.unwrap().path()).ok())
            .filter(|metadata| metadata.is_file())
            .map(|metadata| (metadata.dev(), metadata.ino()))
            .collect();
        assert!(
            payloads.is_subset(&held),
            "RUN {step}: builder did not retain source and cache payloads: {payloads:?}; held {held:?}"
        );
        let release = payloads
            .iter()
            .map(|(dev, ino)| format!("{dev} {ino}\n"))
            .collect::<String>();
        let pending = root.join("release-pending");
        fs::write(&pending, release).unwrap();
        fs::rename(pending, root.join(format!("release-{step}"))).unwrap();
        earlier = payloads;
    }
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "build did not finish: {}",
            error()
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "{}", error());
    for step in 1..=2 {
        assert_eq!(
            fs::read_to_string(root.join(format!("proof-{step}"))).unwrap(),
            format!("{}\n", step * 2),
            "application must inspect every admitted payload identity"
        );
    }
    assert_eq!(fs::read(root.join("later")).unwrap(), b"after both RUNs\n");
    let published = load(&image);
    assert_eq!(published.layers.len(), 4);
    for ordinal in 2..=5 {
        let checkpoint = work.join(format!("checkpoint-image-{ordinal}"));
        let metadata = load(&checkpoint);
        assert_eq!(metadata.layers, published.layers[..ordinal - 1]);
        for layer in metadata.layers {
            let relative = Path::new("blobs").join(layer.digest.replace(':', "/"));
            let source = identity(&checkpoint.join(&relative));
            let cached = identity(&store.join("cache-v2/content").join(&relative));
            let public = identity(&image.join(&relative));
            assert_ne!(source, cached);
            assert_ne!(public, source, "public output aliases private checkpoint");
            assert_ne!(public, cached, "public output aliases managed cache");
        }
    }
    let entries: Vec<_> = fs::read_dir(store.join("cache-v2/entries"))
        .unwrap()
        .map(|entry| load(&entry.unwrap().path()))
        .collect();
    assert_eq!(
        entries.len(),
        5,
        "four instructions and final stage publication"
    );
    for ordinal in 2..=5 {
        let checkpoint = load(&work.join(format!("checkpoint-image-{ordinal}")));
        assert!(
            entries
                .iter()
                .any(|entry| entry.selected == checkpoint.selected)
        );
    }
}
