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
