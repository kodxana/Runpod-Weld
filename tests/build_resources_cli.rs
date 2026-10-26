#![cfg(target_os = "linux")]
use std::{fs, os::unix::process::CommandExt, process::Command};

fn command(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
    cmd.env("HOME", home).env("RPWELD_HOME", home.join("store"));
    cmd
}

#[test]
fn automatic_and_explicit_origins_are_reported_even_when_progress_is_quiet() {
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    fs::write(context.join("Dockerfile"), "FROM scratch\n").unwrap();
    let result = command(temp.path())
        .args([
            "build",
            "-t",
            "test/resources",
            "--progress",
            "quiet",
            "--max-rootfs-bytes",
            "1234",
            "--max-layer-bytes",
            "1048576",
            "--max-entries",
            "32",
            "--metadata-budget",
            "1048576",
        ])
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let out = String::from_utf8_lossy(&result.stdout);
    for value in [
        "rootfs=1234 (explicit)",
        "layer/replay=1048576 (explicit)",
        "entries=32 (explicit)",
        "logical metadata=1048576 (explicit)",
        "quota unknown",
        "Logical metadata is not RSS",
    ] {
        assert!(out.contains(value), "{out}");
    }
    let result = command(temp.path())
        .args(["build", "-t", "test/resources", "--progress", "quiet"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.lines()
            .find(|s| s.starts_with("Build resources:"))
            .unwrap()
            .matches("(auto)")
            .count()
            == 4
    );
}

#[test]
fn no_cache_scratch_succeeds_below_replay_fd_overhead() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    let store = temp.path().join("store");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let source = store.join("Dockerfile");
    fs::write(&source, "FROM scratch\n").unwrap();
    let mut cmd = command(temp.path());
    unsafe {
        cmd.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 200,
                rlim_max: 200,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let result = cmd
        .args(["build", "-t", "test/low-fds", "--no-cache", "-f"])
        .arg(&source)
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("hard NOFILE=Some(200)"));
    assert!(
        store.join("store.lock").exists(),
        "successful managed source reads still acquire a lease"
    );
}

#[test]
#[ignore = "requires isolated mount namespace and CAP_SYS_ADMIN; uses small tmpfs fixtures"]
fn managed_dockerfile_disk_and_inode_refusals_precede_store_lock() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    };
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
    struct Mount(CString);
    impl Drop for Mount {
        fn drop(&mut self) {
            unsafe {
                libc::umount2(self.0.as_ptr(), libc::MNT_DETACH);
            }
        }
    }
    for (options, expected) in [
        ("size=64m,nr_inodes=4096,mode=0700", "bytes"),
        ("size=1g,nr_inodes=32,mode=0700", "inodes"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let context = temp.path().join("context");
        fs::create_dir(&store).unwrap();
        fs::create_dir(&context).unwrap();
        let mount = CString::new(store.as_os_str().as_bytes()).unwrap();
        let options = CString::new(options).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    mount.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    options.as_ptr().cast(),
                )
            },
            0
        );
        let _mount = Mount(mount);
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let source = store.join("Dockerfile");
        fs::write(&source, "FROM scratch\n").unwrap();
        let result = command(temp.path())
            .args(["build", "-t", "test/refusal", "--no-cache", "-f"])
            .arg(&source)
            .arg("--work-dir")
            .arg(temp.path().join("work"))
            .arg("--output")
            .arg(temp.path().join("output"))
            .arg(&context)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(
            !store.join("store.lock").exists(),
            "source lease mutated the store before resource refusal: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(
            error.contains("resource preflight before source lease") && error.contains(expected),
            "{error}"
        );
        assert_eq!(fs::read_dir(&store).unwrap().count(), 1);
        assert!(!temp.path().join("work").exists());
        assert!(!temp.path().join("output").exists());
        assert!(!temp.path().join(".config").exists());
    }
}

#[test]
fn entry_flags_are_positive_unique_and_validated_before_source_or_state() {
    for flags in [
        vec!["--max-entries", "0"],
        vec!["--max-entries", "18446744073709551616"],
        vec!["--max-entries", "1", "--max-entries", "2"],
    ] {
        let temp = tempfile::tempdir().unwrap();
        let result = command(temp.path())
            .args(["build", "-t", "test/refusal", "-f", "absent"])
            .args(flags)
            .arg(".")
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("--max-entries"));
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }
}
