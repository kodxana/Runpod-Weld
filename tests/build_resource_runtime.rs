#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{
    ffi::CString,
    fs,
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN and RPWELD_TEST_LAYOUT; isolated 512 MiB tmpfs"]
fn running_build_stops_on_disk_reserve_and_reaps_its_descendants() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let base = fs::canonicalize(std::env::var_os("RPWELD_TEST_LAYOUT").unwrap()).unwrap();
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
    let temp = tempfile::tempdir().unwrap();
    let mounted = temp.path().join("limited");
    fs::create_dir(&mounted).unwrap();
    let mount_path = CString::new(mounted.as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                mount_path.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                c"size=512m,nr_inodes=16384,mode=0700".as_ptr().cast(),
            )
        },
        0
    );
    struct Mount(CString);
    impl Drop for Mount {
        fn drop(&mut self) {
            unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
        }
    }
    let _mount = Mount(mount_path);
    let context = temp.path().join("context");
    let store = temp.path().join("store");
    let work = mounted.join("work");
    let output = temp.path().join("image");
    fs::create_dir(&context).unwrap();
    fs::write(
        context.join("Dockerfile"),
        "FROM alpine\nRUN echo $$ >/run-pid; sleep 120 & echo $! >/descendant-pid; dd if=/dev/zero of=/growth bs=1048576 count=280 && touch /allocation-complete && wait\n",
    )
    .unwrap();
    let stdout = temp.path().join("stdout");
    let stderr = temp.path().join("stderr");
    let binary = std::env::var_os("RPWELD_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_rpweld").into());
    let mut command = Command::new(binary);
    command
        .env("HOME", temp.path())
        .env("RPWELD_HOME", &store)
        .args([
            "build",
            "-t",
            "test/resource-runtime",
            "--no-cache",
            "--no-host-dns",
            "--max-rootfs-bytes",
            "536870912",
            "--max-layer-bytes",
            "536870912",
            "--metadata-budget",
            "67108864",
            "--max-entries",
            "100000",
            "--run-timeout-seconds",
            "60",
        ])
        .arg("--base")
        .arg(format!("alpine={}", base.display()))
        .arg("--work-dir")
        .arg(&work)
        .arg("--output")
        .arg(&output)
        .arg(&context)
        .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
        .stderr(Stdio::from(fs::File::create(&stderr).unwrap()));
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let start = Instant::now();
    let mut identities = Vec::new();
    let status = loop {
        if identities.is_empty() {
            // Observe start times while the processes are alive, so PID reuse
            // cannot turn the cleanup assertion into a false failure.
            let pids: Option<Vec<_>> = ["run-pid", "descendant-pid"]
                .iter()
                .map(|name| {
                    let pid: u32 = fs::read_to_string(work.join("rootfs").join(name))
                        .ok()?
                        .trim()
                        .parse()
                        .ok()?;
                    Some((pid, process_start(pid)?))
                })
                .collect();
            if let Some(pids) = pids {
                identities = pids;
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(30) {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            child.wait().unwrap();
            panic!(
                "resource monitor did not stop RUN before its 60s timeout: {}",
                fs::read_to_string(&stderr).unwrap()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let log = format!(
        "{}\n{}",
        fs::read_to_string(stdout).unwrap(),
        fs::read_to_string(stderr).unwrap()
    );
    assert!(!status.success(), "{log}");
    assert_eq!(
        identities.len(),
        2,
        "RUN and descendant were not observed: {log}"
    );
    assert!(
        log.contains("build in progress") && log.contains("additional/reserved bytes"),
        "{log}"
    );
    assert!(!log.contains("RUN timed out"), "{log}");
    assert!(work.join("rootfs/growth").metadata().unwrap().len() >= 256 * 1024 * 1024);
    for (pid, started) in identities {
        assert_ne!(
            process_start(pid),
            Some(started),
            "surviving RUN process {pid}: {log}"
        );
    }
    assert!(!output.exists(), "failed build published an image: {log}");
    assert!(
        !has_file(&store.join("tags")),
        "failed build published a tag: {log}"
    );
    let records: Vec<rpweld::build_record::Record> = fs::read_dir(&store)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path().join(rpweld::build_record::FILE);
            path.exists()
                .then(|| serde_json::from_slice(&fs::read(path).unwrap()).unwrap())
        })
        .collect();
    assert_eq!(records.len(), 1, "{log}");
    assert_eq!(records[0].phase, rpweld::build_record::Phase::Failed);
    assert!(records[0].manifest.is_none());
}

fn process_start(pid: u32) -> Option<String> {
    // /proc/stat field 22; comm may contain spaces and parentheses.
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(
        stat.rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(19)?
            .to_owned(),
    )
}

fn has_file(path: &Path) -> bool {
    match fs::read_dir(path) {
        Ok(mut entries) => entries.any(|entry| {
            let path = entry.unwrap().path();
            path.is_file() || has_file(&path)
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("{}: {error}", path.display()),
    }
}
