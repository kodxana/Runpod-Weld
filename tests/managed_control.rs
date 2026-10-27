#![cfg(target_os = "linux")]

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
