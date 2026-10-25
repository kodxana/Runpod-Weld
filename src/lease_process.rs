//! CLI handoff and parent-side waiting; guard algorithm lives in lease_guard.
use crate::store_lease::StoreLease;
use std::{
    ffi::{OsStr, OsString},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, ExitStatus},
    time::{Duration, Instant},
};

/// Dispatch before any threads or application signal handlers. Invalid hidden
/// invocations exit 125 without taking ownership of an unvalidated descriptor.
pub fn entry(args: impl Iterator<Item = OsString>) -> ! {
    let mut args = args;
    let fd = args.next().and_then(|s| {
        s.to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<i32>().ok())
    });
    let separator = args.next();
    let argv: Vec<_> = args.collect();
    let Some(fd) = fd.filter(|fd| *fd >= 3) else {
        std::process::exit(125)
    };
    if separator.as_deref() != Some(OsStr::new("--")) || argv.is_empty() || argv[0].is_empty() {
        std::process::exit(125);
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        std::process::exit(125);
    }
    // Exactly one ownership transfer, only after syntactic and fd validation.
    let lease = unsafe { OwnedFd::from_raw_fd(fd) };
    crate::lease_guard::run(crate::lease_guard::Options { lease, argv })
}

/// Construct before applying cwd/env/stdio, so those settings reach the guard
/// and workload unchanged. No process_group(0): the guard needs setsid().
pub(crate) fn command(
    program: impl AsRef<OsStr>,
    lease: Option<&StoreLease>,
) -> io::Result<Command> {
    let mut lifetime = None;
    let file = match lease {
        Some(lease) => lease.duplicate_for_supervisor()?,
        None => {
            // Unmanaged RUN still needs descendant-safe teardown. A private
            // disposable file supplies the guard's lifetime token, not a store.
            let temporary = tempfile::NamedTempFile::new()?;
            let fd =
                unsafe { libc::fcntl(temporary.as_file().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            lifetime = Some(temporary);
            unsafe { std::fs::File::from_raw_fd(fd) }
        }
    };
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("__lease-guard")
        .arg(file.as_raw_fd().to_string())
        .arg("--")
        .arg(program);
    unsafe {
        cmd.pre_exec(move || {
            let _ = &lifetime;
            // Pending cancellation survives exec until the guard's sigtimedwait.
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGTERM);
            libc::sigaddset(&mut mask, libc::SIGINT);
            if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) < 0
                || libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(cmd)
}

/// Completion means the guard observed ECHILD, not merely workload-leader exit.
/// Cancellation escalates by a second TERM request; never kill the guard. This
/// may wait indefinitely for uninterruptible descendants, keeping resources safe.
pub(crate) fn wait(
    child: &mut Child,
    cancelled: &impl Fn() -> bool,
    timeout: Duration,
) -> io::Result<(ExitStatus, bool)> {
    let start = Instant::now();
    let mut stopping = None;
    let mut escalated = false;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, stopping.is_some())),
            Ok(None) => (),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // Fail closed: cannot tear down resources on an uncertain wait.
            Err(_) => {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
        }
        if stopping.is_none() && (cancelled() || start.elapsed() > timeout) {
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
            stopping = Some(Instant::now());
        } else if !escalated && stopping.is_some_and(|s| s.elapsed() >= Duration::from_secs(5)) {
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
            escalated = true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
