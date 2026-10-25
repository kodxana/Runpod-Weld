//! Linux lease keeper for a trusted workload; call only in a fresh single-threaded
//! process, before creating threads or installing application signal handlers.
//!
//! Parent integration (intentionally not wired into the CLI): acquire flock first,
//! spawn a hidden invocation with ONLY that fd made inheritable in the child-side
//! pre_exec, then close the parent's copy (never LOCK_UN). Parse a decimal fd >= 3
//! and `--` followed by lossless OsString argv; construct OwnedFd exactly once,
//! only after validating the invocation. Never accept this invocation remotely.
//! No store directory fd may be passed; run also closes every other fd >= 3.
//! The inherited open-file description must already hold the lease: fstat cannot
//! prove flock ownership, and acquiring/converting/unlocking here would be wrong.
//!
//! SIGINT/SIGTERM request cleanup; another delivered request escalates to SIGKILL.
//! Standard signals can coalesce: wait before sending an escalation. Parent may
//! return after a bounded wait and close its copy while this process keeps reaping.
//! Signal the guard via a parent-owned pidfd (or an unreaped direct-child PID),
//! never a cached PID after reaping. Do not set a parent-death kill signal or put
//! the guard in a parent kill-on-close cgroup. No registry auth is routed here.
//!
//! Stdio and environment are inherited directly: pipes stream without relaying,
//! stdin is neither consumed nor replaced. This detached session is not an
//! interactive terminal job-control proxy. Parent-owned pipe closure can still
//! cause workload EOF/SIGPIPE. SIGHUP is ignored by the guard. SIGKILL of the
//! supervisor itself releases its lease even if descendants survive; this is not
//! a hostile-workload boundary. Uninterruptible descendants can retain it forever.
//! Exit is the leader's code, or 128+signal, after ALL descendants are reaped;
//! setup/exec failure is 125. Descendant status does not overwrite leader status.

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

pub struct Options {
    pub lease: OwnedFd,
    pub argv: Vec<OsString>,
}

/// Takes exclusive Rust ownership of the inherited descriptor. Never returns.
pub fn run(options: Options) -> ! {
    let result = supervise(&options);
    // Drop closes, never explicitly unlocks the shared open-file description.
    drop(options);
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("lease guard: {error}");
            std::process::exit(125)
        }
    }
}

fn checked(value: libc::c_int) -> io::Result<()> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn supervise(options: &Options) -> io::Result<i32> {
    let fd = options.lease.as_raw_fd();
    if fd < 3 || options.argv.is_empty() {
        return Err(io::Error::other("expected lease fd >= 3 and nonempty argv"));
    }
    // All unsafe operations below run in this dedicated single-threaded process.
    unsafe {
        checked(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC))?;
        let mut stat: libc::stat = std::mem::zeroed();
        checked(libc::fstat(fd, &mut stat))?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != libc::geteuid()
            || stat.st_nlink != 1
            || stat.st_mode & 0o077 != 0
        {
            return Err(io::Error::other(
                "lease must be a private owned single-link regular file",
            ));
        }
        // procfs enumeration works even when an inherited fd exceeds RLIMIT_NOFILE.
        let fds = std::fs::read_dir("/proc/self/fd")?
            .map(|entry| {
                entry?
                    .file_name()
                    .to_string_lossy()
                    .parse::<i32>()
                    .map_err(io::Error::other)
            })
            .collect::<io::Result<Vec<_>>>()?;
        for other in fds {
            if other >= 3 && other != fd {
                libc::close(other);
            }
        }
        checked(libc::prctl(libc::PR_SET_PDEATHSIG, 0))?;
        checked(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1))?;
        // An already detached session leader needs no second setsid.
        if libc::getsid(0) != libc::getpid() {
            checked(libc::setsid())?;
        }
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        // SIGCHLD must remain waitable even if the launcher ignored it.
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        let mut signals: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut signals);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGCHLD] {
            libc::sigaddset(&mut signals, signal);
        }
        checked(libc::sigprocmask(
            libc::SIG_BLOCK,
            &signals,
            std::ptr::null_mut(),
        ))?;
        let mut command = Command::new(&options.argv[0]);
        command.args(&options.argv[1..]);
        command.pre_exec(move || {
            checked(libc::setpgid(0, 0))?;
            checked(libc::close(fd))?;
            for signal in [
                libc::SIGHUP,
                libc::SIGINT,
                libc::SIGTERM,
                libc::SIGCHLD,
                libc::SIGPIPE,
            ] {
                libc::signal(signal, libc::SIG_DFL);
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            checked(libc::sigprocmask(
                libc::SIG_SETMASK,
                &empty,
                std::ptr::null_mut(),
            ))
        });
        let child = command.spawn()?;
        let leader = child.id() as libc::pid_t;
        // Child has no kill-on-drop behavior. Only this loop reaps children.
        drop(child);
        let mut leader_live = true;
        let mut exit_code = 125;
        let mut cancellation = 0;
        loop {
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 20_000_000,
            };
            let signal = libc::sigtimedwait(&signals, std::ptr::null_mut(), &timeout);
            if signal == libc::SIGINT || signal == libc::SIGTERM {
                cancellation = if cancellation == 0 {
                    signal
                } else {
                    libc::SIGKILL
                };
            }
            if cancellation != 0 {
                // The unreaped leader (including a zombie) reserves its PID/PGID.
                // Never signal this group again after reaping the leader.
                if leader_live {
                    libc::kill(-leader, cancellation);
                }
                signal_children(cancellation);
            }
            loop {
                let mut status = 0;
                let pid = libc::waitpid(-1, &mut status, libc::WNOHANG);
                if pid > 0 {
                    if pid == leader {
                        leader_live = false;
                        exit_code = if libc::WIFEXITED(status) {
                            libc::WEXITSTATUS(status)
                        } else {
                            128 + libc::WTERMSIG(status)
                        };
                    }
                } else if pid == 0 {
                    break;
                } else {
                    match io::Error::last_os_error().raw_os_error() {
                        Some(libc::ECHILD) => return Ok(exit_code),
                        Some(libc::EINTR) => continue,
                        // Fail closed: no post-spawn error may release the lease.
                        _ => break,
                    }
                }
            }
        }
    }
}

unsafe fn signal_children(signal: i32) {
    // Adopted children may have detached from the original workload group.
    // Reading only our direct children is safe: none can be reaped concurrently,
    // so even the kill fallback cannot target a reused PID. Retry each loop to
    // cover new adoptions and transient procfs errors.
    let Ok(children) = std::fs::read_to_string("/proc/thread-self/children") else {
        return;
    };
    for pid in children
        .split_whitespace()
        .filter_map(|s| s.parse::<i32>().ok())
    {
        unsafe {
            let handle = libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32;
            if handle >= 0 {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    handle,
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
                libc::close(handle);
            } else {
                libc::kill(pid, signal);
            }
        }
    }
}
