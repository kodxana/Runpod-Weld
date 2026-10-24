//! Experimental trusted-command spike, NOT a container or hostile-code sandbox.
//! No mounts, proc/dev fabrication, native root replacement, or PRoot fallback.
//! Host network/PID visibility and kernel limits remain those of the caller.
use std::{io, path::PathBuf, sync::atomic::AtomicBool, time::Duration};

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub rootfs: PathBuf,
    /// Must already exist and not overlap rootfs; used only for overlap refusal.
    pub state_dir: PathBuf,
    /// Executed by the image's /bin/sh -c, in /, with a cleared environment.
    pub command: String,
    pub uid: u32,
    pub gid: u32,
    pub timeout: Duration,
    pub term_grace: Duration,
}

#[derive(Debug, serde::Serialize)]
pub struct RunOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    /// Always false: setsid/setpgid descendants can escape group cleanup.
    pub descendant_cleanup_guaranteed: bool,
}

pub fn run(options: &RunOptions) -> io::Result<RunOutcome> {
    run_with_cancel(options, &AtomicBool::new(false))
}

/// The caller can set `cancel` from its own signal/event handler. This module
/// installs no process-global handlers or subreaper state, and never reaps
/// unrelated children. Killing the supervisor itself can leave children alive.
/// Callers must not concurrently reap this child (including waitpid(-1)) or
/// configure SIGCHLD with SIG_IGN/SA_NOCLDWAIT. Only trusted image commands are
/// supported; retained root privileges, inherited descriptors, or mounted paths
/// can expose the outer Pod. Missing /proc and /dev remain missing.
pub fn run_with_cancel(options: &RunOptions, cancel: &AtomicBool) -> io::Result<RunOutcome> {
    #[cfg(target_os = "linux")]
    {
        linux::run(options, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (options, cancel);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "experimental chroot execution requires Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                fs::{MetadataExt, OpenOptionsExt},
                process::{CommandExt, ExitStatusExt},
            },
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::atomic::Ordering,
        thread,
        time::Instant,
    };

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn validate(root: &Path, state: &Path, cwd: &Path) -> io::Result<PathBuf> {
        let root = fs::canonicalize(root)?;
        let state = fs::canonicalize(state)?;
        let cwd = fs::canonicalize(cwd)?;
        if !root.is_dir() || !state.is_dir() {
            return Err(invalid("rootfs and state must be existing directories"));
        }
        if root == Path::new("/")
            || cwd.starts_with(&root)
            || state.starts_with(&root)
            || root.starts_with(&state)
        {
            return Err(invalid(
                "refusing /, a rootfs containing cwd, or overlapping rootfs and engine state",
            ));
        }
        Ok(root)
    }

    pub(super) fn run(options: &RunOptions, cancel: &AtomicBool) -> io::Result<RunOutcome> {
        if options.timeout.is_zero() {
            return Err(invalid("timeout must be positive"));
        }
        let root = validate(
            &options.rootfs,
            &options.state_dir,
            &std::env::current_dir()?,
        )?;
        // Pin the directory used by chroot, rather than resolve the name in the child.
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&root)?;
        let before = fs::metadata(&root)?;
        let pinned = directory.metadata()?;
        if before.dev() != pinned.dev() || before.ino() != pinned.ino() {
            return Err(invalid("rootfs changed during validation"));
        }
        let outer = fs::metadata("/")?;
        if pinned.dev() == outer.dev() && pinned.ino() == outer.ino() {
            return Err(invalid("refusing an alias of the outer root"));
        }
        // shortcut: trusted, stable rootfs paths only; mount aliases and concurrent
        // renames are not a security boundary. Upgrade before accepting hostile input.
        // Stdio setup may overwrite descriptors 0..=2 before pre_exec runs.
        let directory = above_stdio(directory)?;
        let fd = directory.as_raw_fd();
        let (uid, gid) = (options.uid, options.gid);
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(&options.command)
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        unsafe {
            command.pre_exec(move || {
                // Only async-signal-safe syscalls in the forked child.
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fchdir(fd) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::chroot(c".".as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::chdir(c"/".as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::close(fd) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgid(gid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        drop(directory);
        supervise(child, options.timeout, options.term_grace, cancel)
    }

    fn above_stdio(directory: fs::File) -> io::Result<fs::File> {
        if directory.as_raw_fd() > 2 {
            return Ok(directory);
        }
        let fd = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    fn signal_group(pid: libc::pid_t, signal: i32) -> io::Result<()> {
        if unsafe { libc::kill(-pid, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn exited_without_reaping(pid: libc::pid_t) -> io::Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { info.si_pid() } != 0)
    }

    fn supervise(
        mut child: Child,
        timeout: Duration,
        grace: Duration,
        cancel: &AtomicBool,
    ) -> io::Result<RunOutcome> {
        let pid = child.id() as libc::pid_t;
        let start = Instant::now();
        let mut timed_out = false;
        let mut cancelled = false;
        let mut failure = None;
        loop {
            match exited_without_reaping(pid) {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                // Another reaper invalidates the PID reservation: never signal a
                // potentially reused group, even though cleanup is now unknown.
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Err(error),
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
            cancelled = cancel.load(Ordering::Relaxed);
            timed_out = start.elapsed() >= timeout;
            if cancelled || timed_out {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        // Keep the leader unreaped until the final group signal to prevent PID reuse.
        // Also stop remaining group members after a normally exiting shell.
        if let Err(error) = signal_group(pid, libc::SIGTERM) {
            failure.get_or_insert(error);
        }
        let stopping = Instant::now();
        while stopping.elapsed() < grace {
            thread::sleep(Duration::from_millis(10).min(grace.saturating_sub(stopping.elapsed())));
        }
        if let Err(error) = signal_group(pid, libc::SIGKILL) {
            failure.get_or_insert(error);
        }
        let status = child.wait()?;
        if let Some(error) = failure {
            return Err(error);
        }
        // shortcut: no subreaper in a shared library; escaped groups and orphan
        // reaping require a dedicated supervisor process in a later tranche.
        // wait() can exceed the deadline for a kernel task in uninterruptible sleep.
        Ok(RunOutcome {
            exit_code: status.code(),
            signal: status.signal(),
            timed_out,
            cancelled,
            descendant_cleanup_guaranteed: false,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn refuses_outer_root_and_ancestors() {
            let cwd = std::env::current_dir().unwrap();
            assert!(validate(Path::new("/"), &cwd, &cwd).is_err());
            assert!(validate(&cwd, &cwd, &cwd).is_err());
            assert!(validate(cwd.parent().unwrap_or(Path::new("/")), &cwd, &cwd).is_err());
        }

        #[test]
        fn refuses_symlink_to_outer_root() {
            let path =
                std::env::temp_dir().join(format!("rpweld-root-alias-{}", std::process::id()));
            std::os::unix::fs::symlink("/", &path).unwrap();
            let cwd = std::env::current_dir().unwrap();
            let result = validate(&path, &cwd, &cwd);
            fs::remove_file(path).unwrap();
            assert!(result.is_err());
        }

        #[test]
        fn refuses_root_state_overlap_in_both_directions() {
            let base = std::env::temp_dir().join(format!("rpweld-overlap-{}", std::process::id()));
            let nested = base.join("nested");
            let sibling = base.join("sibling");
            fs::create_dir_all(&nested).unwrap();
            fs::create_dir_all(&sibling).unwrap();
            let cwd = std::env::current_dir().unwrap();
            assert!(validate(&base, &nested, &cwd).is_err());
            assert!(validate(&nested, &base, &cwd).is_err());
            assert!(validate(&nested, &nested, &cwd).is_err());
            assert!(validate(&nested, &sibling, &cwd).is_ok());
            fs::remove_dir_all(base).unwrap();
        }

        #[test]
        fn root_descriptor_survives_closed_stdin() {
            const MARKER: &str = "RPWELD_TEST_CLOSED_STDIN";
            if std::env::var_os(MARKER).is_none() {
                let status = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "executor::linux::tests::root_descriptor_survives_closed_stdin",
                    ])
                    .env(MARKER, "1")
                    .status()
                    .unwrap();
                assert!(status.success());
                return;
            }
            // Change standard descriptors only in this isolated test process.
            unsafe {
                libc::close(0);
            }
            let directory = fs::File::open("/").unwrap();
            assert_eq!(directory.as_raw_fd(), 0);
            let directory = above_stdio(directory).unwrap();
            assert!(directory.as_raw_fd() > 2);
            assert!(directory.metadata().unwrap().is_dir());
            let flags = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFD) };
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
            assert_eq!(unsafe { libc::fcntl(0, libc::F_GETFD) }, -1);
        }

        fn shell(script: &str) -> Child {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) != 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
            command.spawn().unwrap()
        }

        #[test]
        fn normal_exit_137_is_not_a_signal_or_timeout() {
            for code in [0, 137] {
                let result = supervise(
                    shell(&format!("exit {code}")),
                    Duration::from_secs(5),
                    Duration::ZERO,
                    &AtomicBool::new(false),
                )
                .unwrap();
                assert_eq!(result.exit_code, Some(code));
                assert_eq!(result.signal, None);
                assert!(!result.timed_out);
                assert!(!result.cancelled);
                assert!(!result.descendant_cleanup_guaranteed);
            }
            let result = supervise(
                shell("kill -KILL $$"),
                Duration::from_secs(5),
                Duration::ZERO,
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(result.exit_code, None);
            assert_eq!(result.signal, Some(libc::SIGKILL));
            assert!(!result.timed_out);
            assert!(!result.cancelled);
        }

        #[test]
        fn cancellation_stops_a_running_child_without_reporting_timeout() {
            let cancel = AtomicBool::new(false);
            let child = shell("while :; do :; done");
            let start = Instant::now();
            let result = thread::scope(|scope| {
                scope.spawn(|| {
                    thread::sleep(Duration::from_millis(100));
                    cancel.store(true, Ordering::Relaxed);
                });
                supervise(
                    child,
                    Duration::from_secs(5),
                    Duration::from_millis(50),
                    &cancel,
                )
                .unwrap()
            });
            assert!(result.cancelled);
            assert!(!result.timed_out);
            assert_eq!(result.exit_code, None);
            assert_eq!(result.signal, Some(libc::SIGTERM));
            assert!(!result.descendant_cleanup_guaranteed);
            assert!(start.elapsed() < Duration::from_secs(5));
        }

        #[test]
        fn child_timeout_kills_term_ignoring_group() {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "trap '' TERM; while :; do :; done"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) != 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
            let start = Instant::now();
            let result = supervise(
                command.spawn().unwrap(),
                Duration::from_millis(100),
                Duration::from_millis(50),
                &AtomicBool::new(false),
            )
            .unwrap();
            assert!(result.timed_out);
            assert_eq!(result.signal, Some(libc::SIGKILL));
            assert!(start.elapsed() < Duration::from_secs(5));
        }

        #[test]
        #[ignore = "requires root/CAP_SYS_CHROOT and RPWELD_TEST_ROOTFS with a working /bin/sh"]
        fn private_root_timeout() {
            let rootfs = std::env::var_os("RPWELD_TEST_ROOTFS")
                .expect("fixture rootfs")
                .into();
            let result = super::super::run(&RunOptions {
                rootfs,
                state_dir: std::env::current_dir().unwrap(),
                command: "trap '' TERM; while :; do :; done".into(),
                uid: 0,
                gid: 0,
                timeout: Duration::from_millis(100),
                term_grace: Duration::from_millis(50),
            })
            .unwrap();
            assert!(result.timed_out);
            assert_eq!(result.signal, Some(libc::SIGKILL));
        }
    }
}
