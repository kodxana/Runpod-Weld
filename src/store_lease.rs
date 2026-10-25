//! Process-wide store coordination. Acquire this lease BEFORE any finer store locks.
//!
//! All participants must keep the root and `store.lock` inode in place forever.
//! A lease pins the opened directory, not the pathname: callers must compare its
//! identity before operating through a separately resolved path. Same-user code
//! that renames/replaces the root or lock violates this protocol.
//! Drop only closes descriptors; it must never issue LOCK_UN, which would unlock
//! the shared open file description still held by a supervisor or forked child.

use std::{fs::File, io, path::Path};

/// Linux device/inode identity of the pinned store directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootIdentity {
    pub device: u64,
    pub inode: u64,
}

/// Shared reader/build lease. Fields are deliberately opaque.
#[derive(Debug)]
pub struct StoreLease {
    _root: File,
    lock: File,
    identity: RootIdentity,
}

/// Exclusive maintenance lease; never deletes the root or the persistent lock.
#[derive(Debug)]
pub struct ExclusiveStoreLease(StoreLease);

impl StoreLease {
    /// Open an existing, user-owned real directory and acquire its shared lease.
    /// Publishes `store.lock` atomically with mode 0600 (independent of umask),
    /// using a temporary file in the pinned directory; never truncates a lock.
    /// Contention is polled at most every 25 ms, with cancellation before/after
    /// acquisition. There is no total wait deadline: cancellation governs the
    /// wait and is cooperative, not a filesystem I/O timeout.
    pub fn shared(store: &Path, cancelled: &impl Fn() -> bool) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            linux::shared(store, cancelled)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (store, cancelled);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "store leases require Linux",
            ))
        }
    }

    /// Acquire an existing lock without creating or writing anything.
    /// `None` means ONLY flock EWOULDBLOCK. A missing root/lock is an error:
    /// absence cannot establish that pre-protocol readers are not using a store.
    pub fn try_exclusive_existing(store: &Path) -> io::Result<Option<ExclusiveStoreLease>> {
        #[cfg(target_os = "linux")]
        {
            linux::exclusive(store)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = store;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "store leases require Linux",
            ))
        }
    }

    pub fn root_identity(&self) -> RootIdentity {
        self.identity
    }

    /// Return an independently owned, CLOEXEC descriptor for the SAME open file
    /// description. The recipient owns and must close this File (or convert it
    /// into OwnedFd). It must never flock/LOCK_UN it. Dropping either owner does
    /// not release the lease until the last duplicate/inherited descriptor closes.
    /// For exec handoff, the supervisor must explicitly arrange inheritance of
    /// this duplicate only. The descriptor is always >= 3. This exports the
    /// lock, not a directory capability.
    pub fn duplicate_for_supervisor(&self) -> io::Result<File> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            // SAFETY: valid borrowed fd; successful fcntl returns a new owned fd.
            let fd = unsafe { libc::fcntl(self.lock.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { File::from_raw_fd(fd) })
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &self.lock;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "store leases require Linux",
            ))
        }
    }
}

impl ExclusiveStoreLease {
    pub fn root_identity(&self) -> RootIdentity {
        self.0.root_identity()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, PermissionsExt},
            },
        },
        thread,
        time::Duration,
    };

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn open(store: &Path, create: bool) -> io::Result<StoreLease> {
        // Strip trailing slash/dot components so O_NOFOLLOW still checks the
        // named directory itself. Ancestor components resolve normally.
        let normalized: std::path::PathBuf = store.components().collect();
        let bytes = normalized.as_os_str().as_bytes();
        let path = CString::new(bytes).map_err(|_| invalid("NUL in store path"))?;
        // SAFETY: NUL-terminated path; ownership transferred exactly once below.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let root = unsafe { File::from_raw_fd(fd) };
        let meta = root.metadata()?;
        let uid = unsafe { libc::geteuid() };
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err(invalid(
                "store must be an owned directory without group/other write permission",
            ));
        }
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        // Never repair existing locks, including unreadable ones.
        let mut fd = unsafe { libc::openat(root.as_raw_fd(), c"store.lock".as_ptr(), flags) };
        if fd < 0 && create && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            // /proc keeps temporary creation pinned to our directory descriptor.
            // Set permissions before publication: even umask 0777 cannot expose
            // a half-ready lock to another creator. Rename keeps nlink == 1.
            let temporary = tempfile::Builder::new()
                .prefix(".store.lock-")
                .tempfile_in(format!("/proc/self/fd/{}", root.as_raw_fd()))?;
            temporary
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
            let name = CString::new(temporary.path().file_name().unwrap().as_bytes()).unwrap();
            let rc = unsafe {
                libc::renameat2(
                    root.as_raw_fd(),
                    name.as_ptr(),
                    root.as_raw_fd(),
                    c"store.lock".as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if rc < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(error);
                }
            }
            // The winner is fully initialized; losers remove only their temp.
            fd = unsafe { libc::openat(root.as_raw_fd(), c"store.lock".as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let lock = unsafe { File::from_raw_fd(fd) };
        let lease = StoreLease {
            _root: root,
            lock,
            identity: RootIdentity {
                device: meta.dev(),
                inode: meta.ino(),
            },
        };
        validate(&lease)?;
        Ok(lease)
    }

    fn validate(lease: &StoreLease) -> io::Result<()> {
        let meta = lease.lock.metadata()?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o7077 != 0
        {
            return Err(invalid(
                "store.lock must be a singly linked owned regular file with private permissions",
            ));
        }
        let mut named = std::mem::MaybeUninit::<libc::stat>::uninit();
        // Check the directory entry as well as the descriptor, without following links.
        let rc = unsafe {
            libc::fstatat(
                lease._root.as_raw_fd(),
                c"store.lock".as_ptr(),
                named.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let named = unsafe { named.assume_init() };
        if named.st_dev != meta.dev() || named.st_ino != meta.ino() {
            return Err(invalid("store.lock changed while acquiring lease"));
        }
        Ok(())
    }

    fn attempt(lease: &StoreLease, mode: libc::c_int) -> io::Result<bool> {
        if unsafe { libc::flock(lease.lock.as_raw_fd(), mode | libc::LOCK_NB) } == 0 {
            validate(lease)?;
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(false)
        } else {
            Err(error)
        }
    }

    pub(super) fn shared(store: &Path, cancelled: &impl Fn() -> bool) -> io::Result<StoreLease> {
        let check = || {
            if cancelled() {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "store lease cancelled",
                ))
            } else {
                Ok(())
            }
        };
        check()?;
        let lease = open(store, true)?;
        loop {
            check()?;
            if attempt(&lease, libc::LOCK_SH)? {
                check()?;
                return Ok(lease);
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    pub(super) fn exclusive(store: &Path) -> io::Result<Option<ExclusiveStoreLease>> {
        let lease = open(store, false)?;
        if attempt(&lease, libc::LOCK_EX)? {
            Ok(Some(ExclusiveStoreLease(lease)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, PermissionsExt, symlink},
        },
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    fn store() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }
    fn shared(path: &Path) -> StoreLease {
        StoreLease::shared(path, &|| false).unwrap()
    }
    fn exclusive(path: &Path) -> Option<ExclusiveStoreLease> {
        StoreLease::try_exclusive_existing(path).unwrap()
    }

    // Also isolate immediate-release assertions: unrelated test forks inherit locks until exec.
    fn isolated(scenario: &str) -> bool {
        if std::env::var("STORE_LEASE_TEST_SCENARIO").as_deref() == Ok(scenario) {
            return false;
        }
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "store_lease::tests::isolated_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("STORE_LEASE_TEST_SCENARIO", scenario);
        if unsafe { libc::geteuid() } == 0 {
            command.gid(65534).uid(65534);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{scenario}: {output:?}");
        true
    }

    // Process isolation is required for both umask and closing standard fds.
    #[test]
    fn isolated_creation_and_descriptor_regressions() {
        for scenario in ["0400", "0777", "closed-stdio"] {
            assert!(isolated(scenario));
        }
    }

    #[test]
    fn isolated_child() {
        let Ok(scenario) = std::env::var("STORE_LEASE_TEST_SCENARIO") else {
            return;
        };
        assert_ne!(unsafe { libc::geteuid() }, 0);
        match scenario.as_str() {
            "shared-exclusive" => return shared_exclusive_and_persistent_inode(),
            "cancellation" => return cancellation_before_open_and_during_contention(),
            "duplicate" => return duplicate_survives_owner_drop_and_is_cloexec(),
            "readonly" => return exclusive_missing_is_error_and_readonly_file_is_supported(),
            "inherited" => return inherited_descriptor_keeps_lease_busy_until_child_exit(),
            _ => {}
        }
        let dir = store();
        if scenario == "closed-stdio" {
            let lease = shared(dir.path());
            for fd in 0..=2 {
                assert_eq!(unsafe { libc::close(fd) }, 0);
            }
            let duplicate = lease.duplicate_for_supervisor().unwrap();
            assert!(duplicate.as_raw_fd() >= 3);
            assert_ne!(
                unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            drop(lease);
            assert!(exclusive(dir.path()).is_none());
            drop(duplicate);
            assert!(exclusive(dir.path()).is_some());
            return;
        }
        let mask = u32::from_str_radix(&scenario, 8).unwrap();
        unsafe { libc::umask(mask) };
        let first = shared(dir.path());
        let inode = first.lock.metadata().unwrap().ino();
        assert_eq!(first.lock.metadata().unwrap().mode() & 0o7777, 0o600);
        assert!(exclusive(dir.path()).is_none());
        drop(first);
        let second = shared(dir.path());
        assert_eq!(second.lock.metadata().unwrap().ino(), inode);
        drop(second);
        assert!(exclusive(dir.path()).is_some());
        // Use a new, accessible directory per race under the restrictive mask.
        for _ in 0..16 {
            let race = store();
            fs::set_permissions(race.path(), fs::Permissions::from_mode(0o700)).unwrap();
            concurrent_creation_at(race.path());
            assert!(exclusive(race.path()).is_some());
            assert_eq!(fs::read_dir(race.path()).unwrap().count(), 1);
        }
        for mode in [0o000, 0o200, 0o644, 0o4600] {
            let lock = dir.path().join("store.lock");
            fs::set_permissions(&lock, fs::Permissions::from_mode(mode)).unwrap();
            assert!(StoreLease::shared(dir.path(), &|| false).is_err());
            assert!(StoreLease::try_exclusive_existing(dir.path()).is_err());
            let meta = fs::metadata(&lock).unwrap();
            assert_eq!(meta.ino(), inode);
            assert_eq!(meta.mode() & 0o7777, mode);
        }
        assert_eq!(unsafe { libc::umask(mask) }, mask);
    }

    #[test]
    fn shared_exclusive_and_persistent_inode() {
        if isolated("shared-exclusive") {
            return;
        }
        let dir = store();
        let a = shared(dir.path());
        let b = shared(dir.path());
        assert_eq!(
            a.root_identity(),
            RootIdentity {
                device: fs::metadata(dir.path()).unwrap().dev(),
                inode: fs::metadata(dir.path()).unwrap().ino()
            }
        );
        assert!(exclusive(dir.path()).is_none());
        let lock = dir.path().join("store.lock");
        fs::write(&lock, b"persistent contents").unwrap();
        let inode = fs::metadata(&lock).unwrap().ino();
        drop(a);
        assert!(exclusive(dir.path()).is_none());
        drop(b);
        let ex = exclusive(dir.path()).unwrap();
        assert_eq!(
            ex.root_identity().inode,
            fs::metadata(dir.path()).unwrap().ino()
        );
        assert!(exclusive(dir.path()).is_none());
        drop(ex);
        drop(shared(dir.path()));
        assert_eq!(fs::metadata(&lock).unwrap().ino(), inode);
        assert_eq!(fs::read(lock).unwrap(), b"persistent contents");
    }

    #[test]
    fn cancellation_before_open_and_during_contention() {
        if isolated("cancellation") {
            return;
        }
        let dir = store();
        assert_eq!(
            StoreLease::shared(dir.path(), &|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(!dir.path().join("store.lock").exists());
        drop(shared(dir.path()));
        let _ex = exclusive(dir.path()).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let path = dir.path().to_owned();
        let waiter =
            thread::spawn(move || StoreLease::shared(&path, &|| flag.load(Ordering::SeqCst)));
        thread::sleep(Duration::from_millis(60));
        let start = Instant::now();
        cancel.store(true, Ordering::SeqCst);
        assert_eq!(
            waiter.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn duplicate_survives_owner_drop_and_is_cloexec() {
        if isolated("duplicate") {
            return;
        }
        let dir = store();
        let lease = shared(dir.path());
        let fd = lease.duplicate_for_supervisor().unwrap();
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(lease);
        assert!(exclusive(dir.path()).is_none());
        drop(fd);
        assert!(exclusive(dir.path()).is_some());
    }

    #[test]
    fn inherited_descriptor_keeps_lease_busy_until_child_exit() {
        if isolated("inherited") {
            return;
        }
        use std::{io::Write, os::unix::net::UnixStream};
        let dir = store();
        let lease = shared(dir.path());
        let (mut parent, child) = UnixStream::pair().unwrap();
        // SAFETY: the fork child only uses async-signal-safe calls, then _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(parent.as_raw_fd());
                let mut byte = 0u8;
                let rc = libc::read(child.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
                libc::_exit(if rc == 1 { 0 } else { 1 });
            }
        }
        drop(child);
        drop(lease);
        // No sleep/retry: the child cannot exit until the parent releases it.
        let busy = exclusive(dir.path()).is_none();
        parent.write_all(b"x").unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        assert!(busy, "inherited open file description must retain the lock");
        assert!(exclusive(dir.path()).is_some());
    }

    #[test]
    fn concurrent_creation_uses_one_inode() {
        let dir = store();
        concurrent_creation_at(dir.path());
    }

    fn concurrent_creation_at(path: &Path) {
        let barrier = Arc::new(Barrier::new(9));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = path.to_owned();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    shared(&path)
                })
            })
            .collect();
        barrier.wait();
        let leases: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let inode = leases[0].lock.metadata().unwrap().ino();
        assert!(
            leases
                .iter()
                .all(|l| l.lock.metadata().unwrap().ino() == inode)
        );
        assert!(exclusive(path).is_none());
    }

    #[test]
    fn exclusive_missing_is_error_and_readonly_file_is_supported() {
        if isolated("readonly") {
            return;
        }
        let dir = store();
        assert_eq!(
            StoreLease::try_exclusive_existing(dir.path())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert!(!dir.path().join("store.lock").exists());
        drop(shared(dir.path()));
        fs::set_permissions(
            dir.path().join("store.lock"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        assert!(exclusive(dir.path()).is_some());
    }

    #[test]
    fn rejects_malformed_links_and_permissions_without_mutation() {
        for case in [
            "directory",
            "symlink",
            "hardlink",
            "public",
            "special",
            "fifo",
            "owner",
        ] {
            let dir = store();
            let lock = dir.path().join("store.lock");
            match case {
                "directory" => fs::create_dir(&lock).unwrap(),
                "symlink" => symlink("absent", &lock).unwrap(),
                "fifo" => {
                    use std::{ffi::CString, os::unix::ffi::OsStrExt};
                    let name = CString::new(lock.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                _ => {
                    fs::write(&lock, b"keep").unwrap();
                    fs::set_permissions(
                        &lock,
                        fs::Permissions::from_mode(if case == "public" {
                            0o644
                        } else if case == "special" {
                            0o4600
                        } else {
                            0o600
                        }),
                    )
                    .unwrap();
                    if case == "hardlink" {
                        fs::hard_link(&lock, dir.path().join("alias")).unwrap();
                    }
                    if case == "owner" {
                        if unsafe { libc::geteuid() } != 0 {
                            continue;
                        }
                        use std::{ffi::CString, os::unix::ffi::OsStrExt};
                        let name = CString::new(lock.as_os_str().as_bytes()).unwrap();
                        assert_eq!(unsafe { libc::chown(name.as_ptr(), 65534, 65534) }, 0);
                    }
                }
            }
            let before = fs::symlink_metadata(&lock).unwrap();
            assert!(StoreLease::shared(dir.path(), &|| false).is_err(), "{case}");
            assert!(
                StoreLease::try_exclusive_existing(dir.path()).is_err(),
                "{case}"
            );
            assert_eq!(fs::symlink_metadata(&lock).unwrap().ino(), before.ino());
            assert_eq!(fs::symlink_metadata(&lock).unwrap().mode(), before.mode());
        }
    }

    #[test]
    fn rejects_symlink_and_writable_root() {
        let dir = store();
        let alias = dir.path().join("alias");
        symlink(dir.path(), &alias).unwrap();
        assert!(StoreLease::shared(&alias, &|| false).is_err());
        assert!(StoreLease::shared(&alias.join(""), &|| false).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(StoreLease::shared(dir.path(), &|| false).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_tests {
    use super::*;
    #[test]
    fn unsupported_without_side_effects() {
        assert_eq!(
            StoreLease::shared(Path::new("unused"), &|| false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            StoreLease::try_exclusive_existing(Path::new("unused"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
}
