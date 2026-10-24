//! Minimal real devices for an experimental, trusted rootfs.
//!
//! The caller must keep the rootfs and its ancestry stable for this call (including
//! mounts); this is not an isolation boundary for an attacker-controlled tree.
//! No symlink component is followed. Existing entries are never replaced or
//! chmodded. Errors may leave newly created directories/nodes in place; there is
//! deliberately no rollback that could remove someone else's data.
use std::{io, path::Path};

/// Prepare /dev/{null,zero,random,urandom} as character devices with mode 0666.
///
/// Existing devices must already have exactly mode 0666, including no special
/// permission bits. Repair mode-000 OCI unpack results before calling this.
/// Creation needs mknod permission and a filesystem supporting devices. Setting
/// newly created node permissions uses a verified open device descriptor.
/// Device opens must be permitted by the filesystem, device cgroup and host policy.
pub fn prepare(rootfs: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::prepare(rootfs)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = rootfs;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "device preparation requires Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::{CStr, CString},
        mem::MaybeUninit,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
            unix::ffi::OsStrExt,
        },
        path::Component,
    };

    const DIRECTORY: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    const DEVICES: [(&CStr, libc::c_uint); 4] =
        [(c"null", 3), (c"zero", 5), (c"random", 8), (c"urandom", 9)];

    fn context(action: &str, error: io::Error) -> io::Error {
        io::Error::new(error.kind(), format!("{action}: {error}"))
    }

    fn invalid(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message.into())
    }

    fn open_at(parent: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
        // All names are NUL-terminated; ownership is transferred only on success.
        let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn stat(fd: &OwnedFd) -> io::Result<libc::stat> {
        let mut value = MaybeUninit::uninit();
        if unsafe { libc::fstat(fd.as_raw_fd(), value.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { value.assume_init() })
    }

    fn root(rootfs: &Path) -> io::Result<OwnedFd> {
        if rootfs.as_os_str().is_empty() {
            return Err(invalid("rootfs path is empty"));
        }
        // Walk each component so O_NOFOLLOW also protects intermediate directories.
        let start = if rootfs.is_absolute() { c"/" } else { c"." };
        let mut fd = open_at(libc::AT_FDCWD, start, DIRECTORY)?;
        for component in rootfs.components() {
            match component {
                Component::RootDir | Component::CurDir => (),
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes())
                        .map_err(|_| invalid("rootfs path contains a NUL byte"))?;
                    fd = open_at(fd.as_raw_fd(), &name, DIRECTORY).map_err(|e| {
                        context("rootfs must contain only existing real directories", e)
                    })?;
                }
                _ => {
                    return Err(invalid(
                        "rootfs path must not contain '..' or a platform prefix",
                    ));
                }
            }
        }
        let host = open_at(libc::AT_FDCWD, c"/", DIRECTORY)?;
        let actual = stat(&fd)?;
        let host = stat(&host)?;
        if actual.st_dev == host.st_dev && actual.st_ino == host.st_ino {
            return Err(invalid(
                "refusing to prepare the host root '/' or an inode alias of it",
            ));
        }
        Ok(fd)
    }

    fn validate(value: &libc::stat, name: &CStr, minor: libc::c_uint) -> io::Result<()> {
        if value.st_mode & libc::S_IFMT != libc::S_IFCHR || value.st_rdev != libc::makedev(1, minor)
        {
            return Err(invalid(format!(
                "/dev/{} must be a real character device 1:{minor}; refusing to replace it",
                name.to_string_lossy()
            )));
        }
        Ok(())
    }

    pub(super) fn prepare(rootfs: &Path) -> io::Result<()> {
        let root = root(rootfs)?;
        let created_dev = unsafe { libc::mkdirat(root.as_raw_fd(), c"dev".as_ptr(), 0o755) } == 0;
        if !created_dev {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(context("cannot create rootfs /dev directory", error));
            }
        }
        let dev = open_at(root.as_raw_fd(), c"dev", DIRECTORY)
            .map_err(|e| context("rootfs /dev must be a real, accessible directory", e))?;
        if created_dev && unsafe { libc::fchmod(dev.as_raw_fd(), 0o755) } != 0 {
            return Err(context(
                "cannot set new /dev directory permissions",
                io::Error::last_os_error(),
            ));
        }
        if stat(&dev)?.st_mode & 0o111 != 0o111 {
            return Err(invalid(
                "rootfs /dev must be traversable by nonroot users; existing directory unchanged",
            ));
        }
        for (name, minor) in DEVICES {
            let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let (node, created) = match open_at(dev.as_raw_fd(), name, flags) {
                Ok(node) => (node, false),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    if unsafe {
                        libc::mknodat(
                            dev.as_raw_fd(),
                            name.as_ptr(),
                            libc::S_IFCHR | 0o666,
                            libc::makedev(1, minor),
                        )
                    } != 0
                    {
                        return Err(context(
                            &format!(
                                "cannot create /dev/{} (1:{minor}); host must allow real character devices and mknod; no file fallback",
                                name.to_string_lossy()
                            ),
                            io::Error::last_os_error(),
                        ));
                    }
                    (
                        open_at(dev.as_raw_fd(), name, flags)
                            .map_err(|e| context("cannot pin newly created device", e))?,
                        true,
                    )
                }
                Err(error) => return Err(context("cannot inspect rootfs device", error)),
            };
            let pinned = stat(&node)?;
            validate(&pinned, name, minor)?;
            // The caller guarantees a stable trusted tree. Verify the opened inode
            // before changing permissions; O_NONBLOCK avoids blocking device opens.
            let opened = open_at(
                dev.as_raw_fd(),
                name,
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
            .map_err(|e| {
                context(
                    "cannot open real device; check nodev, device cgroup and host policy",
                    e,
                )
            })?;
            let actual = stat(&opened)?;
            if pinned.st_dev != actual.st_dev || pinned.st_ino != actual.st_ino {
                return Err(invalid("device changed during preparation"));
            }
            if created && unsafe { libc::fchmod(opened.as_raw_fd(), 0o666) } != 0 {
                return Err(context(
                    "cannot set new device permissions; node left in place",
                    io::Error::last_os_error(),
                ));
            }
            let mode = stat(&node)?.st_mode & 0o7777;
            if mode != 0o666 {
                return Err(invalid(format!(
                    "/dev/{} has mode {mode:04o}, expected 0666; repair permissions in the trusted rootfs before retrying (existing nodes are never chmodded)",
                    name.to_string_lossy()
                )));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            io::{Read, Write},
            os::unix::{
                fs::{PermissionsExt, symlink},
                process::CommandExt,
            },
            path::PathBuf,
            sync::atomic::{AtomicU64, Ordering},
        };

        struct Temp(PathBuf);
        impl Temp {
            fn new() -> Self {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                loop {
                    let path = std::env::temp_dir().join(format!(
                        "rpweld-devices-{}-{}",
                        std::process::id(),
                        NEXT.fetch_add(1, Ordering::Relaxed)
                    ));
                    match fs::create_dir(&path) {
                        Ok(()) => return Self(fs::canonicalize(path).unwrap()),
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(e) => panic!("temporary directory: {e}"),
                    }
                }
            }
        }
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn rejects_host_root_and_invalid_roots() {
            assert!(
                prepare(Path::new("/"))
                    .unwrap_err()
                    .to_string()
                    .contains("host root")
            );
            assert!(prepare(Path::new("/./")).is_err());
            assert!(prepare(Path::new("")).is_err());
            let temp = Temp::new();
            assert!(prepare(&temp.0.join("missing")).is_err());
            fs::write(temp.0.join("file"), "keep").unwrap();
            assert!(prepare(&temp.0.join("file")).is_err());
            symlink(&temp.0, temp.0.join("link")).unwrap();
            fs::create_dir(temp.0.join("child")).unwrap();
            assert!(prepare(&temp.0.join("link/child")).is_err());
            assert!(prepare(&temp.0.join("child/..")).is_err());
        }

        #[test]
        fn refuses_dev_symlink_and_regular_file() {
            let temp = Temp::new();
            let outside = Temp::new();
            symlink(&outside.0, temp.0.join("dev")).unwrap();
            assert!(prepare(&temp.0).is_err());
            assert_eq!(fs::read_dir(&outside.0).unwrap().count(), 0);
            fs::remove_file(temp.0.join("dev")).unwrap();
            fs::write(temp.0.join("dev"), "keep").unwrap();
            assert!(prepare(&temp.0).is_err());
            assert_eq!(fs::read(temp.0.join("dev")).unwrap(), b"keep");
        }

        #[test]
        fn refuses_existing_file_and_device_symlink() {
            let temp = Temp::new();
            fs::create_dir(temp.0.join("dev")).unwrap();
            let null = temp.0.join("dev/null");
            fs::write(&null, "keep").unwrap();
            assert!(
                prepare(&temp.0)
                    .unwrap_err()
                    .to_string()
                    .contains("real character device")
            );
            assert_eq!(fs::read(&null).unwrap(), b"keep");
            fs::remove_file(&null).unwrap();
            symlink("/dev/null", &null).unwrap();
            assert!(prepare(&temp.0).is_err());
            assert_eq!(fs::read_link(&null).unwrap(), Path::new("/dev/null"));
        }

        #[test]
        #[ignore = "child probe invoked by real_devices_and_existing_permissions"]
        fn devices_nonroot_probe() {
            let Some(path) = std::env::var_os("RPWELD_DEVICE_TEST_ROOT") else {
                return;
            };
            assert_eq!(unsafe { libc::geteuid() }, 65534);
            let mut null = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(Path::new(&path).join("dev/null"))
                .unwrap();
            null.write_all(b"nonroot write").unwrap();
            assert_eq!(null.read(&mut [0; 1]).unwrap(), 0);
        }

        #[test]
        #[ignore = "requires mknod and a filesystem allowing device I/O"]
        fn real_devices_and_existing_permissions() {
            let temp = Temp::new();
            prepare(&temp.0).unwrap();
            prepare(&temp.0).unwrap();
            let dev = root(&temp.0.join("dev")).unwrap();
            for (name, minor) in DEVICES {
                let node = open_at(dev.as_raw_fd(), name, libc::O_PATH | libc::O_NOFOLLOW).unwrap();
                let value = stat(&node).unwrap();
                validate(&value, name, minor).unwrap();
                assert_eq!(value.st_mode & 0o7777, 0o666);
            }
            let null = temp.0.join("dev/null");
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&null)
                .unwrap();
            file.write_all(b"discard me").unwrap();
            assert_eq!(file.read(&mut [0; 8]).unwrap(), 0);
            let mut zero = [1; 8];
            fs::File::open(temp.0.join("dev/zero"))
                .unwrap()
                .read_exact(&mut zero)
                .unwrap();
            assert_eq!(zero, [0; 8]);
            if unsafe { libc::geteuid() } == 0 {
                fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o755)).unwrap();
                fs::set_permissions(temp.0.join("dev"), fs::Permissions::from_mode(0o755)).unwrap();
                // Drop credentials only in a fresh test process, never in this runner.
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--ignored", "devices_nonroot_probe", "--nocapture"])
                    .env("RPWELD_DEVICE_TEST_ROOT", &temp.0)
                    .gid(65534)
                    .uid(65534)
                    .status()
                    .unwrap();
                assert!(status.success(), "nonroot device read/write probe failed");
            }
            fs::set_permissions(&null, fs::Permissions::from_mode(0o0)).unwrap();
            assert!(
                prepare(&temp.0)
                    .unwrap_err()
                    .to_string()
                    .contains("repair permissions")
            );
            assert_eq!(
                fs::metadata(&null).unwrap().permissions().mode() & 0o7777,
                0
            );
            fs::remove_file(&null).unwrap();
            assert_eq!(
                unsafe {
                    libc::mknodat(
                        dev.as_raw_fd(),
                        c"null".as_ptr(),
                        libc::S_IFCHR | 0o666,
                        libc::makedev(1, 5),
                    )
                },
                0
            );
            assert!(prepare(&temp.0).unwrap_err().to_string().contains("1:3"));
        }
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    #[test]
    fn unsupported_platform() {
        assert_eq!(
            super::prepare(std::path::Path::new("unused"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
    }
}
