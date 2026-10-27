//! Exporter provenance for private checkpoints; never a substitute for hashing.
use super::Error;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Issued only after a private checkpoint export closes its writers. Inherited
/// payloads may alias earlier private checkpoints; public layouts remain copies.
/// Directory pins bind later reads to that output, not to arbitrary caller paths.
pub(crate) struct OwnedCheckpoint {
    path: PathBuf,
    directories: [File; 3],
}

// Leave the engine's fixed replay allowance free; never raise a process limit for
// an optional optimization. The session budgets its payload handles separately.
const FD_HEADROOM: u64 = 272;
const DIRECTORY_PINS: u64 = 3;

fn pin_budget_available() -> bool {
    let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the pointed-to rlimit on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: the successful call initialized this value.
    let limits = unsafe { limits.assume_init() };
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return false;
    };
    let mut needed = FD_HEADROOM + DIRECTORY_PINS;
    for entry in entries {
        if entry.is_err() {
            return false;
        }
        let Some(next) = needed.checked_add(1) else {
            return false;
        };
        needed = next;
        if needed > limits.rlim_cur {
            return false;
        }
    }
    needed <= limits.rlim_cur
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

impl OwnedCheckpoint {
    #[cfg(test)]
    pub(crate) fn verified_for_test(
        path: &Path,
        limits: crate::image::Limits,
    ) -> Result<Option<Self>, Error> {
        crate::image::load_layout(path, None, limits, || false).map_err(Error::Image)?;
        Self::finished(path)
    }

    pub(super) fn finished(path: &Path) -> Result<Option<Self>, Error> {
        if !pin_budget_available() {
            return Ok(None);
        }
        let pins = (|| -> io::Result<_> {
            Ok([
                open_directory(path)?,
                open_directory(&path.join("blobs"))?,
                open_directory(&path.join("blobs/sha256"))?,
            ])
        })();
        let directories = match pins {
            Ok(pins) => pins,
            Err(error) if matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let checkpoint = Self {
            path: path.to_owned(),
            directories,
        };
        checkpoint.validate()?;
        Ok(Some(checkpoint))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        for (suffix, pinned) in ["", "blobs", "blobs/sha256"]
            .into_iter()
            .zip(&self.directories)
        {
            let path = if suffix.is_empty() {
                self.path.clone()
            } else {
                self.path.join(suffix)
            };
            let observed = fs::symlink_metadata(path)?;
            let held = pinned.metadata()?;
            if !observed.is_dir()
                || !held.is_dir()
                || (observed.dev(), observed.ino()) != (held.dev(), held.ino())
            {
                return Err(Error::Invalid("owned checkpoint directory changed"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{fd::AsRawFd, unix::fs::symlink};

    fn layout() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("image/blobs/sha256")).unwrap();
        temp
    }

    #[test]
    fn pins_reject_replaced_directories_and_symlink_aliases() {
        for suffix in ["", "blobs", "blobs/sha256"] {
            for alias in [false, true] {
                let temp = layout();
                let path = temp.path().join("image");
                let checkpoint = OwnedCheckpoint::finished(&path).unwrap().unwrap();
                checkpoint.validate().unwrap();
                assert_eq!(checkpoint.path(), path);
                let selected = if suffix.is_empty() {
                    path.clone()
                } else {
                    path.join(suffix)
                };
                let moved = temp.path().join("moved");
                fs::rename(&selected, &moved).unwrap();
                if alias {
                    symlink(&moved, &selected).unwrap();
                } else {
                    fs::create_dir(&selected).unwrap();
                }
                assert!(matches!(checkpoint.validate(), Err(Error::Invalid(_))));
            }
        }
    }

    #[test]
    fn pins_are_read_only_cloexec_and_do_not_claim_payload_integrity() {
        let temp = layout();
        let path = temp.path().join("image");
        let payload = path.join("blobs/sha256/payload");
        fs::write(&payload, b"before").unwrap();
        let checkpoint = OwnedCheckpoint::finished(&path).unwrap().unwrap();
        for file in &checkpoint.directories {
            // SAFETY: fcntl only reads flags on a live borrowed descriptor.
            let (flags, fd_flags) = unsafe {
                (
                    libc::fcntl(file.as_raw_fd(), libc::F_GETFL),
                    libc::fcntl(file.as_raw_fd(), libc::F_GETFD),
                )
            };
            assert!(flags >= 0 && fd_flags >= 0);
            assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
            assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
        }
        fs::write(payload, b"after!").unwrap();
        // Publication must still independently hash payloads; pins prove lineage only.
        checkpoint.validate().unwrap();
    }

    #[test]
    fn unavailable_fd_budget_disables_optional_capability() {
        const CHILD: &str = "RPWELD_OWNED_CHECKPOINT_FD_TEST";
        if std::env::var_os(CHILD).is_some() {
            let temp = layout();
            let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            // SAFETY: live output pointer, initialized by a successful getrlimit.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr()) },
                0
            );
            // SAFETY: initialized above.
            let mut limits = unsafe { limits.assume_init() };
            limits.rlim_cur = limits.rlim_cur.min(200);
            // SAFETY: reducing the soft limit in this isolated subprocess only.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
            assert!(
                OwnedCheckpoint::finished(&temp.path().join("image"))
                    .unwrap()
                    .is_none()
            );
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "export::owned::tests::unavailable_fd_budget_disables_optional_capability",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
