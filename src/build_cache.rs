//! Private, content-keyed completed-stage cache. Never executes a cache entry.
//! Like COPY, fingerprinting requires a stable context. Reads may update source
//! atimes; key their post-read values, which subsequent COPY preflight observes.
//! Strict-atime mounts and external readers can therefore reduce cache reuse.
use crate::build::{Error, Limits};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Error>;

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

pub(crate) fn key(
    inputs: &[u8],
    context: Option<&Path>,
    limits: Limits,
    cancelled: &impl Fn() -> bool,
) -> Result<String> {
    let mut hash = Sha256::new();
    field(&mut hash, b"weld-stage-cache-v1");
    field(&mut hash, inputs);
    // Development builds share a version string: bind cache entries to executable bytes.
    let mut executable = fs::File::open(std::env::current_exe()?)?;
    if executable.metadata()?.len() > 64 * 1024 * 1024 {
        return Err("builder executable exceeds cache identity budget".into());
    }
    let mut buf = [0u8; 65536];
    loop {
        if cancelled() {
            return Err("cache hashing cancelled".into());
        }
        let n = executable.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    if let Some(root) = context {
        #[cfg(target_os = "linux")]
        fingerprint(root, &mut hash, limits, cancelled)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, limits);
            return Err("cache requires Linux".into());
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(target_os = "linux")]
fn fingerprint(
    root: &Path,
    hash: &mut Sha256,
    limits: Limits,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    use std::{
        ffi::CString,
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    };
    let mut pending = vec![PathBuf::new()];
    let (mut entries, mut bytes, mut metadata) = (0usize, 0u64, 0u64);
    while let Some(relative) = pending.pop() {
        if cancelled() {
            return Err("cache hashing cancelled".into());
        }
        let path = root.join(&relative);
        let m = fs::symlink_metadata(&path)?;
        entries += 1;
        metadata = metadata
            .checked_add(relative.as_os_str().len() as u64 + 128)
            .ok_or("cache metadata overflow")?;
        if entries > limits.max_rootfs_entries || metadata > limits.layer.max_metadata_bytes {
            return Err("cache context metadata budget exceeded".into());
        }
        field(hash, relative.as_os_str().as_bytes());
        field(
            hash,
            format!(
                "{}:{}:{}:{}:{}",
                m.mode(),
                m.uid(),
                m.gid(),
                m.mtime(),
                m.mtime_nsec()
            )
            .as_bytes(),
        );
        // Include all xattrs without following symlinks, including ACL/capability bytes.
        let cpath = CString::new(path.as_os_str().as_bytes())?;
        let size = unsafe { libc::llistxattr(cpath.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if size as u64 > limits.layer.max_metadata_bytes.saturating_sub(metadata) {
            return Err("cache xattr budget exceeded".into());
        }
        let mut names = vec![0u8; size as usize];
        let got =
            unsafe { libc::llistxattr(cpath.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
        if got != size {
            return Err("context xattrs changed while hashing".into());
        }
        let mut names: Vec<_> = names.split(|b| *b == 0).filter(|n| !n.is_empty()).collect();
        names.sort();
        for name in names {
            let cname = CString::new(name)?;
            let size =
                unsafe { libc::lgetxattr(cpath.as_ptr(), cname.as_ptr(), std::ptr::null_mut(), 0) };
            if size < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            metadata = metadata
                .checked_add(size as u64 + name.len() as u64)
                .ok_or("cache xattr budget overflow")?;
            if metadata > limits.layer.max_metadata_bytes {
                return Err("cache xattr budget exceeded".into());
            }
            let mut value = vec![0u8; size as usize];
            let got = unsafe {
                libc::lgetxattr(
                    cpath.as_ptr(),
                    cname.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            if got != size {
                return Err("context xattrs changed while hashing".into());
            }
            field(hash, name);
            field(hash, &value);
        }
        field(hash, b"end-xattrs");
        if m.is_dir() {
            let mut children = Vec::new();
            for child in fs::read_dir(&path)? {
                if entries + pending.len() + children.len() >= limits.max_rootfs_entries {
                    return Err("cache context entry budget exceeded".into());
                }
                children.push(relative.join(child?.file_name()));
            }
            children.sort();
            pending.extend(children.into_iter().rev());
        } else if m.is_file() {
            bytes = bytes
                .checked_add(m.len())
                .ok_or("cache context byte overflow")?;
            if bytes > limits.max_rootfs_bytes {
                return Err("cache context byte budget exceeded".into());
            }
            field(hash, &m.len().to_le_bytes());
            let mut f = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)?;
            if !f.metadata()?.is_file() {
                return Err("context file changed while hashing".into());
            }
            let mut read = 0u64;
            let mut buf = [0u8; 65536];
            loop {
                if cancelled() {
                    return Err("cache hashing cancelled".into());
                }
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                read += n as u64;
                if read > m.len() {
                    return Err("context file changed while hashing".into());
                }
                hash.update(&buf[..n]);
            }
            if read != m.len() {
                return Err("context file changed while hashing".into());
            }
        } else if m.file_type().is_symlink() {
            field(hash, fs::read_link(&path)?.as_os_str().as_bytes());
        } else {
            return Err("cache context contains unsupported special file".into());
        }
        // read/read_dir/read_link can all change atime. Hash the value COPY will
        // see, rather than the stale timestamp captured before fingerprinting.
        let after = fs::symlink_metadata(&path)?;
        field(hash, &after.atime().to_le_bytes());
        field(hash, &after.atime_nsec().to_le_bytes());
    }
    Ok(())
}

pub(crate) fn lookup(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => Ok(true),
        Ok(_) => Err("cache entry must be a real directory".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn publish(
    source: &Path,
    destination: &Path,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    if lookup(destination)? {
        return Ok(());
    }
    let temporary = tempfile::Builder::new()
        .prefix(".publish-")
        .tempdir_in(destination.parent().ok_or("cache parent missing")?)?;
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        if cancelled() {
            return Err("cache publication cancelled".into());
        }
        for e in fs::read_dir(source.join(&relative))? {
            let e = e?;
            let child = relative.join(e.file_name());
            let target = temporary.path().join(&child);
            let kind = e.file_type()?;
            if kind.is_dir() {
                fs::create_dir(&target)?;
                pending.push(child);
            } else if kind.is_file() {
                fs::copy(e.path(), target)?;
            } else {
                return Err("cache publication requires a regular OCI layout".into());
            }
        }
    }
    match fs::rename(temporary.path(), destination) {
        Ok(()) => {
            let _ = temporary.keep();
            Ok(())
        }
        Err(_) if lookup(destination)? => Ok(()), // A concurrent successful build won publication.
        Err(e) => Err(e.into()),
    }
}
